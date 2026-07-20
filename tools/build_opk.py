#!/usr/bin/env python3
"""Build deterministic, device-compatible OpenOS OPK packages and catalog."""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn
from urllib.parse import urlsplit
from zipfile import ZIP_STORED, ZipFile, ZipInfo


ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "store"
OUTPUT = STORE / "packages"
APPS_DIR = ROOT / "apps"
DEFAULT_PACKAGE_BASE = "https://raw.githubusercontent.com/openplace1/OpenOS/main/store/packages"

MAX_PACKAGE_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_MANIFEST_BYTES = 8192
MAX_ENTRIES = 64
MAX_CATALOG_BYTES = 24 * 1024
MAX_OSA_SOURCE_BYTES = 128 * 1024
MAX_OSA_LINES = 512
MAX_OSA_LINE_BYTES = 768
MAX_OSAC_BYTES = 96 * 1024

ID_PATTERN = re.compile(r"[a-z0-9._-]{1,48}\Z")
COLOR_PATTERN = re.compile(r"#[0-9A-Fa-f]{6}\Z")
SYSTEM_IDS = {
    "openos.home",
    "openos.lockscreen",
    "openos.controlcenter",
    "openos.settings",
    "openos.files",
    "openos.clock",
    "openos.calculator",
    "openos.notes",
    "openos.compiler",
    "openos.openstore",
}


def fail(message: str) -> NoReturn:
    raise SystemExit(f"OPK build error: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def compact_json(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def package_base_url(value: Any) -> str:
    require(isinstance(value, str) and 8 < len(value) <= 2048,
            "packageBaseUrl must be an HTTPS URL")
    require(not any(char.isspace() for char in value),
            "packageBaseUrl cannot contain whitespace")
    parsed = urlsplit(value)
    require(parsed.scheme == "https" and bool(parsed.netloc) and
            not parsed.query and not parsed.fragment,
            "packageBaseUrl must be an HTTPS directory URL without query or fragment")
    return value.rstrip("/")


def safe_archive_path(value: Any, *, directory: bool = False) -> str:
    require(isinstance(value, str) and 0 < len(value) <= 160, "invalid archive path")
    require("\\" not in value and ":" not in value and "\0" not in value,
            f"unsafe archive path: {value!r}")
    require(not value.startswith("/"), f"absolute archive path: {value!r}")
    path = PurePosixPath(value)
    require(all(part not in ("", ".", "..") for part in value.split("/")) and
            all(part not in ("", ".", "..") for part in path.parts),
            f"unsafe archive path: {value!r}")
    require(directory or not value.endswith("/"), f"file path ends in '/': {value!r}")
    return value


def source_path(value: Any) -> Path:
    require(isinstance(value, str) and value, "source path must be a string")
    path = (ROOT / value).resolve()
    try:
        path.relative_to(ROOT)
    except ValueError:
        fail(f"source lies outside repository: {value!r}")
    require(path.is_file(), f"source file does not exist: {value!r}")
    return path


def validate_manifest(value: Any, source_name: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{source_name}: manifest must be an object")
    required = {"schema", "id", "name", "version", "versionCode", "entry", "scope", "isApp"}
    missing = sorted(required - value.keys())
    require(not missing, f"{source_name}: missing fields: {', '.join(missing)}")
    require(value["schema"] == 1 and not isinstance(value["schema"], bool),
            f"{source_name}: schema must be 1")
    package_id = value["id"]
    require(isinstance(package_id, str) and ID_PATTERN.fullmatch(package_id) is not None,
            f"{source_name}: invalid package id")
    require(isinstance(value["name"], str) and 0 < len(value["name"]) <= 48,
            f"{source_name}: name must contain 1-48 characters")
    require(isinstance(value["version"], str) and 0 < len(value["version"]) <= 24,
            f"{source_name}: version must contain 1-24 characters")
    require(isinstance(value["versionCode"], int) and
            not isinstance(value["versionCode"], bool) and value["versionCode"] >= 1,
            f"{source_name}: versionCode must be a positive integer")
    entry = safe_archive_path(value["entry"])
    require(entry.lower().endswith((".osa", ".osac")),
            f"{source_name}: entry must be .osa or .osac")
    require(value["scope"] in ("user", "system"),
            f"{source_name}: scope must be user or system")
    require(isinstance(value["isApp"], bool), f"{source_name}: isApp must be boolean")
    if value["scope"] == "system":
        require(package_id in SYSTEM_IDS, f"{source_name}: unapproved system package id")
    else:
        require(not package_id.startswith("openos."),
                f"{source_name}: openos.* is reserved for system packages")
    return value


def zip_info(name: str) -> ZipInfo:
    info = ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    # Classic ESP32 boards without PSRAM cannot reliably reserve the roughly
    # 44 KB of contiguous heap required by a DEFLATE decoder. Stored entries
    # are copied to the SD card in small chunks by the OpenOS installer.
    info.compress_type = ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Interactive .osa discovery
# ---------------------------------------------------------------------------

def prompt_str(label: str, *, max_len: int, allow_empty: bool = False) -> str:
    while True:
        raw = input(f"  {label}: ").strip()
        if not raw and not allow_empty:
            print(f"    -> {label} cannot be empty, try again")
            continue
        if len(raw.encode("utf-8")) > max_len:
            print(f"    -> {label} exceeds {max_len} bytes, try again")
            continue
        if "\n" in raw or "\r" in raw:
            print(f"    -> {label} must be a single line")
            continue
        return raw


def prompt_id(existing_ids: set[str]) -> str:
    while True:
        raw = input("  id (e.g. jan.paint): ").strip()
        if ID_PATTERN.fullmatch(raw) is None:
            print("    -> id must match [a-z0-9._-]{1,48}")
            continue
        if raw in existing_ids:
            print(f"    -> id {raw!r} is already in use, choose another")
            continue
        return raw


def prompt_version() -> str:
    return prompt_str("version (e.g. 1.0)", max_len=24)


def prompt_version_code() -> int:
    while True:
        raw = input("  versionCode (positive integer): ").strip()
        try:
            value = int(raw)
        except ValueError:
            print("    -> this must be an integer")
            continue
        if value < 1:
            print("    -> versionCode must be >= 1")
            continue
        return value


def prompt_color() -> str:
    while True:
        raw = input("  appColor (#RRGGBB): ").strip()
        if COLOR_PATTERN.fullmatch(raw) is None:
            print("    -> color must be in #RRGGBB format")
            continue
        return raw.upper()


def prompt_scope() -> str:
    while True:
        raw = input("  scope (user/system) [user]: ").strip().lower() or "user"
        if raw not in ("user", "system"):
            print("    -> scope must be 'user' or 'system'")
            continue
        return raw


def prompt_is_app() -> bool:
    while True:
        raw = input("  isApp (y/n) [y]: ").strip().lower() or "y"
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        print("    -> answer y/n")


def collect_metadata_for(osa_path: Path, existing_ids: set[str]) -> dict[str, Any]:
    print(f"\nNew/changed file: {osa_path.relative_to(ROOT)}")
    package_id = prompt_id(existing_ids)
    name = prompt_str("name (1-48 characters)", max_len=48)
    summary = prompt_str("summary (1-50 characters)", max_len=50)
    description = prompt_str("description (1-10000 bytes)", max_len=10000)
    developer = prompt_str("developer (1-64 characters)", max_len=64)
    version = prompt_version()
    version_code = prompt_version_code()
    app_color = prompt_color()
    scope = prompt_scope()
    is_app = prompt_is_app()
    return {
        "id": package_id,
        "name": name,
        "summary": summary,
        "description": description,
        "developer": developer,
        "version": version,
        "versionCode": version_code,
        "appColor": app_color,
        "scope": scope,
        "isApp": is_app,
    }


def discover_apps(config: dict[str, Any]) -> None:
    """Scan APPS_DIR for *.osa files, prompting for metadata on new/changed
    files, and merge auto-generated manifest/files entries into
    config["packages"]. Existing entries not tied to an APPS_DIR .osa file
    (e.g. hand-authored packages, or entries for .osa files temporarily
    missing from disk) are left untouched rather than being wiped out.
    Mutates config in place.
    """
    require(APPS_DIR.is_dir(), f"apps directory not found: {APPS_DIR}")

    cache: dict[str, Any] = config.setdefault("appsCache", {})
    osa_files = sorted(APPS_DIR.glob("*.osa"))
    require(bool(osa_files), f"no .osa files found in {APPS_DIR}")

    existing_ids = {
        entry["id"]
        for entry in cache.values()
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }

    existing_packages: list[Any] = config.get("packages")
    if not isinstance(existing_packages, list):
        existing_packages = []
    # Index existing entries by manifest path, since that's the stable
    # identifier we generate per .osa file (apps/<stem>.manifest.json).
    by_manifest: dict[str, dict[str, Any]] = {}
    for entry in existing_packages:
        if isinstance(entry, dict) and isinstance(entry.get("manifest"), str):
            by_manifest[entry["manifest"]] = entry

    discovered_manifests: set[str] = set()
    for osa_path in osa_files:
        rel = str(osa_path.relative_to(ROOT))
        digest = sha256_file(osa_path)
        cached = cache.get(rel)

        if isinstance(cached, dict) and cached.get("sha256") == digest:
            metadata = cached["metadata"]
            package_id = metadata["id"]
        else:
            # Free up this file's own previous id (if any) before checking
            # for collisions, so re-running on the same file doesn't block
            # on itself when nothing else changed but content did.
            previous_id = cached["metadata"]["id"] if isinstance(cached, dict) else None
            candidate_ids = existing_ids - ({previous_id} if previous_id else set())
            metadata = collect_metadata_for(osa_path, candidate_ids)
            package_id = metadata["id"]
            existing_ids.add(package_id)
            cache[rel] = {"sha256": digest, "metadata": metadata}

        manifest = {
            "schema": 1,
            "id": metadata["id"],
            "name": metadata["name"],
            "version": metadata["version"],
            "versionCode": metadata["versionCode"],
            "entry": osa_path.name,
            "scope": metadata["scope"],
            "isApp": metadata["isApp"],
        }
        manifest_path = APPS_DIR / f"{osa_path.stem}.manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

        manifest_rel = str(manifest_path.relative_to(ROOT))
        discovered_manifests.add(manifest_rel)
        by_manifest[manifest_rel] = {
            "manifest": manifest_rel,
            "files": {osa_path.name: str(osa_path.relative_to(ROOT))},
            "developer": metadata["developer"],
            "summary": metadata["summary"],
            "description": metadata["description"],
            "appColor": metadata["appColor"],
        }

    # Preserve original ordering: keep pre-existing entries where they were
    # (updated in place if rediscovered), and append newly discovered ones
    # at the end. Nothing unrelated to apps/*.osa is ever dropped here.
    merged: list[dict[str, Any]] = []
    seen_manifests: set[str] = set()
    for entry in existing_packages:
        if isinstance(entry, dict) and isinstance(entry.get("manifest"), str) \
                and entry["manifest"] in by_manifest:
            merged.append(by_manifest[entry["manifest"]])
            seen_manifests.add(entry["manifest"])
        else:
            merged.append(entry)
    for manifest_rel in discovered_manifests:
        if manifest_rel not in seen_manifests:
            merged.append(by_manifest[manifest_rel])

    config["packages"] = merged


def build_package(package: Any, seen_ids: set[str], base_url: str) -> dict[str, object]:
    require(isinstance(package, dict), "each build.json package must be an object")
    manifest_file = source_path(package.get("manifest"))
    try:
        manifest_value = json.loads(manifest_file.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"could not read {manifest_file.relative_to(ROOT)}: {exc}")
    manifest = validate_manifest(manifest_value, str(manifest_file.relative_to(ROOT)))
    package_id = manifest["id"]
    require(package_id not in seen_ids, f"duplicate package id: {package_id}")
    seen_ids.add(package_id)

    file_map = package.get("files")
    require(isinstance(file_map, dict) and file_map, f"{package_id}: files must be a non-empty object")
    require(len(file_map) + 1 <= MAX_ENTRIES, f"{package_id}: more than {MAX_ENTRIES} ZIP entries")

    files: list[tuple[str, Path, int]] = []
    seen_paths = {"manifest.json"}
    total = 0
    for archive_name_value, source_name in file_map.items():
        archive_name = safe_archive_path(archive_name_value)
        folded = archive_name.casefold()
        require(folded not in {name.casefold() for name in seen_paths},
                f"{package_id}: duplicate/case-colliding path {archive_name!r}")
        seen_paths.add(archive_name)
        source = source_path(source_name)
        size = source.stat().st_size
        require(size <= MAX_FILE_BYTES, f"{package_id}: {archive_name} exceeds 2 MB")
        require(total <= MAX_TOTAL_BYTES - size, f"{package_id}: unpacked files exceed 8 MB")
        total += size
        files.append((archive_name, source, size))

    require(manifest["entry"] in file_map,
            f"{package_id}: manifest entry {manifest['entry']!r} is not present in files")
    entry_source = source_path(file_map[manifest["entry"]])
    entry_bytes = entry_source.read_bytes()
    if manifest["entry"].lower().endswith(".osa"):
        require(len(entry_bytes) <= MAX_OSA_SOURCE_BYTES,
                f"{package_id}: OSA entry source exceeds 128 KB")
        source_lines = entry_bytes.replace(b"\r\n", b"\n").replace(b"\r", b"").split(b"\n")
        if source_lines and source_lines[-1] == b"":
            source_lines.pop()
        require(len(source_lines) <= MAX_OSA_LINES,
                f"{package_id}: OSA entry exceeds 512 lines")
        require(all(len(line) <= MAX_OSA_LINE_BYTES for line in source_lines),
                f"{package_id}: OSA entry has a line longer than 768 bytes")
    else:
        require(len(entry_bytes) <= MAX_OSAC_BYTES,
                f"{package_id}: OSAC entry exceeds 96 KB")
    manifest_bytes = compact_json(manifest)
    require(len(manifest_bytes) <= MAX_MANIFEST_BYTES, f"{package_id}: manifest exceeds 8 KB")
    require(total <= MAX_TOTAL_BYTES - len(manifest_bytes), f"{package_id}: package exceeds 8 MB unpacked")

    OUTPUT.mkdir(parents=True, exist_ok=True)
    output_path = OUTPUT / f"{package_id}.opk"
    temporary = output_path.with_suffix(".opk.tmp")
    try:
        with ZipFile(temporary, "w", compression=ZIP_STORED,
                     allowZip64=False) as archive:
            archive.writestr(zip_info("manifest.json"), manifest_bytes)
            for archive_name, source, _ in sorted(files, key=lambda item: item[0]):
                archive.writestr(zip_info(archive_name), source.read_bytes())
        require(temporary.stat().st_size <= MAX_PACKAGE_BYTES,
                f"{package_id}: OPK exceeds 8 MB")
        os.replace(temporary, output_path)
    finally:
        temporary.unlink(missing_ok=True)

    digest = sha256_file(output_path)
    print(f"Built {output_path.relative_to(ROOT)}  sha256={digest}")
    developer = package.get("developer")
    summary = package.get("summary")
    description = package.get("description")
    app_color = package.get("appColor")
    require(isinstance(developer, str) and 0 < len(developer) <= 64 and
            "\n" not in developer and "\r" not in developer,
            f"{package_id}: developer must contain 1-64 characters on one line")
    require(isinstance(summary, str) and 0 < len(summary) <= 50 and
            "\n" not in summary and "\r" not in summary,
            f"{package_id}: summary must contain 1-50 characters on one line")
    require(isinstance(description, str) and 0 < len(description) <= 10000 and
            len(description.encode("utf-8")) <= 10000 and
            not any(ord(char) < 0x20 and char not in "\n\r\t" for char in description),
            f"{package_id}: description must contain 1-10000 UTF-8 bytes")
    require(isinstance(app_color, str) and COLOR_PATTERN.fullmatch(app_color) is not None,
            f"{package_id}: appColor must be #RRGGBB")
    return {
        "id": package_id,
        "name": manifest["name"],
        "version": manifest["version"],
        "versionCode": manifest["versionCode"],
        "scope": manifest["scope"],
        "developer": developer,
        "summary": summary,
        "description": description,
        "appColor": app_color.upper(),
        "url": f"{base_url}/{output_path.name}",
        "sha256": digest,
    }


def main() -> None:
    build_json_path = STORE / "build.json"
    try:
        config = json.loads(build_json_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        config = {}
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"could not read store/build.json: {exc}")
    require(isinstance(config, dict), "build.json must contain an object")

    discover_apps(config)

    # Persist the cache (and freshly generated packages list) immediately so
    # that manifest generation and metadata prompts are never repeated after
    # a later validation failure.
    build_json_path.write_text(
        json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )

    require(isinstance(config.get("packages"), list), "build.json must contain a packages array")
    base_url = package_base_url(config.get("packageBaseUrl", DEFAULT_PACKAGE_BASE))

    seen_ids: set[str] = set()
    catalog_apps = [build_package(package, seen_ids, base_url)
                    for package in config["packages"]]
    catalog_apps.sort(key=lambda item: str(item["id"]))
    catalog_bytes = compact_json({"schema": 1, "apps": catalog_apps})
    require(len(catalog_bytes) <= MAX_CATALOG_BYTES, "catalog exceeds device 24 KB limit")

    catalog_path = STORE / "catalog.json"
    temporary = catalog_path.with_suffix(".json.tmp")
    try:
        temporary.write_bytes(catalog_bytes)
        os.replace(temporary, catalog_path)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"Wrote {catalog_path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
