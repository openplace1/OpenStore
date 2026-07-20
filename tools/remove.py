#!/usr/bin/env python3
"""Interactively remove an app from the OpenStore repository.

This removes an app everywhere it is referenced so it stops appearing
in the store catalog:

  - store/catalog.json           (entry removed)
  - store/build.json              ("packages" entry + "appsCache" entry removed)
  - store/packages/<id>.opk       (built package file deleted, if present)
  - apps/<name>.osa                (user app source, if present)
  - apps/<name>.manifest.json      (user app manifest, if present)
  - store/system_apps/<name>.osa   (system app source, if present)
  - store/manifests/<id>.json      (system app manifest, if present)

System apps (scope == "system") require an extra confirmation, since
removing one can break the base OS.

After removing files, this script rewrites store/catalog.json to stay in
sync with store/build.json (equivalent to running tools/build_opk.py's
catalog step, but without rebuilding .opk archives). Run
tools/build_opk.py afterwards if you also want fresh .opk packages.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "store"
APPS_DIR = ROOT / "apps"
PACKAGES_DIR = STORE / "packages"
CATALOG_PATH = STORE / "catalog.json"
BUILD_JSON_PATH = STORE / "build.json"


def load_json(path: Path) -> Any:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SystemExit(f"Could not read {path.relative_to(ROOT)}: {exc}")


def write_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    temporary.replace(path)


def write_compact_json(path: Path, value: Any) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(
        (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    )
    temporary.replace(path)


def confirm(prompt: str) -> bool:
    answer = input(f"{prompt} [y/N]: ").strip().lower()
    return answer in ("y", "yes")


def resolve(value: str) -> Path:
    """Resolve a build.json-style path (may use \\ or /) to an absolute Path."""
    return (ROOT / value.replace("\\", "/")).resolve()


def delete_if_exists(path: Path) -> None:
    if path.exists():
        path.unlink()
        print(f"  removed {path.relative_to(ROOT)}")


def main() -> None:
    catalog = load_json(CATALOG_PATH)
    build_config = load_json(BUILD_JSON_PATH)

    if not catalog or not isinstance(catalog.get("apps"), list) or not catalog["apps"]:
        print("No apps found in store/catalog.json.")
        return

    apps = catalog["apps"]
    apps_sorted = sorted(apps, key=lambda a: (a.get("scope", ""), a.get("name", "")))

    print("Installed apps:\n")
    for i, app in enumerate(apps_sorted, start=1):
        scope_tag = "system" if app.get("scope") == "system" else "user"
        print(f"  {i}. {app.get('name', '?')}  ({app.get('id', '?')})  [{scope_tag}]")

    print()
    raw = input("Enter the number of the app to remove (or 'q' to quit): ").strip()
    if raw.lower() in ("q", "quit", ""):
        print("Cancelled.")
        return

    try:
        index = int(raw)
        if not (1 <= index <= len(apps_sorted)):
            raise ValueError
    except ValueError:
        raise SystemExit("Invalid selection.")

    app = apps_sorted[index - 1]
    app_id = app.get("id")
    scope = app.get("scope")
    name = app.get("name", app_id)

    print(f"\nSelected: {name} ({app_id}), scope={scope}")

    if scope == "system":
        print("\nWARNING: this is a system app. Removing it can break OpenOS")
        print("(home, lockscreen, settings, etc. may stop working).")
        if not confirm("Are you sure you want to remove this system app?"):
            print("Cancelled.")
            return
    else:
        if not confirm(f"Remove '{name}' from the store?"):
            print("Cancelled.")
            return

    # --- 1. Remove from build.json packages + appsCache ---
    removed_manifest_rel: str | None = None
    if isinstance(build_config, dict) and isinstance(build_config.get("packages"), list):
        new_packages = []
        for pkg in build_config["packages"]:
            manifest_rel = pkg.get("manifest") if isinstance(pkg, dict) else None
            manifest_path = resolve(manifest_rel) if manifest_rel else None
            manifest_value = load_json(manifest_path) if manifest_path else None
            pkg_id = manifest_value.get("id") if isinstance(manifest_value, dict) else None
            if pkg_id == app_id:
                removed_manifest_rel = manifest_rel
                continue
            new_packages.append(pkg)
        build_config["packages"] = new_packages

        cache = build_config.get("appsCache")
        if isinstance(cache, dict):
            for source_rel in list(cache.keys()):
                entry = cache[source_rel]
                if isinstance(entry, dict) and entry.get("metadata", {}).get("id") == app_id:
                    del cache[source_rel]

        write_json(BUILD_JSON_PATH, build_config)
        print(f"  updated {BUILD_JSON_PATH.relative_to(ROOT)}")

    # --- 2. Delete manifest + source files (user app in apps/, or system app) ---
    if removed_manifest_rel:
        manifest_path = resolve(removed_manifest_rel)
        manifest_value = load_json(manifest_path)
        delete_if_exists(manifest_path)
        if isinstance(manifest_value, dict):
            entry = manifest_value.get("entry")
            if entry:
                delete_if_exists(manifest_path.parent / entry)

    # Fallback cleanup by conventional filename, in case the app predates
    # build.json bookkeeping or files.py couldn't find it above.
    stem_guess = app_id.split(".")[-1] if app_id else None
    if stem_guess:
        delete_if_exists(APPS_DIR / f"{stem_guess}.osa")
        delete_if_exists(APPS_DIR / f"{stem_guess}.manifest.json")
        delete_if_exists(STORE / "system_apps" / f"{stem_guess}.osa")
    if app_id:
        delete_if_exists(STORE / "manifests" / f"{app_id}.json")

    # --- 3. Delete built .opk package ---
    if app_id:
        delete_if_exists(PACKAGES_DIR / f"{app_id}.opk")

    # --- 4. Rewrite catalog.json without the removed app ---
    catalog["apps"] = [a for a in apps if a.get("id") != app_id]
    write_compact_json(CATALOG_PATH, catalog)
    print(f"  updated {CATALOG_PATH.relative_to(ROOT)}")

    print(f"\nDone. '{name}' no longer appears in the store.")
    print("Tip: run tools/build_opk.py if you want catalog.json regenerated")
    print("     from scratch (e.g. to also re-sort/re-validate everything).")


if __name__ == "__main__":
    main()
