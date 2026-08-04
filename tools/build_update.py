#!/usr/bin/env python3
"""Build and sign the flat OpenOS OTA manifest.

Human release fields live in update/info.json. This tool fills the firmware
size and SHA-256, signs a canonical length-prefixed payload with ECDSA P-256,
and writes deterministic UTF-8/LF JSON. The private key must stay outside Git.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
from typing import Any, NoReturn

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
except ImportError as exc:  # pragma: no cover - exercised by CLI environments
    raise SystemExit(
        "build_update.py requires 'cryptography' (python -m pip install cryptography)"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INFO = ROOT / "update" / "info.json"
DEFAULT_PUBLIC_KEY = ROOT / "update" / "openos-release-2026-01-public.pem"
KEY_ID = "openos-release-2026-01"
TARGET = "denky32-wroom32"
PARTITION_SCHEME = "openos-dual-v1"
MAX_SLOT_BYTES = 0x1F0000
MAX_MANIFEST_BYTES = 4096
ESP_IMAGE_MAGIC = 0xE9
ESP32_CHIP_ID = 0
ESP_APP_DESC_MAGIC = 0xABCD5432

SIGNED_FIELDS = (
    "schema",
    "product",
    "channel",
    "target",
    "partitionScheme",
    "name",
    "version",
    "versionCode",
    "minUpdaterVersionCode",
    "releaseType",
    "description",
    "publishedAt",
    "firmware",
    "size",
    "sha256",
    "keyId",
)
ALL_FIELDS = SIGNED_FIELDS + ("signature",)


def fail(message: str) -> NoReturn:
    raise SystemExit(f"OTA build error: {message}")


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def canonical_payload(info: dict[str, Any]) -> bytes:
    output = bytearray(b"OPENOS-OTA-V1\n")
    for field in SIGNED_FIELDS:
        require(field in info, f"missing signed field {field!r}")
        value = info[field]
        require(type(value) in (str, int), f"{field} must be a string or integer")
        encoded = str(value).encode("utf-8")
        output.extend(field.encode("ascii"))
        output.extend(b":")
        output.extend(str(len(encoded)).encode("ascii"))
        output.extend(b":")
        output.extend(encoded)
        output.extend(b"\n")
    return bytes(output)


def safe_firmware_path(info_path: Path, value: Any) -> Path:
    require(isinstance(value, str) and 0 < len(value.encode("utf-8")) <= 160,
            "firmware must be a relative file path")
    require(not any(ord(char) <= 0x20 for char in value) and
            not any(char in value for char in "\\:?#"),
            "firmware path contains characters rejected by OpenOS")
    pure = PurePosixPath(value)
    require(not pure.is_absolute() and value == pure.as_posix(),
            "firmware must use a relative POSIX path")
    require(all(part not in ("", ".", "..") for part in pure.parts),
            "firmware path contains an unsafe component")
    root = info_path.parent.resolve()
    result = (root / Path(*pure.parts)).resolve()
    try:
        result.relative_to(root)
    except ValueError:
        fail("firmware lies outside update directory")
    return result


def expected_image_marker(info: dict[str, Any]) -> bytes:
    return (
        "OPENOS-OTA-IMAGE-V1|"
        f"target={info['target']}|"
        f"partition={info['partitionScheme']}|"
        f"version={info['version']}|"
        f"versionCode={info['versionCode']}|"
    ).encode("utf-8")


def validate_firmware_image(firmware: bytes, info: dict[str, Any]) -> None:
    require(len(firmware) >= 4096, "firmware is too small to be an ESP32 app image")
    require(firmware[0] == ESP_IMAGE_MAGIC, "firmware has an invalid ESP image magic")
    require(1 <= firmware[1] <= 16, "firmware has an invalid ESP segment count")
    require(int.from_bytes(firmware[12:14], "little") == ESP32_CHIP_ID,
            "firmware targets a chip other than ESP32")
    require(int.from_bytes(firmware[32:36], "little") == ESP_APP_DESC_MAGIC,
            "firmware is missing the ESP application descriptor")
    marker = expected_image_marker(info)
    require(firmware.count(marker) == 1,
            "firmware does not contain the expected OpenOS target/version marker")


def validate_metadata(info: dict[str, Any]) -> None:
    require(set(info) == set(ALL_FIELDS),
            "info.json must contain exactly the documented OTA fields")
    require(info["schema"] == 1 and info["product"] == "openos",
            "unsupported schema or product")
    require(info["target"] == TARGET, "target does not match release hardware")
    require(info["partitionScheme"] == PARTITION_SCHEME,
            "partitionScheme does not match the OTA layout")
    require(info["keyId"] == KEY_ID, "keyId does not match this release key")
    require(isinstance(info["channel"], str) and
            info["channel"] in {"stable", "beta", "dev"}, "invalid channel")
    require(isinstance(info["releaseType"], str) and
            info["releaseType"] in {"major", "minor", "patch", "security"},
            "invalid releaseType")
    for field, maximum in (("name", 80), ("version", 24),
                           ("publishedAt", 40), ("description", 1200)):
        value = info[field]
        require(isinstance(value, str) and len(value.encode("utf-8")) <= maximum,
                f"{field} is invalid or too long")
    require(bool(info["name"] and info["version"] and info["publishedAt"]),
            "name, version and publishedAt cannot be empty")
    for field in ("name", "version", "publishedAt"):
        require(not any(ord(char) < 0x20 for char in info[field]),
                f"{field} contains a control character rejected by OpenOS")
    require(not any(ord(char) < 0x20 and char not in "\n\t"
                    for char in info["description"]),
            "description contains a control character rejected by OpenOS")
    require(type(info["versionCode"]) is int and info["versionCode"] >= 1,
            "versionCode must be a positive integer")
    require(type(info["minUpdaterVersionCode"]) is int and
            info["minUpdaterVersionCode"] >= 1,
            "minUpdaterVersionCode must be a positive integer")
    require(type(info["size"]) is int and 4096 <= info["size"] <= MAX_SLOT_BYTES,
            "firmware size does not fit the OTA slot")
    require(isinstance(info["sha256"], str) and len(info["sha256"]) == 64 and
            all(char in "0123456789abcdef" for char in info["sha256"]),
            "sha256 must be 64 lowercase hexadecimal characters")
    require(isinstance(info["signature"], str), "signature must be a string")


def ordered_manifest(info: dict[str, Any]) -> dict[str, Any]:
    return {field: info[field] for field in ALL_FIELDS}


def write_json_lf(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def reject_runtime_unsupported_escapes(document: str) -> None:
    in_string = False
    escaped = False
    for char in document:
        if not in_string:
            if char == '"':
                in_string = True
            continue
        if escaped:
            require(char != "u", "OpenOS does not accept JSON \\u escapes")
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            in_string = False


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    try:
        document = path.read_text(encoding="utf-8")
        require(len(document.encode("utf-8")) <= MAX_MANIFEST_BYTES,
                "info.json exceeds the OpenOS 4 KB limit")
        reject_runtime_unsupported_escapes(document)
        value = json.loads(document, object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"could not read {path}: {exc}")
    require(isinstance(value, dict), "info.json must contain an object")
    return value


def load_private_key(path: Path) -> ec.EllipticCurvePrivateKey:
    try:
        path.resolve().relative_to(ROOT)
    except ValueError:
        pass
    else:
        fail("private release keys must be stored outside the repository")
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        fail(f"could not load private key {path}: {exc}")
    require(isinstance(key, ec.EllipticCurvePrivateKey) and
            isinstance(key.curve, ec.SECP256R1), "release key must be ECDSA P-256")
    return key


def load_public_key(path: Path) -> ec.EllipticCurvePublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError, TypeError) as exc:
        fail(f"could not load public key {path}: {exc}")
    require(isinstance(key, ec.EllipticCurvePublicKey) and
            isinstance(key.curve, ec.SECP256R1), "release key must be ECDSA P-256")
    return key


def generate_keypair(private_path: Path, public_path: Path, force: bool = False) -> None:
    try:
        private_path.resolve().relative_to(ROOT)
    except ValueError:
        pass
    else:
        fail("private release keys must be generated outside the repository")
    if not force:
        require(not private_path.exists(), f"refusing to overwrite {private_path}")
        require(not public_path.exists(), f"refusing to overwrite {public_path}")
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    private_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    if os.name != "nt":
        private_path.chmod(0o600)
    public_path.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    print(f"Generated private key: {private_path}")
    print(f"Generated public key:  {public_path}")


def sign_release(info_path: Path, private_key_path: Path) -> dict[str, Any]:
    info = load_json(info_path)
    firmware_path = safe_firmware_path(info_path, info.get("firmware"))
    try:
        firmware = firmware_path.read_bytes()
    except OSError as exc:
        fail(f"could not read firmware {firmware_path}: {exc}")
    info["size"] = len(firmware)
    info["sha256"] = hashlib.sha256(firmware).hexdigest()
    info["signature"] = ""
    validate_metadata(info)
    validate_firmware_image(firmware, info)
    key = load_private_key(private_key_path)
    signature = key.sign(canonical_payload(info), ec.ECDSA(hashes.SHA256()))
    info["signature"] = base64.b64encode(signature).decode("ascii")
    validate_metadata(info)
    result = ordered_manifest(info)
    write_json_lf(info_path, result)
    print(f"Signed {info_path}")
    print(f"  firmware: {firmware_path.name} ({len(firmware)} bytes)")
    print(f"  sha256:   {info['sha256']}")
    return result


def verify_release(info_path: Path, public_key_path: Path) -> dict[str, Any]:
    info = load_json(info_path)
    validate_metadata(info)
    firmware_path = safe_firmware_path(info_path, info["firmware"])
    try:
        firmware = firmware_path.read_bytes()
    except OSError as exc:
        fail(f"could not read firmware {firmware_path}: {exc}")
    require(len(firmware) == info["size"], "firmware size differs from info.json")
    require(hashlib.sha256(firmware).hexdigest() == info["sha256"],
            "firmware SHA-256 differs from info.json")
    validate_firmware_image(firmware, info)
    try:
        signature = base64.b64decode(info["signature"], validate=True)
    except ValueError as exc:
        fail(f"invalid base64 signature: {exc}")
    key = load_public_key(public_key_path)
    try:
        key.verify(signature, canonical_payload(info), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        fail("manifest signature verification failed")
    print(f"Verified {info_path} and {firmware_path.name}")
    return info


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--info", type=Path, default=DEFAULT_INFO)
    parser.add_argument("--key", type=Path, help="private ECDSA P-256 release key")
    parser.add_argument("--verify", action="store_true", help="verify instead of signing")
    parser.add_argument("--public-key", type=Path, default=DEFAULT_PUBLIC_KEY)
    parser.add_argument("--generate-key", type=Path,
                        help="generate a new private key at this path")
    parser.add_argument("--force", action="store_true", help="allow key overwrite")
    args = parser.parse_args()

    info_path = args.info.resolve()
    if args.generate_key:
        generate_keypair(args.generate_key.resolve(), args.public_key.resolve(), args.force)
        return
    if args.verify:
        verify_release(info_path, args.public_key.resolve())
        return
    if not args.key:
        parser.error("--key is required when signing")
    sign_release(info_path, args.key.resolve())


if __name__ == "__main__":
    main()
