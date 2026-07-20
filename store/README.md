# OpenStore package repository

OpenStore reads [`catalog.json`](catalog.json) from any configured HTTPS host.
The catalog and OPK files may live in a separate repository, web server or CDN;
they do not need to be published with the firmware source. Each catalog entry
includes an OPK URL, its SHA-256 digest and a monotonically increasing
`versionCode`.

| Catalog field | Meaning |
|---|---|
| `schema` | Catalog schema, currently `1` |
| `apps` | Array of published package entries (maximum 64 on device) |
| `id`, `name`, `scope` | Must agree with the OPK manifest |
| `version`, `versionCode` | Display version and update ordering |
| `developer` | Publisher name, maximum 64 characters |
| `summary` | Store-card description, maximum 50 characters |
| `description` | Detail-page text, maximum 10,000 UTF-8 bytes |
| `appColor` | Icon colour in `#RRGGBB` form |
| `url` | HTTPS URL of the OPK |
| `sha256` | Lowercase SHA-256 of the complete OPK file |

## OPK format

An `.opk` is a standard ZIP archive with a different extension. ZIP methods
`stored` (0) and `deflate` (8) are supported. The archive must contain exactly
one `manifest.json` at its root.

The supplied builder always uses `stored` entries. This lets ESP32 boards
without PSRAM install packages by streaming them directly to the SD card,
without allocating the roughly 44 KB working buffer required by DEFLATE.

| Manifest field | Type | Meaning |
|---|---:|---|
| `schema` | integer | Package schema, currently `1` |
| `id` | string | Stable lowercase package ID |
| `name` | string | Display name |
| `version` | string | Human-readable version |
| `versionCode` | integer | Increasing update number |
| `entry` | string | Relative path to `.osa` or `.osac` entry point |
| `scope` | string | `user` or `system` |
| `isApp` | boolean | Whether the package is intended as a Home app |

Application code, images and other assets may use any safe relative paths in
the ZIP. OSA code accesses its package files through `asset.*`.

## Build and publish

Set `packageBaseUrl` in [`build.json`](build.json) to the public directory that
will contain generated OPK files. Every package entry also supplies
`developer`, `summary`, `description` and `appColor`. Add the manifest and
source files, then run:

```text
python tools/build_opk.py
```

The tool creates deterministic packages, calculates SHA-256 and rewrites the
catalog. Upload `catalog.json` and the generated `.opk` files to the selected
host. On the device, set these keys in `/user/config.ini`:

```ini
store_catalog_url=https://example.com/openstore/catalog.json
store_system_prefix=https://example.com/openstore/packages/
```

`store_system_prefix` is optional unless system-scope packages use the new
host. Both values can also be changed by privileged OSA code through
`store.setSource()` and `store.setSystemSource()`.

## Installer limits

| Limit | Value |
|---|---:|
| Downloaded OPK | 8 MB |
| Uncompressed package | 8 MB |
| One extracted file | 2 MB |
| Files per package | 64 |
| Manifest | 8 KB |

The device rejects encrypted ZIPs, data descriptors, ZIP64-sized payloads,
unsafe paths, duplicate files, unsupported methods and CRC/SHA mismatches.
Installation uses a staging directory and rollback backup.
The URL, hash, ID, scope, display name and version metadata must all agree
between the active catalog and the downloaded manifest. Downgrades and
cross-scope replacements are rejected.

The build tool enforces the same limits before publishing, writes packages and
the catalog atomically, and emits deterministic ZIPs: unchanged inputs produce
the same OPK SHA-256. It also rejects duplicate IDs, reserved namespaces,
missing entry scripts and source files outside the repository.

System packages are additionally limited to known OpenOS package IDs and the
configured system-package prefix. OPK currently protects integrity with catalog
SHA-256; signed catalogs/packages should be added before treating system updates
as secure against an active network attacker.

OpenStore uses the native `store.refresh()` and indexed `store.*(i)` API. Only
the selected item's small strings cross into OSA; the package manager releases
the cached catalog before starting TLS/ZIP work to preserve heap on ESP32 boards
without PSRAM.

Catalog entries with `scope: "system"` appear under the `System Apps` tab.
Publishing a new system update requires changing its source in
`store/system_apps/`, increasing both `version` and `versionCode` in the matching
manifest, rebuilding the OPKs, and uploading the rewritten catalog and package.
The device accepts system packages only for the fixed `openos.*` allowlist and
only from the configured system-package URL prefix.

Run the repository checks with:

```text
python -m unittest discover -s test -p "test_*.py" -v
```
