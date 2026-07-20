i crashed out so i am doing an a week break :3 


# OpenStore repository

This repository hosts the OpenStore catalog and OPK packages separately from
the OpenOS firmware source.

## Publish

Run from the repository root:

```text
python tools/build_opk.py
python -m unittest discover -s test -p "test_*.py" -v
```

Commit and push these generated paths to `main`:

- `store/catalog.json`
- `store/packages/*.opk`

The configured device catalog URL is:

```text
https://raw.githubusercontent.com/openplace1/OpenStore/main/store/catalog.json
```

Package URLs are generated with the base URL defined in `store/build.json`.

# Note

If you want to create an app and publish it to the official repository (the one you're currently on), create an Issue and add the .osa file. If your app is approved, it will be added to the store.
