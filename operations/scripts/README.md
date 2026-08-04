# Controlled operations scripts

These scripts are reusable operational primitives. They must not contain
environment-specific hostnames, addresses, image tags, user identifiers, or
credential values.

`read-root-secret-file.sh` reads a regular root-owned file into a caller-provided
Bash variable without requiring a trailing newline. It rejects symbolic links,
non-root ownership, group or other permissions, empty values, NUL bytes, and a
file that changes while it is being read. It never writes the value, its length,
or its digest to stdout or stderr.

Return codes:

- `0`: the value was read into the requested variable;
- `1`: the file or its security properties are unsafe;
- `2`: the function was called incorrectly.

Run the regression matrix as root:

```sh
sudo bash operations/scripts/tests/read-root-secret-file.test.sh
```

`validate_compose_secret_files.py` renders (or reads) Compose JSON and fails closed
unless every `secrets.*.file` resolves to a root-owned regular file with mode `0400`
or `0600` below an explicitly approved Secret root. It rejects path escapes and a
duplicated `runtime/runtime` segment, and prints only validated paths and metadata.

Run its Compose integration regression as root:

```sh
sudo bash operations/scripts/tests/validate-compose-secret-files.test.sh
```
