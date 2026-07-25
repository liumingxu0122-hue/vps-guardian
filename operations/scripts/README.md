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
