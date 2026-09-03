# CtrlDB

CtrlDB is a safety-first terminal control plane for self-managed databases on
Google Cloud, starting with MongoDB.

The project is in early development and is not ready for production use.

## Direction

CtrlDB is being designed to make routine database operations observable,
repeatable, and difficult to perform unsafely. The initial scope includes:

- discovering Google Cloud resources and database health;
- planning changes with cost, downtime, and rollback information;
- provisioning and resizing Compute Engine infrastructure;
- managing backups, recovery rehearsals, and operational automation; and
- granting time-bounded external access without exposing databases broadly.

The command-line interface will support both an interactive terminal UI and
scriptable, non-interactive commands.

## Development

CtrlDB requires Go 1.27 or later. The repository uses
[Qlty](https://docs.qlty.sh/) as the common interface for formatting, linting,
security scanning, and maintainability checks.

```sh
qlty fmt --all
qlty check --all --no-fix --level=low --fail-level=low
go run ./internal/archcheck
go test ./...
```

## License

Licensed under the Apache License 2.0. CtrlDB is not affiliated with or
endorsed by MongoDB, Inc. MongoDB is a trademark of MongoDB, Inc.
