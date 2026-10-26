# SQLite storage

Tokening's internal store opens one on-disk SQLite database. It uses the pure-Go
`modernc.org/sqlite` driver, so no C compiler or external database server is needed.
The server and grant commands will use this package when they are implemented.
There is no database CLI command yet.

Keep the database in a private directory controlled by the operator. The store
creates the database with mode 0600 and restricts an existing file to the same
mode. Windows file access still depends on the directory's ACL. The parent
directory must already exist. Database symlinks and SQLite URI inputs are
refused. File names containing URI punctuation are escaped, not interpreted as
connection settings.

WAL mode lets readers work while another connection writes. Each connection
uses foreign keys, a five-second busy timeout and `synchronous=FULL`. One store
handle keeps one connection; separate handles or processes use SQLite's write
locks. The directory must allow SQLite to create its `-wal` and `-shm` sidecars.
Use a local filesystem that supports SQLite locking. Copying only the main file
while a writer is running is not a backup; use SQLite's backup API or shut down
all processes before copying the database.

Migrations are embedded SQL files, tracked by SQLite's `user_version`. They run
inside one immediate transaction. A failed migration rolls back both its schema
changes and the version update. Concurrent initializers serialize before reading
the version. A database made by a newer schema is refused rather than downgraded.

The initial schema has targets, versioned templates, grants and decisions.
A grant references the exact `(template_id, template_version)` that issued it.
Template versions cannot be updated or deleted. A policy change will create a new
version; reload and issuance are separate work still to come.

Grant secrets have a unique, 32-byte hash column, with no plaintext secret column.
Counters cannot be negative or exceed the initial allowance. Times are UTC Unix
milliseconds. Credentials have an opaque ciphertext column; encryption is the
vault's responsibility and is not implemented in this stage.

Audit decisions are append-only through SQL triggers. An unknown-token refusal
can have a null grant ID. Arguments are represented by a SHA-256 digest, and
response bodies have no storage column. These checks protect normal application
writes. Someone who can modify the database directly can remove triggers, so
this is not a tamper-evident audit system.

Tests cover persistence, connection settings after pool replacement, foreign-key
and counter checks, immutable template versions and append-only decisions.
Migration tests inject a failure after a schema write and check rollback, reject
newer versions, and race independent database initializers. The planned single-use
consumer and process-kill failure tests are still separate tasks.
