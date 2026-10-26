# Tokening

Narrow permissions for AI agents.

AI agents usually get the same credentials a human admin would, because most APIs offer nothing narrower. Tokening sits between the agent and the API and issues grants for single actions: update this post, once, title and body only, within fifteen minutes. The agent never sees the real key. Every call is checked against its grant, and every refusal comes with a reason a person can read.

The real upstream credential must stay in Tokening, outside the agent environment. The admin listener must also be unreachable by agents. A grant cannot prevent bypass if the agent already has the real credential.

Status: early development. The command scaffold supports `tokening version` and `tokening help` and `tokening check examples/wordpress.json`; the gateway is not implemented yet. Build it with `make build` using Go 1.23 or newer. Run checks with `make test`. `make demo` will fail with an explanation until the Docker demo is ready. The plan is in [docs/plan.md](docs/plan.md).

Licence: Apache 2.0.

Policy files are checked locally without contacting targets or opening the credential vault. See [the policy reference](docs/policy.md) for supported fields and warnings.

The internal SQLite store now supports WAL mode and atomic schema migrations. Grant handling and the gateway are still in development. See [storage](docs/storage.md) for persistence and backup details.
