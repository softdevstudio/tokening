# Tokening

Narrow permissions for AI agents.

AI agents usually get the same credentials a human admin would, because most APIs offer nothing narrower. Tokening sits between the agent and the API and issues grants for single actions: update this post, once, title and body only, within fifteen minutes. The agent never sees the real key. Every call is checked against its grant, and every refusal comes with a reason a person can read.

Status: early development, nothing to install yet. The plan is in [docs/plan.md](docs/plan.md).

Licence: Apache 2.0.
