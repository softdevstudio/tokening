# Policy files

Run `tokening check examples/wordpress.json` to validate a policy. Exit code 0
means it is valid, 1 means it could not be read or validated, and 2 means the
command arguments were wrong. Warnings go to stderr. Warnings do not prevent a
valid policy from loading. Checking never contacts an upstream or reads a secret.

A policy is a JSON object with `targets` and `templates`. Both must be nonempty.
Files are limited to 1 MiB. Unknown fields, duplicate object keys, null values and
trailing JSON values are errors. Omit optional fields instead of setting null.
Target and template names use letters, digits, dots, underscores and hyphens,
starting with a letter or digit.

Targets have `kind`, `url` (for `http` or `mcp_http`) or a `command` array (for
`mcp_stdio`), and `credential`. A credential contains `type` and a `ref` such as
`vault:demo-wp`. HTTP credential types are `basic`, `bearer` and `header`; stdio
uses `env`. Actual credentials never belong in this file. Command and credential
shapes are validated here; the gateway and stdio runner are not implemented yet.
HTTP URLs cannot contain user credentials, a query or a fragment.

Templates name a `target`, a positive `max_uses` and a positive whole-second
`max_ttl` duration such as `15m`. MCP templates have a `tool`. REST templates have
an uppercase `method` and an absolute `path`, for example `/posts/{id}`. Each path
placeholder needs an entry in `args` with `bind: required`. REST body fields also
use `args`; query parameter constraints use `query`. Fields used in paths will
be separated from the body by the gateway. MCP templates cannot have query rules.

Each argument rule can have `bind: required` to fix a value when issuing a grant.
A required binding can omit `type`. Otherwise `type` is `string`, `integer`,
`number` or `boolean`. `bind: optional` permits an issue-time binding, with a
mandatory type. Optional binding means the binding is optional, not that it may
be ignored after a value has been bound. Nested object and array rules are outside
this version's vocabulary.

String rules can set `max_len` (Unicode code points), `max_bytes` (UTF-8 bytes),
and `pattern` (RE2 syntax, matched against the whole string). Limits may be zero.
Numeric rules can set `min` and `max`. `enum` must be a nonempty array matching a
string or numeric type. `sha256: true` on a bound string says that the issuer will
store and match a hash of the bound value. Hash computation and enforcement are
part of grant issuing and the matcher, not the policy checker.

Unlisted fields are refused by default. `additional_args: allow` explicitly
permits them and produces a warning. A string with no length limit, fixed required
binding, enum or hash constraint also produces a warning. A regex alone does not
count as a size limit. Warnings are printed in stable order.

This command checks policy structure and constraints. It does not prove that an
upstream tool exists or that a credential works, and does not yet enforce calls.
