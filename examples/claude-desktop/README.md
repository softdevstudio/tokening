# Claude Desktop and a stdio filesystem server

This example puts Tokening between Claude Desktop and the filesystem MCP
server, so Claude can read one file, or write one file once, and nothing
else in the folder.

Claude Desktop starts MCP servers as commands. Here the command is
`tokening connect`, which passes Claude's messages to the gateway. The
gateway starts the real filesystem server for each call it allows, with
nothing from its own environment but PATH, HOME and the like.

1. Change `/Users/you/notes` in `tokening.json` to your folder, then check
   the policy and start the gateway (see docs/server.md for the keys):

   ```sh
   tokening check tokening.json
   tokening serve --policy tokening.json --db tokening.db --key-file vault.key
   ```

   The filesystem server needs no secret, so `tokening target add` is
   optional here. A server that does (GitHub, a database) gets one as
   environment variables: `{"env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "..."}}`
   in the file passed to `--cred-file`.

2. Issue a grant for one file:

   ```sh
   tokening grant issue notes.read-one-file \
     --bind 'path="/Users/you/notes/todo.md"' --uses 20 --ttl 8h \
     --to claude-desktop --reason "read my todo list"
   ```

3. Put the printed secret in `claude_desktop_config.json` as
   `TOKENING_GRANT`, merge the `notes` entry into Claude Desktop's own
   config file (on macOS, `~/Library/Application Support/Claude/claude_desktop_config.json`),
   and restart Claude Desktop. `tokening` must be on the PATH Claude
   Desktop sees, or give its full path as `command`.

Claude now sees one tool, `read_text_file`. Asking it for todo.md works.
Asking for any other file, a path with `..` in it, or a write comes back as
a refusal that says what the grant allows, and the server is never started
for it. `tokening log` shows every call and every refusal, and
`tokening flight verify` checks the record.

When the grant runs out or expires, issue a new one and change the secret
in the config.

The policy pins the server's version, so an npm update can't change what
the gateway runs. The filesystem server only sees the folder it is given.
Servers with free-form paths or commands can reach whatever the user
running `tokening serve` can, vault.key included, so give those a separate
operating system user (see "Stdio servers" in docs/server.md).
