# Third-party licenses

Tokening uses `modernc.org/sqlite` for SQLite without CGO. This keeps one-binary
builds portable and avoids a separate database service. `golang.org/x/crypto`
provides NaCl secretbox for authenticated credential encryption, as specified in
the project plan. The other modules below are runtime dependencies. Versions are
pinned in `go.mod` and `go.sum`.

| Module | Version | License family | Full notice text |
| --- | --- | --- | --- |
| golang.org/x/crypto | v0.40.0 | BSD-3-Clause | [Notices](third_party/golang.org_x_crypto.txt) |
| modernc.org/sqlite | v1.38.2 | BSD-3-Clause; SQLite public domain | [Notices](third_party/modernc.org_sqlite.txt) |
| github.com/dustin/go-humanize | v1.0.1 | MIT | [Notices](third_party/github.com_dustin_go-humanize.txt) |
| github.com/google/uuid | v1.6.0 | BSD-style | [Notices](third_party/github.com_google_uuid.txt) |
| github.com/mattn/go-isatty | v0.0.20 | MIT | [Notices](third_party/github.com_mattn_go-isatty.txt) |
| github.com/ncruces/go-strftime | v0.1.9 | MIT | [Notices](third_party/github.com_ncruces_go-strftime.txt) |
| github.com/remyoudompheng/bigfft | v0.0.0-20230129092748-24d4a6f8daec | BSD-style | [Notices](third_party/github.com_remyoudompheng_bigfft.txt) |
| golang.org/x/exp | v0.0.0-20250620022241-b7579e27df2b | BSD-style | [Notices](third_party/golang.org_x_exp.txt) |
| golang.org/x/sys | v0.34.0 | BSD-style | [Notices](third_party/golang.org_x_sys.txt) |
| modernc.org/libc | v1.66.3 | BSD-style and bundled licenses | [Notices](third_party/modernc.org_libc.txt) |
| modernc.org/mathutil | v1.7.1 | BSD-style | [Notices](third_party/modernc.org_mathutil.txt) |
| modernc.org/memory | v1.11.0 | BSD-style | [Notices](third_party/modernc.org_memory.txt) |

The Go standard library is BSD-licensed; its [license text](third_party/go.txt)
is included. Include this file and the `third_party` directory with binary
distributions. Update the table and notice files whenever a dependency changes.

## Disposable Docker demonstration

The Go binary has no new dependencies for the demonstration. Compose downloads separate WordPress, MariaDB, Python, Alpine and Go container images, retaining the notices distributed with those images. WordPress is GPL-2.0-or-later (https://wordpress.org/about/license/); MariaDB server is GPL-2.0 (https://mariadb.com/kb/en/mariadb-licenses/); Python is distributed under the PSF license (https://docs.python.org/3/license.html). Container base distributions include packages under their respective licenses.

The WordPress image also downloads the official WordPress MCP Adapter 0.7.1 release, licensed GPL-2.0-or-later, from https://github.com/WordPress/mcp-adapter/releases/tag/v0.7.1. Its bundled license and dependency notices remain in the installed plugin. The ZIP SHA-256 is c8bc28f83d3c39beffa2add4f6becc0b1ae54097df433697d1dbe6520a80d769. This plugin is used in the disposable WordPress container, not linked into the Tokening Go binary. The demo abilities source in this repository is authored for Tokening.

## Browser checks

CI installs Playwright 1.58.2 only for browser verification (Apache-2.0, https://github.com/microsoft/playwright/tree/v1.58.2). The installed test package retains its license and notices. It is not included in the Go binary or generated replay HTML. The panel itself uses repository-owned HTML, CSS and JavaScript with no browser libraries, fonts or remote assets.
