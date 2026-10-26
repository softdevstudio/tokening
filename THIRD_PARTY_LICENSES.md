# Third-party licenses

Tokening uses `modernc.org/sqlite` for SQLite without CGO. This keeps one-binary
builds portable and avoids a separate database service. The other modules below
are its runtime dependencies. Versions are pinned in `go.mod` and `go.sum`.

| Module | Version | License family | Full notice text |
| --- | --- | --- | --- |
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
