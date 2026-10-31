// Package version holds the release version, the one place it is written.
// The binary, the MCP serverInfo and clientInfo, and the release workflow all
// read it from here.
package version

// Version is raised for each release. scripts/release.py reads this line.
const Version = "0.1.4"
