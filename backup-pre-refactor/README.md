# Backup Pre-Refactor (v1.9.0)

This directory contains a backup of the source code and release assets
before the P0/P1 refactoring effort.

## Contents

- `source/` - All source files (.cs, .csproj, .md, .json, Lang/)
- `release/` - Release Lang/ files (exe/zip excluded due to GitHub 100MB limit)
- `publish/` - Publish Lang/ files (exe excluded due to GitHub 100MB limit)

## Note on Large Binaries

The compiled `FirewallManager.exe` (~110MB, self-contained single-file) and
`FirewallManager-v1.9.0-win-x64.zip` have been excluded from this backup
because they exceed GitHub's 100MB file size limit.

To obtain the v1.9.0 binary, see GitHub Releases:
https://github.com/fjhk542/FirewallManager/releases/tag/v1.9.0

## Backup Date

2026-08-04 (based on commit 88a59ab)
