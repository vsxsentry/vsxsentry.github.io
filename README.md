# VSXSentry  -  VS Code Extension Threat Intelligence

[![Sync Feed](https://github.com/vsxsentry/vsxsentry.github.io/actions/workflows/sync_feed.yml/badge.svg)](https://github.com/vsxsentry/vsxsentry.github.io/actions/workflows/sync_feed.yml)

**[vsxsentry.github.io](https://vsxsentry.github.io)**

Community-driven threat intelligence for Visual Studio Code extensions. Track malicious, removed, and suspicious extensions from the VS Marketplace.

## What is VSXSentry?

VS Code extensions execute as native Node.js processes with full access to the file system, terminals, environment variables, SSH keys, and source code  -  with **no sandbox and no permission model**. VSXSentry provides:

- **Live feed** of known-malicious, removed, and suspicious VS Code extensions
- **Extension Checker**  -  paste your `code --list-extensions` output and instantly find matches
- **Policy Generator**  -  create `settings.json` blocklist/allowlist snippets for enterprise deployment
- **Investigation Guide**  -  forensic traces and remediation procedures for incident response
- **Inventory Tools**  -  PowerShell, Python, and Bash scripts to scan workstations

## Feed

The canonical feed is maintained at:
```
https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/VSCODE%20Extensions/feeds/vsxsentry_feed.json
```

[vsxsentry.github.io](https://vsxsentry.github.io) provides the combined feeds in different formats

A GitHub Action syncs a local copy to `feeds/vsxsentry_feed.json` every 6 hours for fast same-origin loading on the site.

## Data Sources

- [Microsoft VS Marketplace RemovedPackages.md](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md)
- [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists)  -  curated threat intelligence lists
- Community submissions and security research

## License

MIT
