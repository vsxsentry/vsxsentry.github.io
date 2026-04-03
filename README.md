# VSXSentry - VS Code Extension Threat Intelligence

[![Sync Feed](https://github.com/vsxsentry/vsxsentry.github.io/actions/workflows/sync_feed.yml/badge.svg)](https://github.com/vsxsentry/vsxsentry.github.io/actions/workflows/sync_feed.yml)

**[vsxsentry.github.io](https://vsxsentry.github.io)**

Community-driven threat intelligence for Visual Studio Code extensions. Track malicious, removed, and suspicious extensions from the VS Marketplace.

## What is VSXSentry?

VS Code extensions execute as native Node.js processes with full access to the file system, terminals, environment variables, SSH keys, and source code - with **no sandbox and no permission model**. VSXSentry provides structured, machine-readable feeds and tools for security teams to detect, block, and respond to malicious extensions.

## Features

### Feed Browser
- **Combined feed** - all records (malicious + risky) with full-text search across all fields
- **Malicious feed** - extensions removed for malware, typo-squatting, impersonation, spam
- **Risky feed** - legitimate but dual-use extensions (remote access, tunnels, credential vaults, AI code agents, file transfer, cloud access, database clients)
- Sortable columns (Extension ID, Publisher, Severity, Category, Comment, Source, Removal Date)
- Every view has a unique shareable URL via hash routing

### Feed Downloads
All feeds are generated server-side and served as static files - right-click any download link to copy the URL for remote consumption (Microsoft XDR, Splunk, etc.):
- **Combined/Malicious/Risky** feeds in JSON and CSV
- **IOC lists** - extension IDs, high-risk IDs, publisher blocklist (one per line)
- **Splunk** lookup CSV
- **Microsoft Sentinel** watchlist CSV
- **STIX 2.1** bundle for TAXII / OpenCTI / MISP
- **MISP** event and warning list
- **OpenCTI** CSV with scores and confidence
- **OpenIOC** for Mandiant-style endpoint sweeps

### Script Generator
Generate platform-specific scripts to detect, block, or remove extensions from the VSXSentry feed:
- **Platforms**: Windows (PowerShell), Linux (Bash), macOS (Bash)
- **Actions**: Detect, Remove, Block (policy)
- **Feed scope**: Malicious only, Risky only, All
- **VS Code variants**: code, code-insiders, codium, cursor
- **Options**: severity filter, dry-run mode, skip confirmation
- Quick presets for one-click use
- Scripts fetch the feed at runtime so they always use the latest data
- CLI discovery with fallback paths, feed fetch with fallback URL, proper error handling at every step
- Block action directly merges `extensions.allowed` into `settings.json` with backup

### VSIX Analyzer
Upload a `.vsix` package for client-side analysis (nothing leaves your browser):
- **Archive SHA-256** hash
- **Per-file SHA-256** hashes for every file in the package (with copy all)
- **Manifest parsing** - extension ID, publisher, version, activation events, capabilities
- **Feed matching** - exact extension ID match and publisher-level match
- **Risk signal scanning** - child_process, file system access, network calls, secret/credential access, terminal creation, minified bundles
- **Native binary detection** with PE signer extraction (signed/unsigned, signer CN)
- **IP address extraction** - hardcoded IPv4 addresses (private ranges filtered)
- **Domain extraction** - external domains found in code (common false positives filtered)
- **URL extraction** - all HTTP/HTTPS URLs found in the package
- **Dependency listing** - runtime and dev dependencies with suspicious name detection
- **File listing** - largest files sorted by size, color-coded by type (binaries, scripts, other)
- **Marketplace download URL** - auto-generated API URL to re-download the exact analyzed version
- **Block policy snippet** - ready-to-use `extensions.blocked` JSON for the analyzed extension
- VSIX download instructions with Marketplace API URL template

### Policy Generator
Generate `extensions.allowed` enterprise policies:
- **Feed scope**: Malicious only, Risky only, All
- **Blocklist mode** - `"*": true` with specific extensions set to `false`
- **Allowlist mode** - `"*": false` with explicit allows (Microsoft/GitHub defaults)
- Custom extension entries for both modes
- Platform-specific deployment guides:
  - **Windows** - ADMX/ADML Group Policy with GPO instructions
  - **macOS** - `.mobileconfig` profiles for MDM (Jamf, Intune, Mosyle, Kandji)
  - **Linux** - `/etc/vscode/policy.json` with Ansible example

### Investigation Guide
- **Forensic Traces** - OS-specific paths for extensions, settings, logs, caches, persistence locations, process artifacts, and network indicators (Windows, macOS, Linux)
- **Remediation Playbook** - 4-step incident response: isolate and remove, hunt for persistence (Settings Sync, workspace recommendations, devcontainer.json, scheduled tasks), credential rotation priority list, enterprise hardening checklist

### Inventory Tools
PowerShell, Python, and Bash scripts in `tools/` to scan workstations for installed extensions.

## Feed

The canonical feed is maintained at:
```
https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/VSCODE%20Extensions/feeds/vsxsentry_feed.json
```

A GitHub Action syncs a local copy every 6 hours and runs `generate_feeds.py` to produce all feed formats as static files under `feeds/`.

### Feed files served from this repo

| File | Description |
|---|---|
| `vsxsentry_feed.json` / `.csv` | Combined feed (malicious + risky) |
| `vsxsentry_malicious_feed.json` / `.csv` | Malicious extensions only |
| `vsxsentry_risky_feed.json` / `.csv` | Risky extensions only |
| `ioc_all_extension_ids.txt` | All malicious extension IDs |
| `ioc_high_risk_extension_ids.txt` | Critical/high severity malicious IDs |
| `ioc_block_publishers.txt` | Publishers with high-severity malicious extensions |
| `risky_extension_ids.txt` | All risky extension IDs |
| `vsxsentry_splunk_lookup.csv` | Splunk lookup table |
| `vsxsentry_sentinel_watchlist.csv` | Microsoft Sentinel watchlist |
| `vsxsentry_stix2_bundle.json` | STIX 2.1 bundle |
| `vsxsentry_misp_event.json` | MISP event |
| `vsxsentry_misp_warninglist.json` | MISP warning list |
| `vsxsentry_opencti_import.csv` | OpenCTI import CSV |
| `vsxsentry_openioc.ioc` | OpenIOC format |
| `stats.json` | Feed statistics |

### Risky extension categories

These are legitimate extensions that represent enterprise risk - not malicious, but dual-use:

| Category | Examples |
|---|---|
| `risky-remote-access` | Remote SSH, Remote Tunnels, RDP, Codespaces, Gitpod, Coder |
| `risky-tunnel` | ngrok, Cloudflare Tunnel, Tailscale, LocalTunnel |
| `risky-credential-access` | 1Password, Keeper, HashiCorp Vault, Doppler, Infisical |
| `risky-ai-code-access` | Copilot, Cline, Roo Code, Continue, Tabnine, Codeium, Supermaven, Cody |
| `risky-cloud-access` | AWS Toolkit, Azure Resources, Cloud Code, Kubernetes, Docker |
| `risky-database-access` | SQLTools, Database Client, MongoDB, Redis, MSSQL, Oracle, CosmosDB |
| `risky-file-transfer` | SFTP sync, ftp-simple, Deploy Reloaded, PRO Deployer |
| `risky-code-execution` | Code Runner, Jupyter, PowerShell, Live Server |
| `risky-api-client` | Thunder Client, Postman, REST Client |
| `risky-collaboration` | Live Share |
| `risky-infrastructure` | Terraform, Pulumi, Tilt |
| `risky-git-access` | GitLens, GitHub Pull Requests |

## Data Sources

- [Microsoft VS Marketplace RemovedPackages.md](https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md) - official list of removed extensions
- [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists) - curated threat intelligence lists
- Community submissions and security research

## Contributing

Found a malicious or suspicious VS Code extension? Submit it via the **Contribute** button on the site, which opens a pre-filled GitHub issue on [mthcht/awesome-lists](https://github.com/mthcht/awesome-lists/issues).

## Related

- [ExtSentry](https://extsentry.github.io) - Browser extension threat intelligence

## License

MIT
