# Contributing to aiagentsecurity.guide

Thanks for your interest in contributing. This site is a curated synthesis of Microsoft AI security documentation and field research from the community. Contributions are welcome and credited.

## How to suggest content

The simplest way to contribute is to open a GitHub Issue with a content suggestion. A maintainer will review it, run it through the content update workflow, and implement it if it's a good fit.

**Open an Issue and include:**

- **Source URL** — link to the Microsoft Learn article, MVP blog post, or official announcement
- **What's new** — one paragraph on what the source adds that isn't already on the site
- **Suggested page(s)** — which page(s) you think should be updated (see site structure below)

The maintainer will review the gap against the current site content and implement changes where warranted. All sources are cited by name.

## Site structure

| File | Content |
|---|---|
| `index.html` | Home — the five surfaces, the map, three facts |
| `surfaces.html` | The five AI threat surfaces: risks, owning controls, licence gates |
| `licensing.html` | Three licence axes and the E5 / Agent 365 / E7 / lake splits |
| `agent-telemetry-map.html` | Interactive map: creation paths → telemetry → licences |
| `field-notes.html` | Field notes — hands-on gotchas: schema traps, licence boundaries, migration surprises |
| `start.html` | Four-screens rule, six-phase rollout, first-week checklist |
| `contact.html` | Feedback form + privacy policy |
| `archive/*.html` | The former deep-dive pages, kept as reference (agent365, identity, threats, playbooks, overview, product-map, demo, changelog) |

When `site.css` changes, bump the `?v=` query on every root page's stylesheet link in the same commit — browsers and CDN edges cache the CSS independently of the HTML, and a stale stylesheet renders new components unstyled.

## What fits this site

The site focuses on **security architecture for Microsoft AI products** — specifically Copilot Studio, Microsoft Foundry, Agent 365, Entra Agent ID, Defender for AI, Purview DLP, and the surrounding identity and data security stack.

Good contributions:
- New Microsoft Learn documentation on AI security topics
- Field-validated findings from Microsoft Security MVPs (with attribution)
- GA/Preview status changes for security products
- New KQL queries or PowerShell scripts for agent security auditing
- New threat scenarios with real-world backing

Not a fit:
- General Azure, M365, or non-security content
- Opinion pieces without factual claims
- Product marketing without technical substance

## Automated content monitoring

This repo runs a daily GitHub Action (`content-monitor.yml`) that searches Microsoft Learn for changes to AI security documentation. When new content is found, it creates an Issue automatically. You can also trigger it manually from the Actions tab.

## Attribution

All contributions from named individuals or community sources are credited in the changelog and on the relevant page. The site's value proposition is transparent attribution — if you contribute a finding, your name goes on it.

## Questions

Use the [contact form](https://aiagentsecurity.guide/contact.html) or open an Issue.
