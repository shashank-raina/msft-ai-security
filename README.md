# Microsoft AI Security Stack — Reference for Security Architects

A technical reference site covering Microsoft's AI and agentic security stack, built for security architects who need breadth across the full stack — not just depth in one product.

🌐 **Live site:** [aiagentsecurity.guide](https://aiagentsecurity.guide)

---

## ⚠️ Disclaimer

**This is an independent project. It is not affiliated with, endorsed by, or sponsored by Microsoft Corporation.** All Microsoft product names, logos, and brands are property of Microsoft Corporation and are used here for reference and identification purposes only.

Content reflects the personal views and research of the maintainer, not those of any employer or vendor. While every effort is made to keep information accurate and current, Microsoft's AI security stack evolves rapidly — always verify against [official Microsoft documentation](https://learn.microsoft.com/) before making architectural decisions.

---

## About

Microsoft's AI security story spans Entra, Defender, Purview, Sentinel, Copilot Studio, AI Foundry, Security Copilot, and more — with documentation scattered across product teams, learn paths, and blog posts. Security architects need to reason about all of it together.

This site exists to fill that gap: a single place to see how the pieces fit, where the gaps are, and how to apply Zero Trust principles to AI and agentic workloads.

The site is structured as a layered model across **seven security domains**, with practical guidance on:

- **Frameworks** — Microsoft's security frameworks applied to AI workloads
- **Zero Trust for AI** — three principles, three-stage maturity model, twelve priority controls
- **Gaps** — known limitations, governance gaps, and architectural caveats worth flagging
- **Authentication patterns** — including Copilot Studio agent auth patterns and Conditional Access scope clarifications
- **Detection content** — KQL queries for Microsoft Sentinel covering agent inventory, auth-type changes, and related scenarios
- **Threat scenarios** — including agent-to-agent (A2A) propagation risks

---

## Audience

Primarily **security architects** designing or assessing Microsoft AI deployments. Content is also framed for adjacent personas including CISOs evaluating risk posture, identity engineers, and SOC analysts building detection content.

The site assumes working familiarity with the Microsoft security stack — it is a reference, not an introduction.

---

## Tech stack

- Static HTML / CSS / JavaScript
- Hosted on **Cloudflare Pages**
- Chat assistant via a Cloudflare Pages Function (`functions/api/chat.js`) calling the Anthropic API
- Contact form via **Formspree**
- No tracking, no ads, no analytics beyond Cloudflare's edge metrics

### Chat API configuration

The `/api/chat` function reads these from the Pages project settings:

- **Environment variables** — `ANTHROPIC_API_KEY`, `CHAT_PASSWORD`
- **KV namespace binding** (optional but recommended) — bind a KV namespace as
  `RATE_LIMIT_KV` to enable per-IP rate limiting (default: 30 requests / 60s).
  Create it under **Workers & Pages → KV**, then add the binding under
  **Pages project → Settings → Functions → KV namespace bindings**. If the
  binding is absent the function fails open (no rate limiting), so the chat
  keeps working without it.

---

## Contributing

Issues, corrections, and suggestions are very welcome — particularly:

- Factual errors or outdated guidance (Microsoft moves fast)
- Broken links to Microsoft documentation
- Missing scenarios or gaps worth surfacing
- KQL improvements or new detection ideas

**How to contribute:**

1. **Open an issue** for discussion before significant changes — this keeps direction aligned and avoids wasted work
2. **Pull requests** are reviewed by the maintainer; the `main` branch is protected and only the maintainer merges
3. For substantive new content (new pages, new sections), please discuss in an issue first

This is a personally maintained reference site, so editorial direction stays with the maintainer. That said, community input is what keeps it useful — please don't hesitate to flag things.

---

## License

Code in this repository is provided for transparency and reuse under the [MIT License](LICENSE).

Written content (page text, frameworks, threat scenarios, KQL queries) is provided for reference under [Creative Commons Attribution 4.0 (CC BY 4.0)](https://creativecommons.org/licenses/by/4.0/) — feel free to reuse with attribution.

External content referenced on the site (Microsoft documentation, third-party blog posts, conference materials) remains the property of its respective authors and is cited where used.

---

## Contact

- **Issues / corrections:** open a GitHub issue
- **Direct contact:** via the contact form on [aiagentsecurity.guide](https://aiagentsecurity.guide)
- **Speaking / community:** active in the European SharePoint, Office 365 & Azure Conference (ESPC) community

---

*Maintained by [@shashank-raina](https://github.com/shashank-raina). Independent of any employer.*
