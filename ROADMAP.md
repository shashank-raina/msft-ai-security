# Roadmap — candidate content for the primer structure

Working notes on what to bring into the six-page structure next, and what deliberately
stays in `/archive/`. Written 1 Sep 2026, after the depth pass (field notes, voice,
four-screens, annotated KQL, held positions). **Rule that governs all of it: every
addition must show judgment or breadth without re-inflating the site. Nav ceiling: 8 items.**

## The gap analysis

The six pages currently teach: **where** risk lives (Five Surfaces) · **what you can
see** (Agent Map) · **what it costs** (Licensing) · **what to do first** (Start Here) ·
**judgment** (Field Notes). Missing from the concept story: what attacks actually look
like, how agent identity/governance mechanically works, and what to do on the bad day.

## Agreed candidates, in priority order

### 1. "How agents get attacked" page — the strongest candidate (+1 nav slot, nav → 8)

The site says "prompt abuse" and "tool poisoning" in passing but never shows the reader
an attack. Roughly six entries, one paragraph each, each paired with the control that
answers it *and that control's limit*:

- **Indirect prompt injection**, with **EchoLeak (CVE-2025-32711)** as the one worked
  case study — crafted email poisons M365 Copilot's context, limited exfiltration,
  victim sees nothing.
- **MCP tool-poisoning chain** — description poisoning → **silent re-trust** (metadata
  changes take effect without re-approval, the step people miss) → invocation →
  exfiltration.
- **Extractive prompt abuse** — pushing an assistant past summarisation boundaries
  ("list every salary in this file").
- **HashJack-style injection** via URL fragments; hostile instructions in calendar invites.
- Controls with limits: Prompt Shields inspects tool outputs only where deployed;
  **spotlighting is off by default**, Chat Completions only, adds tokens; Microsoft's own
  layered pattern assumes **some attacks succeed — design for containment**.
- Mention OWASP Top 10 for Agentic Applications (Dec 2025); Microsoft names tool misuse
  and supply chain as its fastest-moving categories.

Named CVEs and technique names are credibility that can't be faked. Distils from
`archive/threats.html` (~200K) to one short page. Source facts live in the internal
FACTS register; re-verify dates before publishing.

### 2. Emergency runbook — section on Start Here (no nav cost)

"An agent is misbehaving, right now": disable the **blueprint** (fleet kill switch —
stops every agent under it authenticating), block in the registry, the two hunting
queries for what it touched, what evidence to preserve. One screen, distilled from
`archive/playbooks.html`. Nothing signals practitioner more than having thought about
the bad day in advance.

### 3. E5-vs-A365 feature boundary — callout on Licensing (no nav cost)

The Agent 365 service description's boundary is narrower than most decks assume: base
M365 plans already get registry inventory, basic governance actions (publish, block,
delete, approve, assign), conditions-based lifecycle rules, and registry sync from
external platforms. E7/A365 adds observability, CA/ID Protection for agents, the Purview
extensions, the Defender agent capabilities, tenant-wide MCP control. One callout,
placed where the budgeting decision happens.

### 4. Agent identity & governance page — only if promoted deliberately

**Decision: no product-branded "Agent 365" page.** A product page drags the site back
toward restating Microsoft docs (that is exactly what `archive/agent365.html` is, and
why it is archived) and ages with every rename. If the identity story earns a page, it
is concept-titled ("Agent identity & governance"): blueprints as the credential
boundary, the two-leg token flow (CA enforces on T2), legacy agents outside the
perimeter, inheritable permissions. Requires deciding what leaves the nav to make room —
parked until then.

## Active investigation (started 1 Sep 2026)

**Foundry prompt monitoring & control, and the Purview/Defender interaction with
agents.** Questions on the table:

- For **Microsoft Foundry** agents: how are prompts monitored — and is Purview the
  mechanism, or is it Foundry observability / Defender threat protection / the Agent 365
  connector's `UnifiedAgentObservability` spans? What actually *controls* (blocks) a
  prompt vs merely records it?
- How do **Purview** and **Defender** each interact with agents across the platforms —
  which capabilities are automatic, which need developer integration, which need Agent
  365 onboarding?
- Outcome feeds the **Agent Map**: the Foundry creation path's edges, the "gives" on
  each, and the licence gates need to reflect the verified answer.

## What stays in the archive permanently

`product-map` (a catalogue) · `demo` · the full A365 feature inventory · the long
identity walkthrough. Reference, not concept — the 301 redirects and "deep-dive archive"
links already serve them.
