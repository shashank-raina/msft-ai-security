"""
AI Security Site Content Monitor
==================================
Searches Microsoft Learn daily for documentation changes related to
AI security topics. Uses Claude to analyse findings against the site's
current knowledge base and posts a GitHub Issue with actionable recommendations.

Run manually:   python scripts/content_monitor.py
Scheduled via:  .github/workflows/content-monitor.yml

Required env vars:
  ANTHROPIC_API_KEY   — Anthropic API key
  GITHUB_TOKEN        — GitHub token with issues:write permission
  GITHUB_REPO         — e.g. "shashank-raina/msft-ai-security"

Optional env vars:
  DRY_RUN=true        — print findings without creating an Issue
"""

import asyncio
import json
import os
import sys
from datetime import date
from typing import Optional

import anthropic
import httpx
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

# ── Configuration ─────────────────────────────────────────────────────────────

LEARN_MCP_URL = "https://learn.microsoft.com/api/mcp"

# Keywords to search — seeded from site content areas

# ── URL CONSTRUCTION WARNING ─────────────────────────────────────────────────────
# Microsoft Learn URLs follow naming conventions but are NOT always predictable.
# Do NOT construct URLs from table/feature names - always search first.
# Known correct URLs (verified):
#   AIAgentsInfo table: learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aiagentsinfo-table
#   Copilot Data Connector: techcommunity.microsoft.com/blog/microsoftsentinelblog/...4491986
#   Agent 365 GA blog: microsoft.com/en-us/security/blog/2026/05/01/...
#   Work IQ MCP: learn.microsoft.com/en-us/microsoft-agent-365/tooling-servers-overview
#   Defender AI agent detection: learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection
#   Defender AI agent inventory: learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-inventory
#   NOTE: Microsoft Defender security-for-ai docs live under /defender-xdr/security-for-ai/ subdirectory
# ─────────────────────────────────────────────────────────────────────────────────
SEARCH_QUERIES = [
    # Identity & Agent ID
    "Entra Agent ID blueprint principal authentication",
    "Entra Agent ID access packages governance lifecycle",
    "Entra Agent ID SDK containerized token service",
    "Conditional Access Agent ID policy segmentation",

    # Agent 365 & platforms
    "Microsoft Agent 365 observability OpenTelemetry",
    "Agent 365 Foundry agents AI teammate approval workflow",
    "Microsoft Agent 365 Exchange Online built-in agent",

    # Detection & KQL
    "AIAgentsInfo Advanced Hunting schema agent security",
    "CloudAppEvents Copilot audit Microsoft Sentinel",
    "Microsoft Sentinel Copilot data connector CopilotActivity",

    # Runtime & network protection
    "Secure Web AI Gateway Copilot Studio agents network",
    "Microsoft Defender AI agents Advanced Hunting preview 2026",
    "Defender XDR AI agent posture security site:learn.microsoft.com",

    # Data security
    "Purview DLP Copilot sensitivity labels grounding",
    "DSPM for AI data security posture management",

    # Pre-deployment & red teaming
    "PyRIT AI red teaming OWASP LLM agents",
    "Zero Trust for AI reference architecture ZT4AI",

    # MCP & A2A
    "Model Context Protocol MCP security agentic",
    "Agent-to-Agent A2A protocol Microsoft security",
]

# What the site already covers — used by Claude to identify genuinely new content
SITE_KNOWLEDGE_DIGEST = """
The site aiagentsecurity.guide covers these Microsoft AI security topics in depth.
Use this to determine whether a search result is genuinely NEW. If it is already covered
below, skip it — do not flag as a finding.

═══════════════════════════════════════════════════════════════
IDENTITY & ENTRA AGENT ID
═══════════════════════════════════════════════════════════════
- Entra Agent ID: Blueprint model, T1/T2 auth flow
- Blueprint credential preference order: Managed Identity via FIC (most preferred) >
  FIC (preferred when MI unavailable) > Secrets/Certs (dev/test only)
- FIC properties: issuer, subject, audiences (case-sensitive)
- Four Entra objects: Blueprint (template + credentials), Blueprint Principal (audit identity),
  Agent Identity (service principal, "agent" subtype, Object ID = App ID),
  Agent User (full human identity, survives Blueprint deletion)
- THREE SECURITY PROPERTIES of Agent Identity: (1) no admin token generation — Microsoft
  controls Blueprint, (2) tenant-bound tokens, (3) impersonation model
- Classic vs Modern agents: 73% of agents are Classic (service principals, zero Entra coverage)
- Five Copilot Studio auth patterns: ① OBO/Delegated, ② Maker credentials (very high risk),
  ③ App Reg Delegated, ④ App Reg Application (very high risk), ⑤ Agent User Account
  — Updated naming: "Agents with delegated access" (was OBO) / "Agents with own access" (was non-OBO)
- CA for Agent ID (Preview): applies to Modern agents (Agent Identities + Agent Users).
  Does NOT apply to Classic Copilot Studio agents. CA carve-outs: Blueprint token exchanges
  and T1 creation flows excluded by design.
- ID Protection for Agents (Preview): six risk detections:
  unfamiliarResourceAccess, signInSpike, failedAccessAttempt, riskyUserSignIn,
  adminConfirmedAgentCompromised, threatIntelligenceAccount
  — Manual actions: confirm compromise, confirm safe, dismiss risk, disable agent
- Custom security attributes for agent segmentation (AgentAttributes/AgentApprovalStatus)
- Agent segmentation: CA policies target by object ID, Blueprint, or custom security attribute
- InheritDelegatedPermissions property: identity inherits from Blueprint (disabled by default)
- Agent entities are CONFIDENTIAL CLIENTS ONLY — no redirect URIs, no /authorize endpoint
- Single-tenant enforcement: agent identities always single-tenant even if Blueprint supports
  multi-tenancy
- Owner + Sponsor model: technical and business accountability per agent
- Registry convergence: M365 admin center → Agents → All agents (all agents, AI Reader/Admin role,
  no licence needed) vs Entra admin center (Entra Agent ID only, Agent ID Admin role)
- RegistrySource: "A365" (Agent 365) vs "PowerPlatform" (Copilot Studio)
- SEVEN GOVERNANCE PILLARS (Carlos Suarez, Microsoft): CA, ID Governance, Access Packages
  (time-bound permission grants), ID Protection, Network Controls, Sign-in & Audit Logs,
  Consent & Sign-in
- Access Packages: time-bound permissions for agents. CA = real-time access decisions,
  Access Packages = permission lifecycle governance
- Frontier programme: M365 admin center → Copilot → Settings → User access → Copilot Frontier
- Copilot Studio auto-assignment of Agent Identities (Preview): Power Platform creates Blueprint
  and Blueprint Principal automatically
- Foundry auto-provisioning: first agent in project creates default Blueprint + Agent Identity;
  publishing creates dedicated Blueprint + Agent Identity per agent
- Azure App Service / Azure Functions: can use Entra Agent Identity Platform

═══════════════════════════════════════════════════════════════
AGENT 365
═══════════════════════════════════════════════════════════════
- GA May 1 2026, $15/user/month standalone, included in M365 E7 ($99/user/month)
- Announced Microsoft Ignite November 2025; "Frontier Firms" terminology
- Platform-agnostic: Copilot Studio, Foundry, LangChain, OpenAI SDK, Claude Code SDK,
  Bedrock, Vertex AI, n8n, and all major enterprise partners
- Agent Tooling Gateway (ATG): real-time blocking on tool execution path ONLY —
  does NOT inspect model reasoning between tool calls. 1-second timeout.
- Work IQ: intelligence layer grounding agents in org knowledge; sensitivity labels enforced
  at grounding layer; announced AI Tour Paris March 2026
- Partner ecosystem: Adobe, SAP, ServiceNow, Workday, Databricks, NVIDIA, Glean, n8n,
  Cognition, Genspark, Kasisto, Manus + open source (LangChain, OpenAI, Anthropic, Crew.ai,
  Cursor, Perplexity, Vercel)
- Registry: M365 admin center → Agents → All agents
- Roles: AI Administrator, AI Reader
- Agent 365 Portal: admin.cloud.microsoft; three tabs: Overview, All agents, Registry
- Agent 365 for Exchange Online: new built-in agent (URLs still 404ing — not yet published)
- SDK + CLI for blueprint-based agent creation
- Security Store: GA March 31 2026, embedded in Purview + Entra

═══════════════════════════════════════════════════════════════
DETECTION, KQL & SENTINEL
═══════════════════════════════════════════════════════════════
- AIAgentsInfo table: all agent types, all platforms. Key columns: AIAgentId, AIAgentName,
  AgentStatus, UserAuthenticationType, OwnerAccountUpns, RegistrySource, RawAgentInfo
- Playbook 01 KQL: no-auth agents, ownerless agents, maker credentials, auth-type change
  detection, A365 agents with no instructions, MCP tools, non-HTTPS endpoints,
  agent model inventory with EUDB status (extract modelNameHint from RawAgentInfo)
- CloudAppEvents table (Defender Advanced Hunting): M365 Copilot + Security Copilot audit.
  Key ActionTypes: UpdateCopilotAgent, CopilotInteraction, CopilotForSecurityTrigger, DLPRuleMatch
  PREREQUISITE: Settings → Cloud Apps → App connectors → M365 → "M365 activities" checkbox
  METADATA ONLY: no prompt or response content
- Copilot Data Connector for Sentinel (Public Preview Feb 3 2026):
  CopilotActivity table, 21 record types from Purview UAL.
  Single-tenant only. Content Hub install. Global/Security Admin required.
  Record types include: CopilotInteraction (261), TeamCopilotInteraction (334),
  Microsoft365CopilotScheduledPrompt (363), OutlookCopilotAutomation (371),
  CopilotForSecurityTrigger (389), CopilotAgentManagement (390), plus plugin/workspace/
  promptbook lifecycle (310–324), UpdateCopilotSettings (325)
- Sentinel Analytics Rule: auth-type change → high-severity Incident
- Sentinel MCP Entity Analyzer: GA April 2026
- Sentinel Data Federation via Fabric: Preview
- Sentinel Playbook Generator (natural language): Preview
- Sentinel Custom Graphs via Fabric: Preview
- Sentinel GDAP + unified RBAC (cross-tenant): Preview — MSSP/partner scenarios
- Copilot Data Connector: single-tenant only (MSSP limitation)
- "Defender for AI" = umbrella term covering Defender for Cloud Apps (CloudAppEvents),
  Security for AI portal (AIAgentsInfo + ATG), Defender for Cloud AI Workloads (Foundry)

═══════════════════════════════════════════════════════════════
DATA SECURITY (PURVIEW)
═══════════════════════════════════════════════════════════════
- Purview DLP for M365 Copilot GA March 31 2026: blocks PII, credit card, custom SITs in
  prompts and web grounding. Exact policy name: "Default DLP policy — Protect sensitive
  M365 Copilot interactions". Two separate policies required (label-blocking + SIT cannot combine)
- Incident CW1226324: Copilot background indexing bypassed DLP for Outlook Drafts/Sent Items
- SAM (SharePoint Advanced Management): included with M365 Copilot. RCD for interim protection.
- DSPM for AI: activity explorer, sensitivity label insights, unethical behaviour detection
- IRM Adaptive Protection: auto-enrols risky users into stricter DLP
- Communication Compliance policy: "DSPM for AI — Unethical behavior in AI apps"
- IRM policy filter: PolicyCategory eq 'ApplicableToAI'
- DLP three layers: policy (M365), browser (Edge for Business), network (Global Secure Access)
- Purview Audit required: AiCopilotQuery, AiCopilotResponse event types
- Retention: Azure pay-as-you-go cost risk
- Purview embedded in Copilot Control System: GA April 2026 (unified data risk in M365 admin center)

═══════════════════════════════════════════════════════════════
RUNTIME & NETWORK PROTECTION
═══════════════════════════════════════════════════════════════
- ATG (Agent Tooling Gateway): tool execution path only, 1-second timeout, dual-admin setup
- Secure Web and AI Gateway for Agents (Preview): Global Secure Access network controls
  extended to Copilot Studio agent outbound traffic. Covers HTTP Node, Custom connectors,
  MCP Server Connector. Configure in Power Platform Admin Center.
- Defender Predictive Shielding (Preview): dynamically adjusts identity and access policies
  during active attacks. Announced RSAC 2026.
- Entra Internet Access: Shadow AI Detection GA March 31 2026, Prompt Injection Protection
  GA March 31 2026
- Prompt Shields: direct and indirect injection detection
- Defender for Cloud AI Workloads: Azure AI Foundry protection

═══════════════════════════════════════════════════════════════
THREATS
═══════════════════════════════════════════════════════════════
- 8 threat scenarios including CW1226324
- Prompt injection, XPIA, maker credential blast radius, A2A propagation
- ClawHavoc: supply chain attack at RSAC 2026, 1,184 malicious skills, 36.8% of ClawHub
  skills have security flaws. First confirmed AI agent supply chain attack.
- Double agents framing (Vasu Jakkal, RSAC 2026)
- ATG limitation: tool path only, reasoning layer not inspected
- Copilot Studio auto security scan: warns on No Auth, Maker credentials, Org-wide share
  (advisory only, not a hard block)
- Agent Runtime Protection Status column: Protected / Needs review / Unknown per agent

═══════════════════════════════════════════════════════════════
FRAMEWORKS & STRATEGY
═══════════════════════════════════════════════════════════════
- NIST AI RMF, ISO 42001, OWASP Agentic AI Top 10, ZT4AI reference architecture
- OWASP LLM Top 10 (2025): LLM01–LLM10 mapped to Microsoft AI agent controls
- ZT4AI: three principles applied to AI, three-stage maturity model (Visibility/Control/Automation),
  workshop + assessment tool (AI pillar summer 2026), patterns and practices articles (RSAC 2026)
- EU AI Act August 2026, Colorado AI Act June 2026
- Purview Compliance Manager AI templates
- Eight-pillar defense strategy page: Visibility, Identity, Data, Endpoints/Cloud,
  Zero Trust for AI, Agents in Security Workflows, Agentic SIEM, Technical/Governance Partners
- Frontier Firms: Microsoft's term for AI-native enterprises (RSAC 2026, Vasu Jakkal)
- PyRIT (Python Risk Identification Tool): open source, MIT, 53+ datasets, 70+ converters,
  6 attack strategies, 20+ scorers, CI/CD release gate, OWASP LLM mapping.
  Playbook 06 covers pre-deployment red teaming workflow.
  Two risk surfaces: security vulnerabilities AND responsible AI harms.
- ARA tool: M365 Copilot Automated Readiness Assessment (open source, Jan 2026)

═══════════════════════════════════════════════════════════════
PRODUCTS COVERED (do not flag these as new)
═══════════════════════════════════════════════════════════════
Agent 365, Entra Agent ID, CA for Agent ID, ID Protection for Agents,
Security Dashboard for AI (GA, ai.security.microsoft.com), ATG, Secure Web and AI Gateway,
Defender for Cloud Apps RT protection, CloudAppEvents, Copilot Data Connector (CopilotActivity),
Sentinel MCP Entity Analyzer, Sentinel Data Federation, Sentinel Playbook Generator,
Sentinel Custom Graphs, Sentinel GDAP + RBAC, Prompt Shields, DSPM for AI,
Purview DLP for Copilot, Browser DLP (Edge for Business), Network DLP (Global Secure Access),
SAM + RCD, IRM Adaptive Protection, Purview Compliance Manager, Purview Audit,
Defender Predictive Shielding, Entra Internet Access (Shadow AI + Prompt Injection GA),
Entra Backup and Recovery (Preview), Entra Tenant Governance (Preview),
Unified Identity Security Dashboard (Preview), Identity Risk Score (Preview),
Agent Governance Toolkit (open source), PyRIT (open source), ARA tool (open source),
Security Copilot (E5/E7 included), Security Analyst Agent, Security Alert Triage Agent,
CA Optimization Agent, Data Security Posture Agent, Data Security Triage Agent,
Security Store (GA March 31 2026), Defender Experts Suite, Work IQ
"""

ANALYSIS_PROMPT = """You are analysing Microsoft Learn documentation search results to identify
content that is NEW or SIGNIFICANTLY UPDATED compared to what the site aiagentsecurity.guide
already covers.

Here is what the site already covers in detail:

{digest}

Today's search results from Microsoft Learn (each entry includes the REAL URL returned by
the Microsoft Learn MCP server — use these URLs exactly as provided):

{results}

Your task:
1. Identify any findings that are GENUINELY NEW — not already covered on the site
2. For each finding, assess whether it is relevant to the site's focus:
   Microsoft AI security, AI agent security, Copilot security, Entra Agent ID,
   Defender for AI, DLP for AI, MCP security
3. Ignore minor wording changes, navigation updates, or content already on the site
4. Focus on: new capabilities, GA announcements, new caveats, architectural changes,
   new KQL/PowerShell, new products, new gaps

CRITICAL URL RULES — failure to follow these rules produces wrong URLs that waste review time:
- The "url" field in each finding MUST be copied VERBATIM from the "url" field in the search
  results provided above. The MCP server returns real URLs — use them.
- NEVER construct, guess, or infer a URL from a document title or feature name.
  Microsoft Learn URL slugs do NOT follow predictable patterns.
  Example of what NOT to do: seeing "AIAgentsInfo table" and guessing
  "advanced-hunting-aiagentstable" — the real URL is "advanced-hunting-aiagentsinfo-table".
- If a search result has no URL, set "url" to "" (empty string). Do not fabricate one.
- If you are uncertain about a URL, set it to "" rather than guess.

Return a JSON object with this exact structure:
{{
  "has_findings": true/false,
  "summary": "1-2 sentence summary of what was found",
  "findings": [
    {{
      "title": "Short descriptive title",
      "url": "URL copied verbatim from search results — never constructed",
      "what_is_new": "What specifically is new or changed",
      "site_pages_affected": ["identity.html", "agent365.html"],
      "priority": "high/medium/low",
      "suggested_action": "What to add or update on the site"
    }}
  ],
  "no_findings_reason": "Only populated if has_findings is false — why nothing was found"
}}

Return ONLY the JSON object. No preamble, no markdown fences.
"""

# ── MCP Client ────────────────────────────────────────────────────────────────

async def search_learn(session: ClientSession, query: str, max_results: int = 5) -> list[dict]:
    """Search Microsoft Learn docs via MCP."""
    try:
        result = await session.call_tool(
            "microsoft_docs_search",
            arguments={"query": query, "top": max_results},
        )
        if result and result.content:
            for block in result.content:
                if hasattr(block, "text"):
                    text = block.text.strip()
                    # Try JSON parse first
                    try:
                        data = json.loads(text)
                        if isinstance(data, list):
                            return data
                        if isinstance(data, dict):
                            for key in ("results", "value", "items", "documents"):
                                if key in data and isinstance(data[key], list):
                                    return data[key]
                            return [data]
                    except json.JSONDecodeError:
                        pass
                    # Plain text — split into chunks if multiple results
                    return [{"title": query, "content": text, "url": "", "raw": text}]
    except Exception as e:
        print(f"  Search error for '{query}': {e}", file=sys.stderr)
    return []


async def fetch_article(session: ClientSession, url: str) -> str:
    """Fetch full article content via MCP."""
    try:
        result = await session.call_tool(
            "microsoft_docs_fetch",
            arguments={"url": url},
        )
        if result and result.content:
            for block in result.content:
                if hasattr(block, "text"):
                    return block.text[:3000]  # cap per article
    except Exception as e:
        print(f"  Fetch error for '{url}': {e}", file=sys.stderr)
    return ""


# ── Analysis ──────────────────────────────────────────────────────────────────

def analyse_with_claude(all_results: list[dict]) -> dict:
    """Send results to Claude for gap analysis against site knowledge."""
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    # Trim results to avoid huge context — fewer results but with full content
    results_text = json.dumps(all_results[:20], indent=2, ensure_ascii=False)
    if len(results_text) > 80_000:
        results_text = results_text[:80_000] + "\n... (truncated)"

    prompt = ANALYSIS_PROMPT.format(
        digest=SITE_KNOWLEDGE_DIGEST,
        results=results_text,
    )

    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = response.content[0].text.strip()
    # Strip markdown fences if present
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1].rsplit("```", 1)[0].strip()

    return json.loads(raw)


# ── GitHub Issue ──────────────────────────────────────────────────────────────

def create_github_issue(analysis: dict, search_date: str) -> Optional[str]:
    """Create a GitHub Issue with the findings."""
    token = os.environ.get("GITHUB_TOKEN")
    repo  = os.environ.get("GITHUB_REPO")

    if not token or not repo:
        print("Missing GITHUB_TOKEN or GITHUB_REPO — skipping Issue creation")
        return None

    findings = analysis.get("findings", [])
    high = [f for f in findings if f.get("priority") == "high"]
    med  = [f for f in findings if f.get("priority") == "medium"]
    low  = [f for f in findings if f.get("priority") == "low"]

    # Build issue body
    body_lines = [
        f"## AI Security Content Monitor — {search_date}",
        "",
        f"**Summary:** {analysis.get('summary', 'No summary provided')}",
        "",
        f"Found **{len(findings)} potential updates** "
        f"({len(high)} high · {len(med)} medium · {len(low)} low priority)",
        "",
        "---",
        "",
    ]

    for priority, items in [("🔴 High priority", high), ("🟡 Medium priority", med), ("🟢 Low priority", low)]:
        if not items:
            continue
        body_lines.append(f"### {priority}")
        body_lines.append("")
        for f in items:
            body_lines.append(f"#### {f.get('title', 'Untitled')}")
            if f.get("url"):
                body_lines.append(f"**Source:** {f['url']}")
            body_lines.append(f"**What's new:** {f.get('what_is_new', '')}")
            pages = f.get("site_pages_affected", [])
            if pages:
                body_lines.append(f"**Pages to update:** {', '.join(pages)}")
            body_lines.append(f"**Suggested action:** {f.get('suggested_action', '')}")
            body_lines.append("")

    body_lines += [
        "---",
        "",
        "**Next step:** Review each finding above and bring relevant links to your Claude session "
        "using the standard content update workflow.",
        "",
        f"*Generated by content_monitor.py on {search_date}*",
    ]

    # Label based on priority
    labels = ["content-update"]
    if high:
        labels.append("priority:high")

    payload = {
        "title": f"📡 AI Security content monitor — {search_date} ({len(findings)} findings)",
        "body": "\n".join(body_lines),
        "labels": labels,
    }

    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    url = f"https://api.github.com/repos/{repo}/issues"
    resp = httpx.post(url, json=payload, headers=headers, timeout=30)

    if resp.status_code == 201:
        issue_url = resp.json()["html_url"]
        print(f"✓ Issue created: {issue_url}")
        return issue_url
    else:
        print(f"✗ Failed to create issue: {resp.status_code} {resp.text}", file=sys.stderr)
        return None


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    today = date.today().isoformat()
    dry_run = os.environ.get("DRY_RUN", "").lower() == "true"

    print(f"AI Security content monitor — {today}")
    print(f"MCP server: {LEARN_MCP_URL}")
    print(f"Queries: {len(SEARCH_QUERIES)}")
    print(f"Dry run: {dry_run}")
    print()

    all_results: list[dict] = []
    seen_keys: set[str] = set()

    # Connect to Microsoft Learn MCP server
    async with streamablehttp_client(LEARN_MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Discover available tools
            tools = await session.list_tools()
            tool_names = [t.name for t in tools.tools]
            print(f"Available tools: {tool_names}")
            print()

            for i, query in enumerate(SEARCH_QUERIES):
                print(f"Searching: {query}")
                results = await search_learn(session, query, max_results=5)

                # Debug: show raw format on first query
                if i == 0 and results:
                    print(f"  [debug] First result keys: {list(results[0].keys()) if isinstance(results[0], dict) else type(results[0])}")
                    sample = results[0]
                    if isinstance(sample, dict):
                        for k, v in sample.items():
                            preview = str(v)[:80].replace('\n', ' ')
                            print(f"    {k}: {preview}")

                new_count = 0
                for item in results:
                    if not isinstance(item, dict):
                        item = {"content": str(item)}

                    # Build a dedup key from url or title or content snippet
                    url   = item.get("url", item.get("link", item.get("href", "")))
                    title = item.get("title", item.get("name", ""))
                    content = item.get("content", item.get("description", item.get("text", item.get("raw", ""))))

                    dedup_key = url or title or content[:100]
                    if not dedup_key or dedup_key in seen_keys:
                        continue

                    seen_keys.add(dedup_key)

                    # Fetch full article content if we have a URL — gives Claude real
                    # content and confirms the URL is valid (no 404s passed to analysis)
                    full_content = ""
                    if url and url.startswith("https://learn.microsoft.com"):
                        full_content = await fetch_article(session, url)
                        if not full_content:
                            # URL returned no content — skip rather than pass a dud URL
                            print(f"    ⚠ No content fetched for {url} — skipping")
                            continue

                    all_results.append({
                        "query": query,
                        "title": title,
                        "url": url,  # Real URL from MCP search result — never constructed
                        "description": str(content)[:300],
                        "full_content": full_content[:1500] if full_content else str(content)[:500],
                    })
                    new_count += 1

                print(f"  → {len(results)} results ({new_count} new, {len(all_results)} total unique)")
                await asyncio.sleep(0.5)  # polite rate limiting

    print(f"\nTotal unique articles found: {len(all_results)}")
    print("Analysing with Claude...")

    if not all_results:
        print("No results found — nothing to analyse.")
        return

    # Claude gap analysis
    try:
        analysis = analyse_with_claude(all_results)
    except (json.JSONDecodeError, KeyError) as e:
        print(f"Failed to parse Claude response: {e}", file=sys.stderr)
        sys.exit(1)

    has_findings = analysis.get("has_findings", False)
    findings = analysis.get("findings", [])

    print(f"\nAnalysis complete — has_findings: {has_findings}, count: {len(findings)}")

    if not has_findings:
        print(f"No new content found: {analysis.get('no_findings_reason', '')}")
        return

    # Print summary
    print(f"\nSummary: {analysis.get('summary', '')}")
    for f in findings:
        priority = f.get("priority", "?").upper()
        print(f"  [{priority}] {f.get('title', '')}")
        print(f"         Pages: {', '.join(f.get('site_pages_affected', []))}")
        print(f"         URL: {f.get('url', '')}")

    if dry_run:
        print("\nDRY RUN — skipping Issue creation. Full analysis:")
        print(json.dumps(analysis, indent=2))
        return

    # Create GitHub Issue
    create_github_issue(analysis, today)


if __name__ == "__main__":
    asyncio.run(main())
