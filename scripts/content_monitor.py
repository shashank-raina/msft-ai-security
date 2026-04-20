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
SEARCH_QUERIES = [
    "Entra Agent ID security",
    "Agent 365 governance security",
    "Copilot Studio authentication security",
    "Microsoft Defender AI agents",
    "AIAgentsInfo Advanced Hunting",
    "Conditional Access AI agents",
    "DLP Microsoft 365 Copilot",
    "SharePoint Advanced Management Copilot",
    "Microsoft Foundry security logging",
    "MCP security model context protocol",
    "Copilot Studio maker credentials",
    "Agent Tooling Gateway ATG",
    "Entra Agent ID blueprint federated",
    "AI security posture management DSPM",
    "Purview Compliance Manager AI",
]

# What the site already covers — used by Claude to identify genuinely new content
SITE_KNOWLEDGE_DIGEST = """
The site aiagentsecurity.guide covers these Microsoft AI security topics in depth:

IDENTITY & AGENTS:
- Entra Agent ID: Blueprint model, T1/T2 auth flow, FIC vs secrets/certs, four object types
  (Blueprint, Blueprint Principal, Agent Identity, Agent User)
- Classic vs Modern agents distinction — most existing agents are Classic with zero Entra coverage
- Five Copilot Studio auth patterns (OBO, Maker credentials, App Reg Delegated,
  App Reg Application, Agent User Account)
- CA for Agents: applies to Foundry + Microsoft-built Security Copilot agents ONLY —
  NOT Copilot Studio (this is a critical correctness point)
- Orphaned Agent Identities after Blueprint deletion
- Owner vs Sponsor model
- Registry convergence: Agent 365 (M365 admin center) for all agents,
  Entra admin center for identity governance only
- Roles: AI Reader, AI Administrator (Agent 365), Agent ID Administrator (Entra)
- RegistrySource column: "A365" vs "PowerPlatform"

AGENT 365:
- GA May 1 2026, $15/user/month standalone, $99/user/month E7 bundle
- Platform-agnostic: Copilot Studio, Foundry, LangChain, OpenAI SDK, Claude Code SDK,
  Bedrock, Vertex AI
- Agent Tooling Gateway (ATG): real-time protection on tool execution path only —
  does NOT inspect model reasoning between tool calls
- Frontier programme: adoption.microsoft.com/copilot/frontier-program
- Agent 365 SDK for custom agent instrumentation

DETECTION & KQL:
- AIAgentsInfo table (Defender Advanced Hunting) — now covers all agent types
- Key queries: no-auth agents, ownerless agents, maker credentials, change detection,
  A365 agents with no instructions, MCP tools, non-HTTPS endpoints
- Sentinel Analytics Rule for auth-type change detection
- Graph API scripts for Modern agent Owner/Sponsor check
- Portal: Settings > Security for AI (rolling out, prev: Settings > Cloud Apps > AI Agents)

DATA SECURITY:
- DLP for M365 Copilot: label-blocking now applies to Word/Excel/PowerPoint ALL storage
  locations (rolling out April-May 2026, triggered by incident CW1226324)
- Three DLP layers: policy (M365), browser (Edge for Business), network (Global Secure Access)
- SharePoint Advanced Management (SAM): included with Copilot licence, RCD for interim protection
- DSPM for AI: preview
- IRM Adaptive Protection for AI: auto-enrol risky users into stricter DLP

THREATS:
- 8 threat scenarios including CW1226324 (Copilot background indexing bypasses DLP)
- Prompt injection, XPIA, maker credential blast radius
- ATG limitation: tool path only, no reasoning inspection

FRAMEWORKS:
- NIST AI RMF, ISO 42001, OWASP Agentic AI Top 10, ZT4AI
- EU AI Act August 2026, Colorado AI Act June 2026
- Purview Compliance Manager AI assessment templates

PRODUCTS COVERED:
Agent 365, Entra Agent ID, CA for Agents, ID Protection for Agents, Security Dashboard for AI,
Defender for Cloud Apps RT protection, Prompt Shields, DSPM for AI, Purview DLP for Copilot,
Browser DLP (Edge for Business), Network DLP (Global Secure Access), SAM, IRM Adaptive Protection,
Purview Compliance Manager, Agent Governance Toolkit (open source), Sentinel MCP Entity Analyzer
"""

ANALYSIS_PROMPT = """You are analysing Microsoft Learn documentation search results to identify
content that is NEW or SIGNIFICANTLY UPDATED compared to what the site aiagentsecurity.guide
already covers.

Here is what the site already covers in detail:

{digest}

Today's search results from Microsoft Learn:

{results}

Your task:
1. Identify any findings that are GENUINELY NEW — not already covered on the site
2. For each finding, assess whether it is relevant to the site's focus:
   Microsoft AI security, AI agent security, Copilot security, Entra Agent ID,
   Defender for AI, DLP for AI, MCP security
3. Ignore minor wording changes, navigation updates, or content already on the site
4. Focus on: new capabilities, GA announcements, new caveats, architectural changes,
   new KQL/PowerShell, new products, new gaps

Return a JSON object with this exact structure:
{{
  "has_findings": true/false,
  "summary": "1-2 sentence summary of what was found",
  "findings": [
    {{
      "title": "Short descriptive title",
      "url": "https://learn.microsoft.com/...",
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

def analyse_with_claude(raw_results: list[dict]) -> dict:
    """Send results to Claude for gap analysis against site knowledge."""
    client = anthropic.Anthropic(api_key=os.environ["ANTHROPIC_API_KEY"])

    # Trim results to avoid huge context
    results_text = json.dumps(raw_results[:30], indent=2, ensure_ascii=False)
    if len(results_text) > 60_000:
        results_text = results_text[:60_000] + "\n... (truncated)"

    prompt = ANALYSIS_PROMPT.format(
        digest=SITE_KNOWLEDGE_DIGEST,
        results=results_text,
    )

    response = client.messages.create(
        model="claude-opus-4-5",
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
                    all_results.append({
                        "query": query,
                        "title": title,
                        "url": url,
                        "description": str(content)[:500],
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
