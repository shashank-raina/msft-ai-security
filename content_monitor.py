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
#   AgentsInfo table: learn.microsoft.com/en-us/defender-xdr/advanced-hunting-agentsinfo-table
#   (Previously AIAgentsInfo - transitioning per learn.microsoft.com/en-us/defender-xdr/advanced-hunting-schema-changes;
#    AIAgentsInfo remains accessible until July 1, 2026)
#   Copilot Data Connector: techcommunity.microsoft.com/blog/microsoftsentinelblog/...4491986
#   Agent 365 GA blog: microsoft.com/en-us/security/blog/2026/05/01/...
#   Work IQ MCP: learn.microsoft.com/en-us/microsoft-agent-365/tooling-servers-overview
#   Defender AI agent detection: learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-detection-protection
#   Defender AI agent inventory: learn.microsoft.com/en-us/defender-xdr/security-for-ai/ai-agent-inventory
#   NOTE: Microsoft Defender security-for-ai docs live under /defender-xdr/security-for-ai/ subdirectory
# ─────────────────────────────────────────────────────────────────────────────────
SEARCH_QUERIES = [

    # ── ENTRA AGENT ID ────────────────────────────────────────────────────────
    "Entra Agent ID blueprint principal authentication token",
    "Entra Agent ID federated identity credentials FIC managed identity",
    "Entra Agent ID lifecycle management sponsor owner",
    "Entra Agent ID access packages entitlement governance",
    "Entra Agent ID SDK containerized sidecar token service",
    "Conditional Access agent identity policy custom security attributes",
    "ID Protection for agents risky agents report risk detections",
    "Entra Agent ID agent user account constraints credential",
    "Entra Agent ID collections discovery policies agent registry",
    "Privileged Identity Management PIM agent admin roles",

    # ── AGENT 365 ─────────────────────────────────────────────────────────────
    "Microsoft Agent 365 control plane registry governance",
    "Agent 365 shadow AI discovery local agents OpenClaw",
    "Agent 365 templates policy bundling Entra Purview Defender",
    "Agent 365 lifecycle management ownerless agents sponsorship",
    "Agent 365 agent map visualization ecosystem",
    "Agent 365 observability telemetry SDK OpenTelemetry",
    "Windows 365 for Agents Cloud PC execution environment",
    "Agent 365 registry sync AWS Bedrock Google Cloud multicloud",
    "Agent 365 three agent operating modes delegated autonomous team",
    "Agent 365 software development company partners ecosystem",

    # ── COPILOT STUDIO ────────────────────────────────────────────────────────
    "Copilot Studio authentication patterns OAuth delegated",
    "Copilot Studio maker credentials application permissions security",
    "Copilot Studio automatic security scan secure defaults publishing",
    "Copilot Studio agent runtime protection status maker visibility",
    "Copilot Studio multitenant mode external user authentication",
    "Copilot Studio real-time protection Defender integration",

    # ── MICROSOFT DEFENDER FOR AI ─────────────────────────────────────────────
    "Defender XDR detect block investigate AI agent threats security-for-ai",
    "Defender AI agent threat detection real-time protection ATG",
    "Defender AI agent inventory posture assessment discovery",
    "AgentsInfo Advanced Hunting table schema agent inventory",
    "AlertEvidence Advanced Hunting AI agent investigation",
    "Defender AI security posture management ASPM multicloud",
    "Defender Copilot Studio integration Cloud Apps AI agent",
    "Defender for Cloud AI workloads Foundry threat protection",

    # ── MICROSOFT SENTINEL ────────────────────────────────────────────────────
    "Microsoft Sentinel Copilot data connector CopilotActivity table",
    "Sentinel analytic rules Copilot jailbreak plugin tampering",
    "Sentinel MCP entity analyzer AI agent investigation",
    "Sentinel data federation Fabric cross-tenant investigation",
    "Sentinel playbook generator natural language SOAR automation",
    "Sentinel GDAP unified RBAC cross-tenant MSSP",
    "Microsoft Copilot activity monitoring workbook Sentinel",

    # ── DATA SECURITY (PURVIEW) ───────────────────────────────────────────────
    "Purview DLP Microsoft 365 Copilot sensitivity labels prompts",
    "DSPM for AI data security posture management activity explorer",
    "Purview insider risk management adaptive protection AI agents",
    "Purview data security investigations AI incident workflow",
    "SharePoint Advanced Management restricted content discovery Copilot",
    "Purview communication compliance unethical AI behavior detection",
    "Purview audit eDiscovery AI agent compliance evidence",
    "Purview compliance manager AI baseline EU AI Act NIST",

    # ── NETWORK & RUNTIME PROTECTION ─────────────────────────────────────────
    "Entra Internet Access Global Secure Access shadow AI prompt injection",
    "Secure Web AI Gateway Copilot Studio agents network controls",
    "Agent Tooling Gateway ATG tool invocation blocking real-time",

    # ── MCP & FOUNDRY ─────────────────────────────────────────────────────────
    "Model Context Protocol MCP security governance agentic",
    "Work IQ MCP tooling servers Agent 365 catalog",
    "Foundry Control Plane evaluations red teaming content safety",
    "Foundry AI Red Teaming Agent PyRIT adversarial testing",
    "Azure AI Content Safety prompt shields guardrails agents",
    "Agent-to-Agent A2A protocol Microsoft security interoperability",

    # ── COMPLIANCE & FRAMEWORKS ───────────────────────────────────────────────
    "Zero Trust for AI ZT4AI reference architecture maturity",
    "EU AI Act compliance Microsoft Purview regulatory",
    "NIST AI Risk Management Framework ISO 42001 Microsoft",
    "OWASP LLM Top 10 agentic AI security vulnerabilities",
    "Security Copilot agentic SOC capabilities Security Store",
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
- AgentsInfo table (Preview, replaces AIAgentsInfo July 1, 2026): unified across all
  agent types and platforms. Key columns: AgentId, AgentName, Platform, PublishedStatus
  (Draft/Published), LifecycleStatus (Active/Blocked/Uninstalled/Deleted),
  ToolsAuthenticationType (dynamic), Owners (dynamic array), CreatedDateTime,
  EntraAgentId, EntraBlueprintId, McpServers, ConnectedAgents, RawAgentInfo (JSON)
- Playbook 01 KQL Step 8 (8a-8h): all A365 agents, no-instructions agents, MCP tools configured, non-HTTPS endpoints, nonstandard ports, Graph/Azure management endpoints, generative orchestration + email send (XPIA risk), hard-coded credentials regex. Plus Step 1-7: no-auth agents, ownerless agents, maker credentials, auth-type change
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
  Security for AI portal (AgentsInfo + ATG), Defender for Cloud AI Workloads (Foundry)

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
  workshop + assessment tool. AI PILLAR OF ZT ASSESSMENT NOW AVAILABLE — see
  learn.microsoft.com/entra/fundamentals/zero-trust-ai (3 common agent issues:
  auth/policy mismatch, overpermissioned access, lifecycle gaps).
- EU AI Act August 2026, Colorado AI Act June 2026
- Purview Compliance Manager AI templates + AI Baseline assessment as Phase 6 starting action
- Compliance Manager score vs structured audit-ready assessment distinction
- Six-phase defense strategy page: Discover & Inventory, Identity & Governance,
  Data Security, Runtime Protection, Monitoring & Detection, Compliance & Governance.
  Includes AI Readiness Assessment (pre-Phase-1), four AI security KPIs,
  quarterly board-level reporting pack, AI Governance Operating Model (5 forums).
- Frontier Firms: Microsoft's term for AI-native enterprises (RSAC 2026, Vasu Jakkal)
- PyRIT (Python Risk Identification Tool): open source, MIT, 53+ datasets, 70+ converters,
  6 attack strategies, 20+ scorers, CI/CD release gate, OWASP LLM mapping.
  Playbook 06 covers pre-deployment red teaming workflow.
  Two risk surfaces: security vulnerabilities AND responsible AI harms.
- ARA tool: M365 Copilot Automated Readiness Assessment (open source, Jan 2026)
- Five Copilot Studio auth patterns including Agent's User Account (5th)
- Owner / Sponsor / Approver / Orphaned role model
- Risk tier methodology H/M/L (highest match wins, not average)
- AI Trust and Safety assurance (Adelard methodology) for citizen-facing agents
- Maker awareness 30-minute brief (Playbook 07)
- Third-party agent vetting checklist (Playbook 08)

NOVEMBER 2025 WAVE — covered as of June 5, 2026:
- Microsoft Entra Agent Platform (developer-first identity platform)
- Microsoft Entra Agent Registry (third-party agent inventory)
- AI Prompt Shield (network-layer prompt injection blocking, Preview)
- Specialized roles: Agent Registry Administrator (NEW Entra built-in role)
- Microsoft Copilot Studio AI agent protection in Defender (Preview, GA June 2026)
- External threat detection for Copilot Studio (Preview Sep 4 2025, GA June 2026)
- Foundry Control Plane "Operate" pane structure (Overview/Assets/Compliance/Quota/Monitoring)
- Agent 365 Sentinel data connector (unifies Agent 365 + Foundry + Copilot)
- M365 admin center "Agents at risk" card (4 risk types)
- Purview role groups for AI: Data Security Management, Viewers, IRM Triage Agent
- Microsoft Foundry naming (formerly Azure AI Foundry)
- Custom security attributes for CA at scale
- OBO flow risk attribution detail
- Microsoft Sentinel MCP server + Windows On-device Agent Registry (ODR)
- ID Protection for agents: 5 offline risk detections, 4 actions, 90-day retention

JUNE 2026 PURVIEW WAVE — covered as of June 5, 2026:
- Purview for Local & Endpoint Agents (Preview) — GitHub Copilot CLI, Claude Code,
  OpenAI Codex, OpenClaw. DSPM + DLP + IRM at endpoint, full interaction logs.
- DLP runtime controls for Microsoft Foundry (Preview) — inline DLP at prompt
  handling, SIT detection during execution, block requests pre-execution.
- Purview insights in Foundry Control Plane (GA) — sensitive data detection,
  share of sensitive interactions, high-risk user indicators surfaced in dev workflow.
- Purview ↔ GitHub Copilot integration (Preview) — audit data streaming, repos +
  PRs + developer sessions visibility, consolidated AI activity monitoring.
- Microsoft Purview SDK for .NET (Preview) — drop-in toolkit for content inspection,
  DLP enforcement, sensitivity labelling. Activity feeds back into central Purview.

JUNE 2026 SCHEMA TRANSITION — covered as of June 5, 2026:
- AIAgentsInfo → AgentsInfo table migration (cutover July 1, 2026)
- BehaviorInfo table for real-time protection alerts (cutover July 1, 2026)
- Microsoft Agent 365 license required for Copilot Studio + Foundry agent security (July 1)
- Block rules need redefining under Settings → Security for AI → Policies (July 1)

BUILD 2026 WAVE (June 2, 2026) — covered as of June 5, 2026:
- "Claws" — skills loaded into OpenClaw runtime via ClawHub registry
- ClawHub — public skills registry. Supply chain attack vector documented by MS Threat Intel.
- OpenClaw — self-hosted agent runtime, open-source. Runs on Windows via MXC.
- Microsoft Execution Containers (MXC) SDK — Early Preview. Policy-driven execution layer
  with composable isolation. Developers declare what agent can access.
- Agent 365 + MXC native integration (Preview July 2026) — Defender + Entra + Intune
  + Purview protections via MXC.
- Native Windows + Agent 365 integration — Intune policies gate agent runtime execution.
- Defender local agent discovery (Preview June 2026) — discovers/profiles local AI agents
  on Defender-onboarded Windows devices. Maps to device+user identity. Shadow AI in M365 admin.
  5 categories: CLI agents, Desktop apps, Agentic IDEs, VS Code extensions, Claw-based agents.
  20+ specific products including Claude Code, GitHub Copilot CLI, Cursor, Windsurf, ChatGPT
  Desktop, OpenClaw, etc. Three views: inventory, exposure map, Advanced Hunting (KQL).
- Defender AI agent runtime protection (Preview June 2026) — inline prompt-injection detection
  at 3 hook points (user prompt, pre-tool call, post-tool response). 3 modes: Block/Audit/Disabled.
  Tamper-protected. Alert: "Suspicious AI prompt injection". Currently supports Claude Code +
  GitHub Copilot CLI via their published hooks frameworks. Coverage expanding.
- Defender multi-cloud agent discovery — cloud/platform agents from Copilot Studio, Foundry,
  AWS Bedrock, GCP Vertex AI also covered.
- Defender advanced hunting + exposure graph for agents (Preview coming soon)
- Defender AI model scanning (Preview) — inspect models in registries, workspaces, CI/CD
- Foundry Agent Service hosted agents (Public Preview) — instant-on per-agent sandboxes
- ASSERT — Adaptive Spec-driven Scoring for Evaluation and Regression Testing (open source)
- Agent Control Specification (ACS) — open spec for control hook points in agent loop
- Codename MDASH — Microsoft defence-side project (limited detail)
- NVIDIA OpenShell on Windows via MXC; Hermes Agent (Nous Research) integrating with both
- Claude Code GitHub Action prompt injection finding (Microsoft Threat Intel, Feb 2026)
- Malicious skills on ClawHub — documented supply chain attack pattern

═══════════════════════════════════════════════════════════════
PRODUCTS COVERED (do not flag these as new)
═══════════════════════════════════════════════════════════════
Agent 365, Entra Agent ID, CA for Agent ID, ID Protection for Agents,
Entra Agent Platform, Entra Agent Registry, AI Prompt Shield,
Security Dashboard for AI (Preview, ai.security.microsoft.com), ATG, Secure Web and AI Gateway,
Defender for Cloud Apps RT protection, CloudAppEvents, Copilot Data Connector (CopilotActivity),
Agent 365 Sentinel Data Connector (unifies Agent 365 + Foundry + Copilot),
Sentinel MCP server (hosted), Microsoft Learn MCP server, Foundry MCP integration,
Windows On-device Agent Registry (ODR), Copilot Studio MCP onboarding wizard,
Sentinel MCP Entity Analyzer, Sentinel Data Federation, Sentinel Playbook Generator,
Sentinel Custom Graphs, Sentinel GDAP + RBAC, Prompt Shields, DSPM for AI (new + classic),
Purview DLP for Copilot, Browser DLP (Edge for Business), Network DLP (Global Secure Access),
SAM + RCD, IRM Adaptive Protection, Purview Compliance Manager (incl. AI Baseline),
Purview Audit (Agent 365 activities), Defender Predictive Shielding,
Entra Internet Access (Shadow AI + Prompt Injection GA), External Threat Detection (Copilot Studio),
Entra Backup and Recovery (Preview), Entra Tenant Governance (Preview),
Unified Identity Security Dashboard (Preview), Identity Risk Score (Preview),
Agent Governance Toolkit (open source), PyRIT (open source), ARA tool (open source),
Security Copilot (E5/E7 included), Security Analyst Agent, Security Alert Triage Agent,
CA Optimization Agent, Data Security Posture Agent, Data Security Triage Agent,
Security Store (GA March 31 2026), Defender Experts Suite, Work IQ,
Microsoft Foundry (formerly Azure AI Foundry), Foundry Control Plane,
Foundry IQ knowledge integration, Foundry Red Teaming Agent,
9 Copilot Studio harm categories, 9 Foundry risk dimensions
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
  Example of what NOT to do: seeing "AgentsInfo table" and guessing
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
                    try:
                        data = json.loads(text)
                        if isinstance(data, list):
                            return data
                        if isinstance(data, dict):
                            for key in ("results", "value", "items", "documents", "hits"):
                                if key in data and isinstance(data[key], list):
                                    return data[key]
                            return [data]
                    except json.JSONDecodeError:
                        pass
                    # Plain text — return as single result
                    return [{"raw_text": text, "url": "", "title": query}]
    except Exception as e:
        print(f"  Search error for '{query}': {e}", file=sys.stderr)
    return []


def extract_fields(item: dict) -> tuple[str, str, str]:
    """Extract url, title, content from a result item regardless of field names."""
    # URL — try every known field name
    url = (item.get("url") or item.get("link") or item.get("href") or
           item.get("@id") or item.get("documentUrl") or item.get("webUrl") or
           item.get("pageUrl") or item.get("canonicalUrl") or "")

    # Title — try every known field name
    title = (item.get("title") or item.get("name") or item.get("displayText") or
             item.get("heading") or item.get("pageTitle") or item.get("label") or
             item.get("documentTitle") or "")

    # Content — try every known field name
    content = (item.get("content") or item.get("description") or item.get("text") or
               item.get("raw") or item.get("abstract") or item.get("snippet") or
               item.get("summary") or item.get("body") or item.get("raw_text") or
               item.get("excerpt") or item.get("highlights") or "")

    # If content is a dict (e.g. highlights), stringify it
    if isinstance(content, dict):
        content = str(content)

    return str(url).strip(), str(title).strip(), str(content).strip()


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

    # Trim results to avoid huge context
    results_text = json.dumps(all_results[:30], indent=2, ensure_ascii=False)
    if len(results_text) > 60_000:
        results_text = results_text[:60_000] + "\n... (truncated)"

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
                print(f"Searching ({i+1}/{len(SEARCH_QUERIES)}): {query}")
                results = await search_learn(session, query, max_results=5)

                # Always dump raw format for first query — tells us actual field names
                if i == 0:
                    print(f"  [debug] {len(results)} raw results from MCP")
                    if results:
                        first = results[0]
                        if isinstance(first, dict):
                            print(f"  [debug] Field names: {list(first.keys())}")
                            for k, v in list(first.items())[:5]:
                                print(f"  [debug]   {k!r}: {str(v)[:120]!r}")
                        else:
                            print(f"  [debug] Item type: {type(first)}, value: {str(first)[:200]!r}")

                new_count = 0
                for item in results:
                    if not isinstance(item, dict):
                        item = {"raw_text": str(item)}

                    url, title, content = extract_fields(item)

                    # Fallback: use all fields joined as content if still empty
                    if not url and not title and not content:
                        content = " ".join(str(v)[:100] for v in item.values() if v)[:300]
                        print(f"  [warn] Empty fields for item, raw keys: {list(item.keys())}")

                    dedup_key = url or title or content[:100]
                    if not dedup_key or dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)

                    all_results.append({
                        "query": query,
                        "title": title or f"[no title — query: {query}]",
                        "url": url,
                        "description": content[:500],
                    })
                    new_count += 1

                print(f"  → {new_count} new ({len(all_results)} total unique)")
                await asyncio.sleep(0.8)

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
