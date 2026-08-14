# CyberStroll

**Mapping-driven software supply-chain & API security intelligence**

[![Research Preview](https://img.shields.io/badge/status-research%20preview-orange)](./CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-whitepaper-blue)](./docs/WHITEPAPER.md)

**Languages:** **English** · [简体中文](./README.zh-CN.md)

> The Git repository folder is still named `software_chian` (legacy typo). The public product name is **CyberStroll**.

[Whitepaper](./docs/WHITEPAPER.md) · [Changelog](./CHANGELOG.md) · [Maintenance](./docs/MAINTENANCE.md) · [Contributing](./CONTRIBUTING.md)

---

## What it is

CyberStroll turns **cyberspace mapping data** (FOFA-style discovery, trending components, public deployments) into **actionable security intelligence**—not another giant asset table.

We help researchers answer three questions:

1. **What is exposed?** Public deployments and version spread of popular open-source components/projects  
2. **What is actually risky?** Fingerprinting → vulnerability matching (**suspected** vs **verified**) → API exposure → credential leaks  
3. **What should I look at today?** Daily briefs, component deep-dives, and evidence-backed alerts  

---

## Architecture in one diagram

```text
Security Brain (plan · judge · dispatch · report)
        │ tasks out / evidence in
        ▼
Execution engines × N (probe · fingerprint · API crawl · collect evidence)
```

**Operating rules**

- No task ticket → engines do not scan on their own  
- No source + confidence → findings do not enter the brief  
- No suggested action → avoid noisy alerts  

See the [whitepaper](./docs/WHITEPAPER.md) and project Issues for the full product constitution.

---

## Current stage: Research Preview

| Item | Status |
|------|--------|
| Stage | Research preview / experimental operations |
| Primary deliverables | Intelligence briefs, component reports, redacted alerts (in progress) |
| Console | Authenticated dashboard in the deployment environment |
| Public docs | Whitepaper, changelog, responsible-disclosure examples |

Priority is a closed loop of **topic selection → analysis → verifiable conclusions**, not maximizing raw asset counts.

---

## Core modules

| Module | Role |
|--------|------|
| `fofa_client` / `trend_intelligence` | Mapping discovery & trend-driven research queue |
| `tech_detector` / `supply_chain` | Component fingerprinting & supply-chain view |
| `vuln_checker` | Vulnerability matching (suspected / verified) |
| `api_scanner` | API exposure & sensitive path discovery |
| `research_brain` / `dispatcher` | Research planning & task dispatch |
| `notifier` | Alerts with redaction, dedup, and cooldown |
| `ai_analyzer` | Assistive analysis—**not** the sole source of truth |

---

## Documentation

| Doc | Description |
|-----|-------------|
| [docs/WHITEPAPER.md](./docs/WHITEPAPER.md) | Product positioning, users, architecture, trust model, roadmap (currently Chinese; EN planned) |
| [CHANGELOG.md](./CHANGELOG.md) | Visible progress |
| [docs/MAINTENANCE.md](./docs/MAINTENANCE.md) | How we maintain the repo |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | How to report issues & contribute |
| [docs/design/](./docs/design/) | UI / flow sketches |
| [README.zh-CN.md](./README.zh-CN.md) | Full Chinese README |

---

## Security research & disclosure

We study **public misconfigurations and credential exposure** on popular open-source stacks using **read-only** methods and **redacted** evidence.

Example tracker: [Issue #11 — DeepTutor unauthenticated `/api/v1/settings` catalog leak](https://github.com/tajleonbennis-maker/software_chian/issues/11)

**Language rules**

- *Suspected* ≠ *verified*  
- A mapping sample ≠ “the whole Internet”  
- Prefer statements like: *As of {time}, in sample set {n}, we observed …; {x} cases actively re-checked; confidence {level}.*

---

## Getting oriented (not a full install guide)

1. Read the [whitepaper](./docs/WHITEPAPER.md) for goals and non-goals  
2. Skim Issues for baseline / roadmap discussions  
3. Local run needs env config and deploy units (see `.env.example`, `deploy/`)  
4. Probe **only authorized targets**—unauthorized scanning is out of scope  

> One-click public SaaS install is **not** part of this preview. Open an Issue to discuss your use case.

---

## Stack

Python · Flask / Gunicorn · distributed workers · web dashboard · mapping & fingerprinting pipelines

---

## Security & compliance

- Lawful, **authorized** assessment and research only  
- No unauthorized scanning, exploitation, or attack tutorials  
- Credentials are **redacted by default**; full access requires auth and should be audited  
- Public materials must not include usable secrets or weaponized exploit detail  

---

## Roadmap (summary)

| Priority | Focus |
|----------|--------|
| **P0** | Daily brief loop, alerts that reach humans, consistent metrics, trustworthy detail fields |
| **P1** | Component specials (e.g. Dify), evidence packs, upstream responsible disclosure |
| **P2** | Lightweight SBOM fields, stronger secret storage, state machine, optional validation layer |

---

## Contact

- Product & engineering: GitHub Issues  
- Security reports: use the **Security research** issue template; redact secrets  
- Team: **CyberStroll Security Intelligence**  

If you believe **intelligence beats asset hoarding**, star the repo, share scenarios, and challenge our methodology.
