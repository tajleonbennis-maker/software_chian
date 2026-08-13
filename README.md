# Software Chian（供应链安全分析系统）

供应链安全分析平台：资产发现、漏洞检测、供应链风险分析。

## 功能模块（core/）
- **fofa_client** — FoFa 资产测绘
- **api_scanner** — API 扫描
- **vuln_checker** — 漏洞检测
- **exploit_finder** — 漏洞利用检索
- **ai_analyzer** — AI 分析
- **research_brain** — 研究大脑
- **ownership_discovery / exposure_discovery** — 资产归属与暴露面发现
- **tech_detector** — 技术栈识别
- **supply_chain / trend_intelligence** — 供应链与威胁情报

## 技术栈
Flask + Gunicorn + PostgreSQL 16 + Nginx

## 部署
见 `deploy/supply-chain-analyzer.service`（systemd）

> 注意：本项目仅限授权目标的安全评估使用。
