# Software Chian（供应链 · API 安全情报系统）

基于网络空间测绘数据，发现公网暴露的热门开源组件与 API 风险，产出可每日消费的情报简报与可复核结论。

> **产品白皮书（推荐阅读）**：[docs/WHITEPAPER.md](./docs/WHITEPAPER.md)

## 我们在做什么

- **发现**：FOFA 等测绘 + 热搜驱动，限量深挖热门组件/项目
- **分析**：指纹与多组件识别、漏洞（疑似/已复验）、API 与密钥泄露
- **交付**：研判简报、专项报告、带证据的告警——而不只是资产大表

**架构原则**：安全大脑负责思考与指挥，多个执行引擎负责探测与回传证据。

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

## 文档

| 文档 | 说明 |
|------|------|
| [产品白皮书](./docs/WHITEPAPER.md) | 定位、用户、架构、能力、可信度与路线图 |
| [持续反馈](./docs/FEEDBACK_2026-08-13.md) | Dashboard 与功能改进意见 |
| [设计草稿](./docs/design/) | UI/流程示意 |

## 技术栈

Flask + Gunicorn + 数据存储 + Nginx（详见部署与运行配置）

## 部署

见 `deploy/supply-chain-analyzer.service`（systemd）

## 安全与合规

本项目仅限**授权目标**的安全评估与合法安全研究。禁止未授权扫描与攻击。凭据类信息默认脱敏，完整访问需鉴权。

## License / 协作

通过 GitHub Issues 讨论产品方向与实现优先级。愿景服从可交付的情报闭环。
