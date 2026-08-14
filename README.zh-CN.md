# CyberStroll

**测绘驱动的软件供应链 · API 安全情报系统**  
*Mapping-driven software supply-chain & API security intelligence*

[![Research Preview](https://img.shields.io/badge/status-research%20preview-orange)](./CHANGELOG.md)
[![Docs](https://img.shields.io/badge/docs-whitepaper-blue)](./docs/WHITEPAPER.md)

**语言：** [English](./README.md) · **简体中文**

> 仓库目录名仍为 `software_chian`（历史拼写）。对外品牌统一使用 **CyberStroll**。

[产品白皮书](./docs/WHITEPAPER.md) · [更新日志](./CHANGELOG.md) · [维护规范](./docs/MAINTENANCE.md) · [参与贡献](./CONTRIBUTING.md)

---

## 一句话

用网络空间测绘数据，发现公网暴露的热门开源组件与 API 风险，产出安全研究人员能**每日消费**的情报简报与**可复核**结论——而不是又一张资产大表。

## 三个问题

1. **什么暴露在外面？** 热门组件 / 项目的公网部署与版本分布  
2. **哪些有真实风险？** 指纹 → 漏洞（疑似 / 已复验）→ API → 密钥泄露  
3. **今天该看什么？** 简报、专项报告、带证据的告警  

## 架构原则

```text
安全大脑（思考 · 指挥 · 研判 · 汇报）
        │ 任务下发 / 证据回传
        ▼
执行引擎 × N（探测 · 指纹 · API · 取证）
```

- 没有任务单，引擎不主动开扫  
- 没有来源与置信度，结论不进简报  
- 没有行动建议，尽量不发告警  

详情见 [白皮书](./docs/WHITEPAPER.md) 与 Issue 基线讨论。

---

## 当前阶段（Research Preview）

| 状态 | 说明 |
|------|------|
| 阶段 | 研究预览 / 实验运营 |
| 主交付物 | 研判简报、组件专项、脱敏告警（建设中） |
| 演示 | Dashboard（需认证）：见部署环境 |
| 公开文档 | 白皮书、反馈、安全披露样例 |

本阶段优先把 **「选题 → 分析 → 可复核结论」** 跑通，而不是追求资产数字最大化。

---

## 核心能力（模块）

| 模块 | 作用 |
|------|------|
| `fofa_client` / `trend_intelligence` | 测绘发现与热搜驱动选题 |
| `tech_detector` / `supply_chain` | 组件指纹与供应链视角 |
| `vuln_checker` | 漏洞匹配（疑似 / 已复验口径） |
| `api_scanner` | API 暴露与敏感路径 |
| `research_brain` / `dispatcher` | 研究大脑选题与任务调度 |
| `notifier` | 告警推送（脱敏、去重、冷却） |
| `ai_analyzer` | 辅助研判与文案，不作为唯一真相源 |

---

## 文档索引

| 文档 | 说明 |
|------|------|
| [docs/WHITEPAPER.md](./docs/WHITEPAPER.md) | 产品定位、用户、架构、可信度、路线图 |
| [CHANGELOG.md](./CHANGELOG.md) | 版本与可见进展 |
| [docs/MAINTENANCE.md](./docs/MAINTENANCE.md) | 仓库维护节奏与协作方式 |
| [CONTRIBUTING.md](./CONTRIBUTING.md) | 如何提 Issue / 反馈 |
| [docs/FEEDBACK_2026-08-13.md](./docs/FEEDBACK_2026-08-13.md) | 早期 Dashboard 反馈 |
| [docs/design/](./docs/design/) | UI / 流程示意 |
| [README.md](./README.md) | 英文主 README |

---

## 安全研究与披露示例

我们对热门开源组件的**公网错误配置 / API 凭据暴露**做责任披露（只读观测、密钥脱敏）。  
示例跟踪： [Issue #11 DeepTutor settings 未认证泄露 LLM Key](https://github.com/tajleonbennis-maker/software_chian/issues/11)

**口径：** 疑似 ≠ 已复验；测绘样本 ≠「全网真相」。对外表述使用固定模板（见白皮书）。

---

## 快速了解（非完整安装手册）

1. 阅读 [白皮书](./docs/WHITEPAPER.md) 理解目标与边界  
2. 浏览 Issues 中的产品基线与路线讨论  
3. 本地运行依赖环境变量与部署单元（见 `.env.example`、`deploy/`）  
4. **仅对授权目标**开展探测；禁止未授权扫描  

> 完整一键安装与对外 SaaS 不在当前预览范围；欢迎先通过 Issue 交流场景。

---

## 技术栈

Python · Flask / Gunicorn · Worker 分布式执行 · Web Dashboard · 测绘与指纹流水线

---

## 安全与合规（必读）

- 仅限**合法授权**的安全评估与研究  
- 禁止未授权扫描、利用与攻击教学用途  
- 凭据默认**脱敏**展示；完整访问需鉴权与审计  
- 公开材料不提供可用密钥或利用武器化细节  

---

## 路线图（摘要）

| 优先级 | 目标 |
|--------|------|
| P0 | 每日简报闭环、告警达人、口径一致、详情可信字段 |
| P1 | 热门组件专项（如 Dify）、可复核证据包、上游责任披露 |
| P2 | 轻量 SBOM、凭据加固、状态机、可选验证层 |

---

## 联系与协作

- 产品 / 技术讨论：GitHub Issues  
- 安全披露协作：请使用 Issue 模板「Security research」并脱敏  
- 品牌：CyberStroll 安全情报分析团队  

如果你认同「情报优于资产堆叠」，欢迎 Star、提场景、挑刺。
