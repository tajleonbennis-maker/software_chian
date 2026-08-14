# Changelog

本文件记录 **CyberStroll**（仓库 `software_chian`）对用户可见的进展。  
格式参考 [Keep a Changelog](https://keepachangelog.com/)，版本遵循研究预览语义。

---

## [Unreleased]

### Planned

- 每日情报简报稳定推送（Telegram / Webhook）
- 组件专项报告导出（一页纸）
- 可复核证据包（来源 / 时间 / 置信度 / FOFA 语法）
- README 演示截图与公开可访问的脱敏案例页

---

## [0.1.0-research] — 2026-08-14

Research Preview 基线：文档与产品叙事对齐，研究链路可运行。

### Added

- 产品白皮书 [`docs/WHITEPAPER.md`](./docs/WHITEPAPER.md)
- 仓库维护规范 [`docs/MAINTENANCE.md`](./docs/MAINTENANCE.md)
- 贡献说明 [`CONTRIBUTING.md`](./CONTRIBUTING.md)
- Issue 模板（缺陷 / 需求 / 安全研究）
- 品牌化 README（CyberStroll）

### Research & platform (runtime)

- 安全大脑 + 多执行引擎调度模型
- FOFA 风格测绘发现与热搜驱动研究队列
- 资产指纹、漏洞匹配、API 遍历、凭据（SK）检测（脱敏入库）
- Dashboard / 研究资产库（实验运营）
- 责任披露样例：DeepTutor `GET /api/v1/settings` 未认证目录泄露分析（[Issue #11](https://github.com/tajleonbennis-maker/software_chian/issues/11)）

### Security posture

- 对外材料强制密钥脱敏
- 明确「疑似 / 已复验」口径与禁止夸大全网结论

### Known limitations

- 主交付物「每日简报」仍在建设，Dashboard 仍是主要工作台
- 仓库目录名历史拼写 `software_chian` 尚未重命名
- 完整对外安装体验与多租户不在本版本范围

---

## 版本说明

| 标签 | 含义 |
|------|------|
| `0.x.y-research` | 研究预览，接口与数据模型可能变化 |
| `Unreleased` | 已决定做、尚未打标签 |
