"""研判卡生成引擎（Codex 方向评审：判断与克制）。

从研究资产 / 漏洞 / 热搜变化中生成「研判卡 decision card」，
每张卡回答 5 个问题：
1. 发生了什么变化？（change_text）
2. 为什么值得看？（why_worth）
3. 证据证明了什么、没证明什么？（evidence_says / evidence_limits）
4. 建议下一步？是否需要授权？（next_step）
5. 什么条件出现时应放弃？（abort_condition）

排序：确定性打分（新颖性/严重性/证据质量/可行动性/去重），
弃权：证据不足的 topic 只进待复核队列，不进简报/告警。
"""
import json
import logging
import time

logger = logging.getLogger("Analyst")

# 证据层级（Codex L0-L3）
EVIDENCE_LEVEL_NAMES = {
    0: "L0 测绘观测",
    1: "L1 HTTP 指纹复核",
    2: "L2 版本+漏洞条件匹配",
    3: "L3 授权内非破坏性验证",
}

SEVERITY_WEIGHT = {"CRITICAL": 100, "HIGH": 60, "MEDIUM": 30, "LOW": 10}
DEFAULT_ABORT = "证据被推翻、样本消失、或连续 N 天无新变化后自动放弃"


def _score(severity: str, evidence_level: int, asset_count: int, is_new: bool,
           has_sk: bool, has_api: bool) -> float:
    """确定性打分（不用 LLM 凭空提高置信度）"""
    s = SEVERITY_WEIGHT.get((severity or "MEDIUM").upper(), 30)
    score = s
    score += evidence_level * 15            # 证据越实越高
    score += min(asset_count, 100) * 0.2    # 暴露面越大越高
    if is_new:
        score += 10                          # 新颖性
    if has_sk:
        score += 50                          # SK 实锤
    if has_api:
        score += 15                          # API 暴露面
    return round(score, 1)


def build_card(topic: str, *, severity: str = "MEDIUM", evidence_level: int = 0,
               asset_count: int = 0, is_new: bool = False, has_sk: bool = False,
               has_api: bool = False, source: str = "", fofa_query: str = "",
               change_text: str = "", why_worth: str = "", evidence_says: str = "",
               evidence_limits: str = "", next_step: str = "", abort_condition: str = "",
               card_type: str = "component", confidence: str = "medium",
               payload: dict = None) -> dict:
    """构造一张研判卡（调用方提供事实性字段，本函数只做汇总与打分）"""
    score = _score(severity, evidence_level, asset_count, is_new, has_sk, has_api)
    card = {
        "topic": topic,
        "card_type": card_type,
        "severity": (severity or "MEDIUM").upper(),
        "confidence": confidence,
        "evidence_level": evidence_level,
        "evidence_level_name": EVIDENCE_LEVEL_NAMES.get(evidence_level, ""),
        "asset_count": asset_count,
        "source": source,
        "fofa_query": fofa_query,
        "change_text": change_text or f"{topic} 公网暴露面观测到变化",
        "why_worth": why_worth or f"{topic} 进入关注范围，需确认是否值得继续研究",
        "evidence_says": evidence_says or "基于测绘与指纹数据观测到部署情况",
        "evidence_limits": evidence_limits or "仅版本/指纹匹配，未经授权验证，不能确认可利用",
        "next_step": next_step or "查看资产详情 → 复核 FOFA 语法 → 决定是否深入",
        "abort_condition": abort_condition or DEFAULT_ABORT,
        "score": score,
        "dedup_key": f"{topic}|{card_type}",
        "payload": payload or {},
    }
    return card


def insufficient_evidence_card(topic: str, *, source: str = "", fofa_query: str = "") -> dict:
    """证据不足的 topic → 弃权卡（只进待复核队列，不进简报）"""
    card = build_card(
        topic,
        severity="LOW", evidence_level=0, asset_count=0,
        confidence="low", source=source, fofa_query=fofa_query,
        change_text=f"{topic} 出现候选信号但证据不足",
        why_worth="暂不进入简报；仅作为待复核线索保留",
        evidence_says="仅有来源标记，无独立指纹/版本证据",
        evidence_limits="证据不足，无法判断真实性",
        next_step="放入待复核队列，等待更多证据或人工确认",
        abort_condition="无新证据持续 N 天则丢弃",
        card_type="insufficient",
    )
    card["dedup_key"] = f"insufficient|{topic}"
    return card
