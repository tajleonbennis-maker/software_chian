"""
AI 安全分析器 - 使用 DeepSeek API 对分析结果进行智能安全分析

功能：
1. 综合安全态势分析 - 对所有资产的安全状况进行整体评估
2. 攻击链推断 - 分析漏洞组合可能形成的攻击路径
3. 智能修复建议 - 基于AI的修复优先级排序和建议
4. 资产风险评估 - 对每个资产进行AI增强的风险评估

DeepSeek API 兼容 OpenAI 接口格式：
    POST {base_url}/v1/chat/completions
    Headers: Authorization: Bearer <key>, Content-Type: application/json
    Body: {"model": "deepseek-chat",
           "messages": [{"role": "system", "content": "..."},
                        {"role": "user", "content": "..."}],
           "max_tokens": 2000, "temperature": 0.3}

注意：
    - AI 分析仅用于防御性安全研究，prompt 设计遵循负责任披露原则
    - 未配置 API Key 时自动禁用，不影响基础功能
    - 完善的错误处理：超时、网络异常、JSON 解析失败等
"""
import json
import logging
import time
import re
import requests
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field

logger = logging.getLogger("AIAnalyzer")


@dataclass
class AIAnalysisResult:
    """AI 分析结果

    封装 DeepSeek 返回的智能安全分析结果，所有字段均提供默认值，
    便于在 API 返回不完整时优雅降级。
    """
    overall_assessment: str = ""        # 总体安全评估（2-3 段文本）
    attack_chains: List[Dict] = None    # 推断的攻击链列表
    remediation_plan: List[Dict] = None # AI 修复建议（按优先级排序）
    risk_insights: str = ""             # 风险洞察（1-2 段文本）
    key_findings: List[str] = None      # 关键发现列表
    recommendations: List[str] = None   # 总体建议列表

    def to_dict(self) -> Dict[str, Any]:
        """序列化为可 JSON 化的字典（供前端渲染）"""
        return {
            "overall_assessment": self.overall_assessment,
            "attack_chains": self.attack_chains or [],
            "remediation_plan": self.remediation_plan or [],
            "risk_insights": self.risk_insights,
            "key_findings": self.key_findings or [],
            "recommendations": self.recommendations or [],
        }


class AIAnalyzer:
    """AI 安全分析器

    通过 DeepSeek API（兼容 OpenAI 格式）对供应链安全分析结果
    进行深度智能分析，包括攻击链推断、修复优先级排序等。

    用法：
        analyzer = AIAnalyzer(api_key="sk-xxx")
        if analyzer.enabled:
            result = analyzer.analyze(final_results)
    """

    # DeepSeek API 端点路径（兼容 OpenAI 格式）
    API_PATH = "/v1/chat/completions"

    # API 调用失败时的最大重试次数（不含首次调用）
    MAX_RETRIES = 2

    # 重试之间的基础等待时间（秒），实际等待 = BASE_RETRY_DELAY * (attempt+1)
    BASE_RETRY_DELAY = 1.5

    def __init__(self, api_key: str, base_url: str = "https://api.deepseek.com",
                 model: str = "deepseek-chat", timeout: int = 60):
        """初始化 AI 分析器

        Args:
            api_key: DeepSeek API 密钥
            base_url: API 基础 URL，默认为官方地址
            model: 使用的模型名称，默认 deepseek-chat
            timeout: 单次 API 请求超时时间（秒）
        """
        self.api_key = api_key
        # 去除末尾多余的斜杠，避免拼接出双斜杠 URL
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        # 仅当提供了 API Key 时才认为分析器可用
        self.enabled = bool(api_key)

    # ============================================================
    # 核心 API 调用
    # ============================================================

    def _call_api(self, system_prompt: str, user_content: str,
                  max_tokens: int = 2000) -> str:
        """调用 DeepSeek API（兼容 OpenAI 格式）

        Args:
            system_prompt: 系统提示词，定义 AI 的角色和输出约束
            user_content: 用户消息内容（即分析任务的具体输入）
            max_tokens: 最大输出 token 数

        Returns:
            AI 返回的文本内容

        Raises:
            RuntimeError: API 调用失败（含重试耗尽、认证失败、网络错误等）
        """
        url = self.base_url + self.API_PATH
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            # 较低的温度值保证安全分析输出的稳定性和可重复性
            "temperature": 0.3,
            "max_tokens": max_tokens,
            # 倾向于确定性的输出，降低采样随机性
            "top_p": 0.9,
        }

        last_error: Optional[str] = None
        # 总共尝试 MAX_RETRIES + 1 次（首次 + 重试）
        for attempt in range(self.MAX_RETRIES + 1):
            try:
                logger.debug("调用 DeepSeek API (attempt=%d/%d, model=%s)",
                             attempt + 1, self.MAX_RETRIES + 1, self.model)
                resp = requests.post(
                    url, headers=headers, json=payload,
                    timeout=self.timeout,
                )

                # 401/403 通常是认证或权限问题，重试无意义
                if resp.status_code in (401, 403):
                    raise RuntimeError(
                        f"DeepSeek API 认证失败 (HTTP {resp.status_code})，请检查 API Key 配置"
                    )

                # 429 限流：等待后重试
                if resp.status_code == 429:
                    last_error = f"API 限流 (HTTP 429)"
                    if attempt < self.MAX_RETRIES:
                        wait = self.BASE_RETRY_DELAY * (attempt + 1)
                        logger.warning("DeepSeek API 限流，%.1f 秒后重试", wait)
                        time.sleep(wait)
                        continue
                    break

                # 5xx 服务端错误：重试
                if resp.status_code >= 500:
                    last_error = f"DeepSeek 服务端错误 (HTTP {resp.status_code})"
                    if attempt < self.MAX_RETRIES:
                        wait = self.BASE_RETRY_DELAY * (attempt + 1)
                        logger.warning("%s，%.1f 秒后重试", last_error, wait)
                        time.sleep(wait)
                        continue
                    break

                # 其他 4xx 错误：不重试
                if not resp.ok:
                    # 尝试从响应体提取错误描述
                    try:
                        err_body = resp.json()
                        err_msg = err_body.get("error", {}).get("message", resp.text[:200])
                    except Exception:
                        err_msg = resp.text[:200]
                    raise RuntimeError(
                        f"DeepSeek API 请求失败 (HTTP {resp.status_code}): {err_msg}"
                    )

                # 解析成功响应
                data = resp.json()
                # 兼容 OpenAI 响应结构：choices[0].message.content
                choices = data.get("choices") or []
                if not choices:
                    raise RuntimeError("DeepSeek API 返回空 choices")
                content = choices[0].get("message", {}).get("content", "")
                finish_reason = choices[0].get("finish_reason", "")
                # 推理模型：content 为空但 finish_reason=length → reasoning 吃满 token，
                # 自动放大 max_tokens 重试一次（仅一次）
                if not content and finish_reason == "length" and max_tokens < 8000:
                    logger.warning("AI 返回 content 为空（reasoning 占满 max_tokens=%d），放大重试", max_tokens)
                    max_tokens = min(max_tokens * 4, 8000)
                    if attempt < self.MAX_RETRIES:
                        continue
                if not content:
                    raise RuntimeError("DeepSeek API 返回空 content")
                return content.strip()

            except requests.Timeout:
                last_error = f"DeepSeek API 请求超时（{self.timeout}s）"
                logger.warning(last_error)
                if attempt < self.MAX_RETRIES:
                    time.sleep(self.BASE_RETRY_DELAY * (attempt + 1))
                    continue
                break
            except requests.ConnectionError as e:
                last_error = f"DeepSeek API 网络连接错误: {e}"
                logger.warning(last_error)
                if attempt < self.MAX_RETRIES:
                    time.sleep(self.BASE_RETRY_DELAY * (attempt + 1))
                    continue
                break
            except RuntimeError:
                # 认证类错误直接抛出，不重试
                raise
            except Exception as e:
                last_error = f"DeepSeek API 调用异常: {e}"
                logger.warning(last_error, exc_info=True)
                if attempt < self.MAX_RETRIES:
                    time.sleep(self.BASE_RETRY_DELAY * (attempt + 1))
                    continue
                break

        # 所有重试均失败
        raise RuntimeError(last_error or "DeepSeek API 调用失败")

    # ============================================================
    # JSON 解析（容错）
    # ============================================================

    @staticmethod
    def _extract_json(text: str) -> Dict[str, Any]:
        """从 AI 返回的文本中提取 JSON 对象

        AI 返回的内容可能包含：
        - 纯 JSON
        - 包裹在 ```json ... ``` 代码块中的 JSON
        - 前后带有解释性文字的 JSON

        本方法尝试多种策略提取并解析 JSON，失败时抛出 ValueError。

        Args:
            text: AI 返回的原始文本

        Returns:
            解析后的字典

        Raises:
            ValueError: 无法从文本中提取有效 JSON
        """
        if not text:
            raise ValueError("AI 返回内容为空")

        # 策略 1：去除 ```json ... ``` 或 ``` ... ``` 代码块
        code_block_pattern = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
        code_block_match = code_block_pattern.search(text)
        if code_block_match:
            candidate = code_block_match.group(1).strip()
        else:
            candidate = text.strip()

        # 策略 2：直接尝试解析
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass

        # 策略 3：提取第一个 { ... } 块（贪婪匹配最外层花括号）
        first_brace = candidate.find("{")
        last_brace = candidate.rfind("}")
        if first_brace != -1 and last_brace != -1 and last_brace > first_brace:
            json_str = candidate[first_brace:last_brace + 1]
            try:
                return json.loads(json_str)
            except json.JSONDecodeError:
                pass

        raise ValueError(f"无法从 AI 返回内容中解析 JSON，原始内容前 200 字符: {text[:200]}")

    # ============================================================
    # Prompt 构建
    # ============================================================

    def _build_system_prompt(self) -> str:
        """构建系统提示词

        定义 AI 的角色、任务边界、输出格式约束。
        强调防御性分析，避免生成攻击指导内容。
        """
        return (
            "你是一名资深的软件供应链安全分析专家，专注于防御性安全研究和风险评估。"
            "你的任务是对软件供应链安全分析平台的扫描结果进行深度分析，"
            "帮助安全团队理解整体安全态势、识别潜在的攻击路径、制定修复优先级。\n\n"
            "【重要约束】\n"
            "1. 你的分析仅用于防御目的，不得提供具体的攻击代码或入侵操作步骤；\n"
            "2. 攻击链分析应聚焦于风险路径的识别和防御视角，而非攻击实现；\n"
            "3. 修复建议应具体可执行，包含优先级、影响组件、修复原因和工作量评估；\n"
            "4. 所有输出使用简体中文；\n"
            "5. 必须严格按照指定的 JSON 格式输出，不要在 JSON 之外添加额外说明文字。\n\n"
            "【输出 JSON 格式】\n"
            "{\n"
            "  \"overall_assessment\": \"总体安全评估，2-3 段文本，描述整体安全态势、主要风险点和潜在影响\",\n"
            "  \"attack_chains\": [\n"
            "    {\n"
            "      \"chain\": \"攻击链名称/路径描述，例如: Log4Shell RCE -> 权限提升 -> 横向移动\",\n"
            "      \"severity\": \"严重等级: CRITICAL / HIGH / MEDIUM / LOW\",\n"
            "      \"description\": \"该攻击链的详细说明，从防御视角解释风险形成机制\",\n"
            "      \"affected_assets\": [\"受影响的资产 URL 列表\"]\n"
            "    }\n"
            "  ],\n"
            "  \"remediation_plan\": [\n"
            "    {\n"
            "      \"priority\": \"优先级: P0(立即) / P1(高) / P2(中) / P3(低)\",\n"
            "      \"action\": \"具体的修复动作描述\",\n"
            "      \"component\": \"受影响的组件或资产\",\n"
            "      \"reason\": \"修复原因，关联具体漏洞或风险\",\n"
            "      \"effort\": \"工作量评估: low / medium / high\"\n"
            "    }\n"
            "  ],\n"
            "  \"risk_insights\": \"风险洞察，1-2 段文本，分析漏洞分布特征、供应链风险集中点、潜在趋势\",\n"
            "  \"key_findings\": [\"关键发现 1\", \"关键发现 2\", \"...\"],\n"
            "  \"recommendations\": [\"总体建议 1\", \"总体建议 2\", \"...\"]\n"
            "}\n"
        )

    def _build_overall_prompt(self, results: Dict[str, Any]) -> str:
        """构建总体分析的 prompt

        将完整的分析结果（汇总统计 + 资产列表）压缩成结构化文本，
        控制 token 数量在合理范围内，避免超出模型上下文限制。

        Args:
            results: 完整分析结果，包含 summary 和 assets

        Returns:
            用户消息内容字符串
        """
        summary = results.get("summary", {})
        assets = results.get("assets", [])

        # 构建汇总统计文本
        summary_text = (
            f"- 资产总数: {summary.get('total_assets', 0)}\n"
            f"- 检测技术总数: {summary.get('total_technologies', 0)}\n"
            f"- 漏洞总数: {summary.get('total_vulnerabilities', 0)}\n"
            f"- 利用方式总数: {summary.get('total_exploits', 0)}\n"
            f"- API 端点总数: {summary.get('total_api_endpoints', 0)}\n"
            f"- 严重等级分布: {summary.get('severity_distribution', {})}\n"
            f"- 风险评分: {summary.get('risk_score', 0)}/100\n"
            f"- 整体风险等级: {summary.get('risk_level', 'INFO')}\n"
        )

        # 构建资产详情文本（为控制 token，每个资产只保留关键信息）
        # 同时为攻击链推断收集漏洞与资产 URL 的映射关系
        asset_lines: List[str] = []
        vuln_records: List[Dict[str, Any]] = []  # 用于攻击链分析的漏洞记录
        # 限制单次分析的资产数量，避免 prompt 过长
        max_assets = 30
        for idx, ar in enumerate(assets[:max_assets]):
            asset = ar.get("asset", {})
            url = asset.get("url") or asset.get("host") or f"资产{idx+1}"
            title = asset.get("title", "")
            risk_level = ar.get("risk_level", "INFO")
            techs = ar.get("technologies", [])
            vulns = ar.get("vulnerabilities", [])
            exploits = ar.get("exploits", [])
            api_endpoints = ar.get("api_endpoints", [])

            # 技术栈摘要（最多 5 个）
            tech_names = []
            for t in techs[:5]:
                name = t.get("name", "")
                ver = t.get("version", "")
                tech_names.append(f"{name}{(' '+ver) if ver else ''}")

            # 漏洞摘要（最多 8 个）
            vuln_names = []
            for v in vulns[:8]:
                cve = v.get("cve_id", "")
                sev = v.get("severity", "")
                comp = v.get("component", "")
                title_v = v.get("title", "")
                vuln_names.append(f"{cve}({sev})[{comp}]: {title_v}")
                # 收集漏洞记录用于攻击链推断
                vuln_records.append({
                    "cve": cve,
                    "severity": sev,
                    "component": comp,
                    "title": title_v,
                    "asset_url": url,
                })

            # 利用方式摘要
            exploit_names = []
            for e in exploits[:3]:
                exploit_names.append(f"{e.get('cve_id', '')}[{e.get('difficulty', '')}]")

            # API 端点摘要
            api_summary = ""
            if api_endpoints:
                api_risks = [ep.get("risk_level", "info") for ep in api_endpoints[:5]]
                api_summary = f"API端点{len(api_endpoints)}个(风险:{','.join(api_risks)})"

            line = (
                f"资产[{idx+1}] URL: {url}\n"
                f"  标题: {title} | 风险等级: {risk_level}\n"
                f"  技术栈: {', '.join(tech_names) if tech_names else '无'}\n"
                f"  漏洞({len(vulns)}): {'; '.join(vuln_names) if vuln_names else '无'}\n"
                f"  利用方式: {', '.join(exploit_names) if exploit_names else '无'}\n"
                f"  {api_summary}"
            )
            asset_lines.append(line)

        assets_text = "\n\n".join(asset_lines)
        if len(assets) > max_assets:
            assets_text += f"\n\n(注: 共 {len(assets)} 个资产，受篇幅限制仅展示前 {max_assets} 个的详细信息)"

        # 漏洞清单（用于攻击链推断的明确输入）
        vuln_list_text = ""
        if vuln_records:
            vuln_list_lines = []
            for vr in vuln_records:
                vuln_list_lines.append(
                    f"- {vr['cve']} | {vr['severity']} | {vr['component']} | {vr['title']} | 影响: {vr['asset_url']}"
                )
            vuln_list_text = "\n".join(vuln_list_lines)

        prompt = (
            "请基于以下软件供应链安全分析平台的扫描结果，进行深度安全分析。\n\n"
            "【汇总统计】\n"
            f"{summary_text}\n\n"
            "【资产详情】\n"
            f"{assets_text}\n\n"
        )
        if vuln_list_text:
            prompt += (
                "【漏洞清单】（用于攻击链推断）\n"
                f"{vuln_list_text}\n\n"
            )
        prompt += (
            "【分析要求】\n"
            "1. overall_assessment: 综合评估整体安全态势，指出最紧迫的风险；\n"
            "2. attack_chains: 分析哪些漏洞可能组合形成攻击路径（如 RCE + 权限提升 + 横向移动），"
            "从防御视角描述每条链的风险机制和受影响资产；\n"
            "3. remediation_plan: 按优先级 P0/P1/P2/P3 排序的修复计划，"
            "P0 为最紧急（如可被远程利用的 RCE），给出具体修复动作、组件、原因和工作量；\n"
            "4. risk_insights: 分析漏洞分布特征、供应链风险集中点；\n"
            "5. key_findings: 列出 3-6 个关键发现；\n"
            "6. recommendations: 列出 3-6 条总体改进建议。\n\n"
            "请严格按指定 JSON 格式输出，不要输出 JSON 以外的内容。"
        )
        return prompt

    def _build_asset_prompt(self, asset_result: Dict[str, Any]) -> str:
        """构建单个资产分析的 prompt

        Args:
            asset_result: 单个资产的完整分析结果

        Returns:
            用户消息内容字符串
        """
        asset = asset_result.get("asset", {})
        url = asset.get("url") or asset.get("host") or "未知资产"
        title = asset.get("title", "")
        server = asset.get("server", "")
        risk_level = asset_result.get("risk_level", "INFO")
        techs = asset_result.get("technologies", [])
        vulns = asset_result.get("vulnerabilities", [])
        exploits = asset_result.get("exploits", [])
        api_endpoints = asset_result.get("api_endpoints", [])

        # 技术栈
        tech_lines = []
        for t in techs:
            ver = t.get("version", "")
            tech_lines.append(
                f"- {t.get('name', '')}{(' '+ver) if ver else ''} | "
                f"分类: {t.get('category', '')} | 厂商: {t.get('vendor', '')} | "
                f"供应链: {t.get('supply_chain', '')}"
            )
        tech_text = "\n".join(tech_lines) if tech_lines else "无"

        # 漏洞
        vuln_lines = []
        for v in vulns:
            vuln_lines.append(
                f"- {v.get('cve_id', '')} | {v.get('severity', '')} | CVSS {v.get('cvss_score', 0)} | "
                f"组件: {v.get('component', '')} | 已装版本: {v.get('installed_version', '')} | "
                f"受影响版本: {v.get('affected_versions', '')}\n"
                f"  标题: {v.get('title', '')}\n"
                f"  描述: {v.get('description', '')}"
            )
        vuln_text = "\n".join(vuln_lines) if vuln_lines else "无"

        # 利用方式
        exploit_lines = []
        for e in exploits:
            exploit_lines.append(
                f"- {e.get('cve_id', '')} | 难度: {e.get('difficulty', '')} | "
                f"入口: {e.get('exploit_entry', '')}"
            )
        exploit_text = "\n".join(exploit_lines) if exploit_lines else "无"

        # API 端点
        api_lines = []
        for ep in api_endpoints:
            issues = ep.get("security_issues", [])
            api_lines.append(
                f"- {ep.get('method', '')} {ep.get('url', '')} | 风险: {ep.get('risk_level', '')}"
                + (f" | 问题: {'; '.join(issues)}" if issues else "")
            )
        api_text = "\n".join(api_lines) if api_lines else "未扫描或无端点"

        prompt = (
            "请对以下单个资产进行 AI 增强的安全风险评估，从防御视角给出专业判断。\n\n"
            f"【资产信息】\n"
            f"URL: {url}\n"
            f"标题: {title}\n"
            f"Server: {server}\n"
            f"风险等级: {risk_level}\n\n"
            f"【技术栈】\n{tech_text}\n\n"
            f"【漏洞列表】\n{vuln_text}\n\n"
            f"【利用方式】\n{exploit_text}\n\n"
            f"【API 端点】\n{api_text}\n\n"
            "【输出要求】请严格按以下 JSON 格式输出，不要输出 JSON 以外内容：\n"
            "{\n"
            "  \"ai_assessment\": \"对该资产安全状况的综合评估（1-2 段），"
            "指出主要风险和潜在影响\",\n"
            "  \"ai_risk_factors\": \"风险因素分析，描述导致该资产风险升高的具体因素组合\",\n"
            "  \"ai_recommendation\": \"针对该资产的修复和加固建议（1 段），按重要性排序\"\n"
            "}\n"
        )
        return prompt

    # ============================================================
    # 公共分析方法
    # ============================================================

    def analyze(self, analysis_results: Dict[str, Any]) -> AIAnalysisResult:
        """对完整分析结果进行 AI 深度分析

        Args:
            analysis_results: 完整的分析结果，包含 summary 和 assets 列表

        Returns:
            AIAnalysisResult 对象

        Raises:
            RuntimeError: API 调用或解析失败
        """
        if not self.enabled:
            raise RuntimeError("AI 分析器未启用（缺少 DEEPSEEK_API_KEY）")

        # 边界情况：无资产
        summary = analysis_results.get("summary", {})
        assets = analysis_results.get("assets", [])
        if not assets:
            return AIAnalysisResult(
                overall_assessment="本次分析未发现任何资产，无法进行 AI 深度分析。",
                key_findings=["未获取到资产数据"],
                recommendations=["请检查查询条件后重新分析"],
            )

        # 边界情况：无漏洞且无 API 端点
        total_vulns = summary.get("total_vulnerabilities", 0)
        total_api = summary.get("total_api_endpoints", 0)
        if total_vulns == 0 and total_api == 0:
            return AIAnalysisResult(
                overall_assessment=(
                    f"本次共分析 {summary.get('total_assets', 0)} 个资产，"
                    "未发现已知漏洞和 API 安全问题。整体安全状况良好，"
                    "建议继续保持安全基线管理，定期复测以应对新披露的漏洞。"
                ),
                key_findings=["未发现已知漏洞", "未发现 API 安全问题"],
                recommendations=[
                    "持续关注所使用组件的安全公告",
                    "建立定期的供应链安全复测机制",
                ],
            )

        # 调用 AI
        system_prompt = self._build_system_prompt()
        user_content = self._build_overall_prompt(analysis_results)
        # 资产较多时适当增大 max_tokens
        max_tokens = 3000 if len(assets) > 10 else 2000
        raw = self._call_api(system_prompt, user_content, max_tokens=max_tokens)

        # 解析结果
        try:
            data = self._extract_json(raw)
        except ValueError as e:
            logger.error("解析 AI 返回 JSON 失败: %s", e)
            logger.debug("AI 原始返回: %s", raw[:500])
            raise RuntimeError(f"AI 返回内容解析失败: {e}")

        # 字段提取与规范化（容错处理）
        result = AIAnalysisResult(
            overall_assessment=self._ensure_str(data.get("overall_assessment")),
            attack_chains=self._normalize_attack_chains(data.get("attack_chains")),
            remediation_plan=self._normalize_remediation_plan(data.get("remediation_plan")),
            risk_insights=self._ensure_str(data.get("risk_insights")),
            key_findings=self._normalize_str_list(data.get("key_findings")),
            recommendations=self._normalize_str_list(data.get("recommendations")),
        )

        # 对修复计划按优先级排序（P0 > P1 > P2 > P3）
        result.remediation_plan = self._sort_remediation_plan(result.remediation_plan)

        logger.info("AI 分析完成: 攻击链 %d 条, 修复项 %d 个",
                    len(result.attack_chains), len(result.remediation_plan))
        return result

    def analyze_asset(self, asset_result: Dict[str, Any]) -> Dict[str, str]:
        """对单个资产进行 AI 增强分析

        Args:
            asset_result: 单个资产的完整分析结果

        Returns:
            {"ai_assessment": "...", "ai_risk_factors": "...", "ai_recommendation": "..."}

        Raises:
            RuntimeError: API 调用或解析失败
        """
        if not self.enabled:
            raise RuntimeError("AI 分析器未启用（缺少 DEEPSEEK_API_KEY）")

        system_prompt = self._build_system_prompt()
        user_content = self._build_asset_prompt(asset_result)
        raw = self._call_api(system_prompt, user_content, max_tokens=1200)

        try:
            data = self._extract_json(raw)
        except ValueError as e:
            logger.error("解析资产 AI 返回 JSON 失败: %s", e)
            raise RuntimeError(f"AI 返回内容解析失败: {e}")

        return {
            "ai_assessment": self._ensure_str(data.get("ai_assessment")),
            "ai_risk_factors": self._ensure_str(data.get("ai_risk_factors")),
            "ai_recommendation": self._ensure_str(data.get("ai_recommendation")),
        }

    # ============================================================
    # 数据规范化辅助方法
    # ============================================================

    @staticmethod
    def _ensure_str(value: Any) -> str:
        """确保返回字符串（None/非字符串转为空字符串或字符串形式）"""
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        # 列表/字典等情况转为 JSON 字符串
        try:
            return json.dumps(value, ensure_ascii=False)
        except Exception:
            return str(value)

    @staticmethod
    def _normalize_str_list(value: Any) -> List[str]:
        """规范化字符串列表"""
        if value is None:
            return []
        if isinstance(value, str):
            # 字符串视为单项
            return [value] if value.strip() else []
        if isinstance(value, list):
            return [str(item).strip() for item in value if item]
        return []

    @staticmethod
    def _normalize_attack_chains(value: Any) -> List[Dict]:
        """规范化攻击链列表，确保每项包含必要字段"""
        if not isinstance(value, list):
            return []
        result = []
        for item in value:
            if not isinstance(item, dict):
                continue
            chain = {
                "chain": AIAnalyzer._ensure_str(item.get("chain")) or "未命名攻击链",
                "severity": (AIAnalyzer._ensure_str(item.get("severity")) or "MEDIUM").upper(),
                "description": AIAnalyzer._ensure_str(item.get("description")),
                "affected_assets": AIAnalyzer._normalize_str_list(item.get("affected_assets")),
            }
            # 规范化严重等级
            if chain["severity"] not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                chain["severity"] = "MEDIUM"
            result.append(chain)
        return result

    @staticmethod
    def _normalize_remediation_plan(value: Any) -> List[Dict]:
        """规范化修复计划列表"""
        if not isinstance(value, list):
            return []
        result = []
        for item in value:
            if not isinstance(item, dict):
                continue
            plan = {
                "priority": (AIAnalyzer._ensure_str(item.get("priority")) or "P3").upper(),
                "action": AIAnalyzer._ensure_str(item.get("action")),
                "component": AIAnalyzer._ensure_str(item.get("component")),
                "reason": AIAnalyzer._ensure_str(item.get("reason")),
                "effort": (AIAnalyzer._ensure_str(item.get("effort")) or "medium").lower(),
            }
            # 规范化优先级
            if plan["priority"] not in ("P0", "P1", "P2", "P3"):
                plan["priority"] = "P3"
            # 规范化工作量
            if plan["effort"] not in ("low", "medium", "high"):
                plan["effort"] = "medium"
            result.append(plan)
        return result

    @staticmethod
    def _sort_remediation_plan(plan: List[Dict]) -> List[Dict]:
        """对修复计划按优先级排序（P0 最紧急）"""
        priority_order = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}
        return sorted(plan, key=lambda x: priority_order.get(x.get("priority", "P3"), 3))
