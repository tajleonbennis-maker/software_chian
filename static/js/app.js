/* ============================================================
   软件供应链安全分析平台 - 前端 JavaScript
   ============================================================
   功能：
   1. 模式切换（FOFA 搜索 / 手动输入）
   2. 提交分析请求
   3. 轮询分析进度
   4. 渲染分析结果（汇总卡片、表格、详情展开）
   5. 漏洞和利用方式的展示
   6. API 安全报告的渲染
   ============================================================ */

(function () {
    "use strict";

    // ============================================================
    // 全局状态
    // ============================================================
    let currentMode = "manual";     // 默认从最直接的 URL 输入开始
    let currentTaskId = null;       // 当前分析任务 ID
    let pollTimer = null;           // 轮询定时器
    let analysisResults = null;     // 最新分析结果缓存
    let publicAssets = [];           // latest persisted public inventory
    let publicRiskEvents = [];
    let activeFacet = { type: "", value: "" };
    let pollFailures = 0;            // 连续轮询失败次数
    let pollStartedAt = 0;           // 轮询开始时间

    // 登录相关状态
    let currentRole = "guest";      // 当前角色（admin/guest）
    let isLoggedIn = false;         // 是否已登录

    // ============================================================
    // DOM 元素引用
    // ============================================================
    const els = {
        // 模式切换
        tabFofa: document.getElementById("tabFofa"),
        tabManual: document.getElementById("tabManual"),
        fofaModeContent: document.getElementById("fofaModeContent"),
        manualModeContent: document.getElementById("manualModeContent"),
        // FOFA 输入
        fofaQuery: document.getElementById("fofaQuery"),
        fofaSize: document.getElementById("fofaSize"),
        fofaKey: document.getElementById("fofaKey"),
        // 手动输入
        manualUrls: document.getElementById("manualUrls"),
        // 选项
        scanApi: document.getElementById("scanApi"),
        onlineQuery: document.getElementById("onlineQuery"),
        // 按钮
        startBtn: document.getElementById("startAnalysisBtn"),
        cancelBtn: document.getElementById("cancelAnalysisBtn"),
        // 进度
        progressSection: document.getElementById("progressSection"),
        progressBar: document.getElementById("progressBar"),
        progressText: document.getElementById("progressText"),
        progressStep: document.getElementById("progressStep"),
        progressCount: document.getElementById("progressCount"),
        // 错误
        errorSection: document.getElementById("errorSection"),
        errorMessage: document.getElementById("errorMessage"),
        // 结果
        resultsSection: document.getElementById("resultsSection"),
        summaryCards: document.getElementById("summaryCards"),
        severityChart: document.getElementById("severityChart"),
        assetTableBody: document.getElementById("assetTableBody"),
        // AI 分析
        aiAnalysisPanel: document.getElementById("aiAnalysisPanel"),
        aiAnalysisContent: document.getElementById("aiAnalysisContent"),
        // FOFA 状态
        fofaStatusBadge: document.getElementById("fofaStatusBadge"),
        aiStatusBadge: document.getElementById("aiStatusBadge"),
        showcaseAssets: document.getElementById("showcaseAssets"),
        showcaseNotice: document.getElementById("showcaseNotice"),
        showcaseUpdated: document.getElementById("showcaseUpdated"),
        researchBrainStatus: document.getElementById("researchBrainStatus"),
        researchProjects: document.getElementById("researchProjects"),
        researchTrends: document.getElementById("researchTrends"),
        researchRuns: document.getElementById("researchRuns"),
        labStatus: document.getElementById("labStatus"),
        labExperiments: document.getElementById("labExperiments"),
        publicAssetSearch: document.getElementById("publicAssetSearch"),
        publicRiskFilter: document.getElementById("publicRiskFilter"),
        publicSummary: document.getElementById("publicSummary"),
        resultCount: document.getElementById("resultCount"),
        riskFacets: document.getElementById("riskFacets"),
        techFacets: document.getElementById("techFacets"),
        protocolFacets: document.getElementById("protocolFacets"),
        countryFacets: document.getElementById("countryFacets"),
    };

    // ============================================================
    // 工具函数
    // ============================================================

    /**
     * HTML 转义，防止 XSS
     */
    function escapeHtml(text) {
        if (text === null || text === undefined) return "";
        const div = document.createElement("div");
        div.textContent = String(text);
        return div.innerHTML;
    }

    /**
     * 显示/隐藏元素
     */
    function show(el) { el.classList.remove("hidden"); }
    function hide(el) { el.classList.add("hidden"); }

    /**
     * 获取严重等级对应的 CSS 类名
     */
    function severityClass(severity) {
        const s = (severity || "").toUpperCase();
        if (s === "CRITICAL") return "critical";
        if (s === "HIGH") return "high";
        if (s === "MEDIUM") return "medium";
        if (s === "LOW") return "low";
        return "info";
    }

    /**
     * 严重等级中文显示
     */
    function severityLabel(severity) {
        const s = (severity || "").toUpperCase();
        const map = {
            "CRITICAL": "严重",
            "HIGH": "高危",
            "MEDIUM": "中危",
            "LOW": "低危",
            "INFO": "信息",
        };
        return map[s] || s;
    }

    /**
     * 风险等级中文显示
     */
    function riskLevelLabel(level) {
        return severityLabel(level);
    }

    /**
     * 获取风险等级对应的颜色（用于风险评分条）
     */
    function riskScoreColor(score) {
        if (score >= 75) return "var(--severity-critical)";
        if (score >= 50) return "var(--severity-high)";
        if (score >= 25) return "var(--severity-medium)";
        return "var(--severity-low)";
    }

    async function loadShowcase() {
        try {
            const resp = await fetch("/api/showcase");
            const data = await resp.json();
            if (!resp.ok) throw new Error(data.error || "加载失败");
            publicAssets = data.assets || [];
            publicRiskEvents = data.risk_events || [];
            els.showcaseNotice.textContent = data.task_count ? `全量资产库 · 汇总 ${data.task_count} 个已完成任务 · 按 URL 去重` : "暂无已完成的扫描任务";
            els.showcaseUpdated.textContent = data.updated_at ? `更新于 ${new Date(data.updated_at * 1000).toLocaleString()}` : "";
            renderPublicSummary(data.action_summary || {}, data.summary || {});
            renderFacets();
            renderPublicAssets();
        } catch (error) {
            els.showcaseNotice.textContent = error.message;
            els.showcaseAssets.innerHTML = '<div class="card empty-state">公开成果暂时无法加载</div>';
        }
    }

    async function loadResearchOverview() {
        try {
            const resp = await fetch("/api/research/overview");
            const data = await resp.json();
            if (!resp.ok) throw new Error("加载失败");
            els.researchBrainStatus.textContent = `${data.enabled ? "持续运行" : "已暂停"} · ${escapeHtml(data.model)} · 候选资产 ${data.total_candidate_assets || 0}`;
            els.researchProjects.innerHTML = (data.projects || []).map(project => `<article class="research-project"><div><strong>${escapeHtml(project.name)}</strong><span>${escapeHtml(project.category)}</span></div><p>${escapeHtml((project.insight || {}).headline || project.rationale)}</p>${project.insight ? `<small>${escapeHtml(project.insight.summary || "")}</small>` : ""}<footer><span>候选 ${project.asset_count || 0} · 确认 ${project.analyzed_count || 0} · 排除 ${project.rejected_count || 0}</span><span>${project.last_run_at ? `最近研究 ${new Date(project.last_run_at * 1000).toLocaleString()}` : "等待首次研究"}</span></footer></article>`).join("");
            const trends = (data.trends || {}).signals || [];
            els.researchTrends.innerHTML = trends.length ? `<strong>近期趋势选题</strong><div>${trends.slice(0, 12).map(item => `<span class="trend-chip ${item.is_hot ? "hot" : ""}">${escapeHtml(item.name)}${item.momentum > 0 ? " ↑" : ""}</span>`).join("")}</div>` : '<span class="muted">等待首次趋势情报同步</span>';
            els.researchRuns.innerHTML = (data.runs || []).slice(0, 5).map(run => `<div class="research-run"><span class="run-status ${escapeHtml(run.status)}">${escapeHtml(run.status)}</span><strong>${escapeHtml(run.project_name)}</strong><span>发现 ${run.discovered_count || 0} · 新增 ${run.new_count || 0}</span><time>${new Date(run.started_at * 1000).toLocaleString()}</time></div>`).join("") || '<span class="muted">研究大脑即将开始第一轮</span>';
        } catch (error) {
            els.researchBrainStatus.textContent = "研究状态暂不可用";
        }
    }

    async function loadLabOverview() {
        try {
            const resp = await fetch("/api/lab/overview");
            const data = await resp.json();
            const online = (data.nodes || []).filter(node => node.online).length;
            els.labStatus.textContent = `${online}/${(data.nodes || []).length} 节点在线 · ${(data.experiments || []).length} 个实验`;
            els.labExperiments.innerHTML = (data.experiments || []).map(exp => `<article class="lab-experiment"><header><div><span class="lab-project">${escapeHtml(exp.project_name)} ${escapeHtml(exp.version || "")}</span><h4>${escapeHtml(exp.hypothesis)}</h4></div><span class="lab-state ${escapeHtml(exp.status)}">${escapeHtml(exp.status)}</span></header><dl><div><dt>公网观察</dt><dd>${escapeHtml(exp.public_observation || "等待关联公网证据")}</dd></div><div><dt>靶场复现</dt><dd>${escapeHtml(exp.reproduction_summary || "实验待部署")}</dd></div><div><dt>修复对比</dt><dd>${escapeHtml(exp.remediation || "等待完成复现后验证")}</dd></div></dl><footer>${escapeHtml(exp.conclusion_boundary)}</footer></article>`).join("") || '<div class="empty-state">靶场已就绪，暂无已登记实验</div>';
        } catch (error) { els.labStatus.textContent = "靶场状态暂不可用"; }
    }

    function renderPublicSummary(action, technical) {
        // 优先展示研究资产库真实统计（与 Dashboard 同源）；无研究数据时回落为公开资产统计
        const base = technical.research_assets_total > 0 ? technical : {
            total_assets: technical.total_assets,
            total_technologies: technical.total_technologies,
            total_api_endpoints: technical.total_api_endpoints,
            total_vulnerabilities: technical.total_vulnerabilities,
            identified_project_families: technical.identified_project_families,
        };
        const assetText = base.research_assets_total > 0
            ? `共 <strong>${base.research_assets_total}</strong> 条研究资产`
            : `共 <strong>${base.total_assets || 0}</strong> 条资产`;
        const vulnText = base.research_vuln_total > 0
            ? `<strong>${base.research_vuln_total}</strong> 个漏洞（高危 ${base.research_risk_critical_high || 0}）`
            : `<strong>${base.total_vulnerabilities || 0}</strong> 个漏洞`;
        els.publicSummary.innerHTML = `
            <span>${assetText} · 已分析 <strong>${base.research_assets_analyzed || 0}</strong></span>
            <span>${vulnText}</span>
            <span><strong>${action.action_assets || 0}</strong> 个风险资产</span>
            <span><strong>${base.identified_project_families || 0}</strong> 个开源项目家族</span>
            <span><strong>${base.total_technologies || 0}</strong> 个产品指纹</span>
            <span><strong>${base.total_api_endpoints || 0}</strong> 个 API 端点${base.research_api_exposed ? ` · 暴露 ${base.research_api_exposed}` : ''}</span>`;
    }

    function renderFacets() {
        const counts = (values) => Object.entries(values.reduce((acc, value) => { if (value) acc[value] = (acc[value] || 0) + 1; return acc; }, {})).sort((a,b) => b[1]-a[1]);
        const render = (container, type, entries) => {
            container.innerHTML = entries.slice(0, 10).map(([name, count]) => `<button class="facet-item" data-type="${type}" data-value="${escapeHtml(name)}"><span>${escapeHtml(name)}</span><em>${count}</em></button>`).join("") || '<span class="muted">暂无数据</span>';
        };
        render(els.riskFacets, "risk", counts(publicRiskEvents.map(e => e.event_type)));
        const projectCounts = counts(publicAssets.map(a => (a.project_family || {}).name));
        const techCounts = counts(publicAssets.flatMap(a => (a.technologies || []).map(t => t.name)));
        els.techFacets.innerHTML = projectCounts.slice(0, 10).map(([name, count]) => `<button class="facet-item project-facet" data-type="project" data-value="${escapeHtml(name)}"><span>${escapeHtml(name)}</span><em>${count}</em></button>`).join("") + techCounts.slice(0, 10).map(([name, count]) => `<button class="facet-item" data-type="tech" data-value="${escapeHtml(name)}"><span>${escapeHtml(name)}</span><em>${count}</em></button>`).join("") || '<span class="muted">暂无数据</span>';
        render(els.protocolFacets, "protocol", counts(publicAssets.map(a => (a.asset || {}).protocol)));
        render(els.countryFacets, "country", counts(publicAssets.map(a => (a.asset || {}).country || "未知")));
        document.querySelectorAll(".facet-item").forEach(button => button.addEventListener("click", () => {
            const same = activeFacet.type === button.dataset.type && activeFacet.value === button.dataset.value;
            activeFacet = same ? {type:"",value:""} : {type:button.dataset.type,value:button.dataset.value};
            document.querySelectorAll(".facet-item").forEach(item => item.classList.toggle("active", !same && item === button));
            renderPublicAssets();
        }));
    }

    function renderPublicAssets() {
        const keyword = (els.publicAssetSearch.value || "").trim().toLowerCase();
        const risk = els.publicRiskFilter.value;
        const filtered = publicAssets.filter(item => {
            if (risk && (item.risk_level || "INFO").toUpperCase() !== risk) return false;
            const asset = item.asset || {};
            if (activeFacet.type === "tech" && !(item.technologies || []).some(t => t.name === activeFacet.value)) return false;
            if (activeFacet.type === "project" && (item.project_family || {}).name !== activeFacet.value) return false;
            if (activeFacet.type === "protocol" && asset.protocol !== activeFacet.value) return false;
            if (activeFacet.type === "country" && (asset.country || "未知") !== activeFacet.value) return false;
            if (activeFacet.type === "risk") {
                const id = asset.ip || asset.url;
                if (!publicRiskEvents.some(e => (e.asset.ip || e.asset.url) === id && e.event_type === activeFacet.value)) return false;
            }
            if (!keyword) return true;
            const haystack = [asset.ip, asset.host, asset.domain, asset.url, asset.title, (item.ownership_profile || {}).site_title, asset.server, (item.project_family || {}).name,
                ...(item.technologies || []).map(t => `${t.name} ${t.version}`),
                ...(item.vulnerabilities || []).map(v => `${v.cve_id} ${v.component} ${v.title}`)
            ].join(" ").toLowerCase();
            return haystack.includes(keyword);
        });
        els.resultCount.textContent = `${filtered.length} 条结果`;
        if (!filtered.length) {
            els.showcaseAssets.innerHTML = '<div class="card empty-state">没有符合条件的资产</div>';
            return;
        }
        els.showcaseAssets.innerHTML = filtered.map((item, index) => {
            const asset = item.asset || {};
            const techs = item.technologies || [];
            const apis = item.api_endpoints || [];
            const vulns = item.vulnerabilities || [];
            const exposures = item.exposure_findings || [];
            const owner = item.ownership_profile || {};
            const project = item.project_family || null;
            const projectTag = project ? `<span class="project-family-tag">开源项目 · ${escapeHtml(project.name)}</span>` : "";
            const projectHtml = project ? `<section class="project-attribution"><h4>软件来源与部署关系</h4><dl class="ownership-grid"><div><dt>识别项目</dt><dd>${escapeHtml(project.name)}</dd></div><div><dt>上游来源</dt><dd>${escapeHtml(project.upstream)}</dd></div><div><dt>部署关系</dt><dd>${escapeHtml(project.deployment_relation)}</dd></div><div><dt>实例所有者</dt><dd>${escapeHtml(project.deployment_owner)}</dd></div><div><dt>识别置信度</dt><dd>${escapeHtml(project.confidence)}</dd></div><div><dt>识别依据</dt><dd>${escapeHtml((project.evidence || []).join("；"))}</dd></div></dl><p class="attribution-notice">${escapeHtml(project.notice)}</p></section>` : "";
            const techTags = techs.slice(0, 8).map(t => `<span class="fofa-tag">${escapeHtml(t.name)}${t.version ? ` ${escapeHtml(t.version)}` : ""}</span>`).join("") || '<span class="muted">组件未识别</span>';
            const apiRows = apis.map(api => `<tr><td><span class="api-method">${escapeHtml(api.method)}</span></td><td><code>${escapeHtml(api.url)}</code></td><td>${api.auth_required ? escapeHtml(api.auth_type || "需要认证") : "未识别认证"}</td><td><span class="severity-tag ${severityClass(api.risk_level)}">${severityLabel(api.risk_level)}</span></td></tr>`).join("") || '<tr><td colspan="4" class="empty-state">未扫描或未识别 API</td></tr>';
            const vulnItems = vulns.map(v => `<article class="showcase-vuln"><div><strong>${escapeHtml(v.cve_id)}</strong><span class="verification-tag">${escapeHtml(v.verification_status || "待核实")}</span><span class="severity-tag ${severityClass(v.severity)}">${severityLabel(v.severity)}</span></div><p>${escapeHtml(v.component)}${v.observed_version ? ` ${escapeHtml(v.observed_version)}` : " · 版本未知"} · ${escapeHtml(v.title)}</p><small>${escapeHtml(v.verification_reason || v.description)}</small></article>`).join("") || '<div class="empty-state">未匹配到已知漏洞（不代表无漏洞）</div>';
            const exposureItems = exposures.map(f => `<article class="showcase-vuln"><div><strong>${escapeHtml(f.url)}</strong><span class="severity-tag ${severityClass(f.risk_level)}">${severityLabel(f.risk_level)}</span></div><p>${escapeHtml(f.evidence)} · 来源：${escapeHtml(f.source)}</p><small>状态 ${escapeHtml(f.status_code)} · ${f.publicly_accessible ? "无需登录可达" : "未确认公开访问"}${(f.sensitive_field_types || []).length ? ` · 字段类型：${escapeHtml(f.sensitive_field_types.join("、"))}` : ""}</small></article>`).join("") || '<div class="empty-state">未执行或未发现前端敏感路由</div>';
            const credentialFindings = exposures.filter(f => f.publicly_accessible && (f.sensitive_field_types || []).some(type => ["API 密钥", "访问令牌", "密码", "私钥", "云凭据"].includes(type)));
            const credentialEvidence = credentialFindings.map(f => `<article class="redacted-evidence-card"><div class="redacted-evidence-head"><div><span class="evidence-kicker">脱敏证据预览</span><h4>提供商连接配置公开</h4></div><span class="event-status">待人工确认</span></div><div class="evidence-field"><label>配置入口</label><a href="${escapeHtml(f.url)}" target="_blank" rel="noopener">${escapeHtml(new URL(f.url).pathname)}</a></div>${(f.sensitive_field_types || []).includes("LLM 配置") ? '<div class="evidence-field"><label>提供商 / Base URL</label><div>检测到 LLM 外部服务配置 <span class="redacted-note">具体值未保存</span></div></div>' : ''}<div class="evidence-field"><label>${escapeHtml((f.sensitive_field_types || []).filter(type => type !== "LLM 配置").join(" / ") || "敏感凭据")}</label><div class="masked-secret" aria-label="凭据已脱敏">••••••••••••••••••••••••<span>未读取 · 未保存 · 未验证</span></div></div><footer><span>HTTP ${escapeHtml(f.status_code)}</span><span>无需认证可访问</span><span>来源：${escapeHtml(f.source)}</span></footer></article>`).join("");
            const ownerHtml = `<dl class="ownership-grid"><div><dt>网站标题</dt><dd>${escapeHtml(owner.site_title || asset.title || "-")}</dd></div><div><dt>组织名称</dt><dd>${escapeHtml(owner.organization || "待确认")}</dd></div><div><dt>地区</dt><dd>${escapeHtml([asset.country, asset.city].filter(Boolean).join(" / ") || "-")}</dd></div><div><dt>备案</dt><dd>${escapeHtml(owner.icp || asset.icp || "-")}</dd></div><div><dt>版权</dt><dd>${escapeHtml(owner.copyright_notice || "-")}</dd></div><div><dt>安全联系人</dt><dd>${escapeHtml((owner.security_contacts || []).join("、") || "-")}</dd></div><div><dt>公开邮箱</dt><dd>${escapeHtml((owner.public_emails || []).join("、") || "-")}</dd></div><div><dt>企业电话</dt><dd>${escapeHtml((owner.public_phones || []).join("、") || "-")}</dd></div><div><dt>归属置信度</dt><dd>${escapeHtml(owner.confidence || "low")}</dd></div></dl>`;
            return `<article class="fofa-asset-card">
                <button class="showcase-asset-summary" type="button" aria-expanded="false">
                    <div class="asset-primary"><div class="asset-ip">${escapeHtml(asset.ip || asset.host || "未知地址")}<span class="asset-port">:${escapeHtml(asset.port || (asset.protocol === "https" ? 443 : 80))}</span></div><a href="${escapeHtml(asset.url)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${escapeHtml(asset.url || asset.host)}</a><h3>${escapeHtml(asset.title || owner.site_title || "标题未识别")}</h3><div class="fofa-tags">${projectTag}${techTags}</div></div>
                    <div class="asset-side"><span class="severity-tag ${severityClass(item.risk_level)}">${severityLabel(item.risk_level)}</span><dl><div><dt>域名</dt><dd>${escapeHtml(asset.domain || asset.host || "-")}</dd></div><div><dt>地区</dt><dd>${escapeHtml([asset.country, asset.city].filter(Boolean).join(" / ") || "-")}</dd></div><div><dt>服务</dt><dd>${escapeHtml(asset.server || "-")}</dd></div></dl><div class="asset-counts"><span>${techs.length} 组件</span><span>${apis.length} API</span><span>${exposures.length} 暴露面</span><span>${vulns.length} 漏洞</span></div></div>
                </button>
                <div class="showcase-asset-detail">${credentialEvidence ? `<section class="credential-evidence-section"><h4>凭据暴露证据</h4>${credentialEvidence}</section>` : ""}<section><h4>责任主体线索（仅公开组织信息）</h4>${ownerHtml}</section><section><h4>组件指纹</h4><div class="showcase-chips">${techs.map(t => `<span class="showcase-chip"><strong>${escapeHtml(t.name)}</strong> ${escapeHtml(t.version || "版本未知")}<small>${escapeHtml(t.category || "未分类")}</small></span>`).join("")}</div></section><section><h4>API 暴露面</h4><div class="table-container"><table class="showcase-api-table"><thead><tr><th>方法</th><th>端点</th><th>认证</th><th>风险</th></tr></thead><tbody>${apiRows}</tbody></table></div></section><section><h4>前端路由与敏感页面（仅保存脱敏证据）</h4><div class="showcase-vulns">${exposureItems}</div></section><section><h4>漏洞情报</h4><div class="showcase-vulns">${vulnItems}</div></section></div>
            </article>`;
        }).join("");
        els.showcaseAssets.querySelectorAll(".showcase-asset-summary").forEach(button => button.addEventListener("click", () => {
            const card = button.closest(".fofa-asset-card");
            card.classList.toggle("expanded");
            button.setAttribute("aria-expanded", card.classList.contains("expanded"));
        }));
    }

    // ============================================================
    // FOFA 配置状态检测
    // ============================================================

    async function checkFofaConfig() {
        try {
            const resp = await fetch("/api/fofa/config");
            const data = await resp.json();
            const badge = els.fofaStatusBadge;

            if (data.fofa_key_configured) {
                badge.textContent = "资产数据源已配置";
                badge.className = "status-badge configured";
                els.fofaKey.value = "";
                els.fofaKey.placeholder = "已通过环境变量配置";
            } else {
                badge.textContent = "资产数据源未配置";
                badge.className = "status-badge not-configured";
                els.fofaKey.value = "";
                els.fofaKey.placeholder = "请输入 FOFA Key";
            }

            // 设置默认查询数量
            if (data.default_size && !els.fofaSize.value) {
                els.fofaSize.value = data.default_size;
            }
        } catch (e) {
            els.fofaStatusBadge.textContent = "资产数据源检测失败";
            els.fofaStatusBadge.className = "status-badge not-configured";
        }
    }

    // ============================================================
    // AI 配置状态检测
    // ============================================================

    async function checkAiConfig() {
        try {
            const resp = await fetch("/api/ai/config");
            const data = await resp.json();
            const badge = els.aiStatusBadge;

            if (data.ai_enabled) {
                // AI 分析已启用
                badge.textContent = `AI 已启用 (${data.model || "deepseek-chat"})`;
                badge.className = "status-badge configured";
            } else if (data.api_key_configured && !data.analysis_enabled) {
                // API Key 已配置但被全局开关关闭
                badge.textContent = "AI 已配置但被关闭";
                badge.className = "status-badge not-configured";
            } else {
                // 未配置 API Key
                badge.textContent = "AI 未配置";
                badge.className = "status-badge not-configured";
            }
        } catch (e) {
            els.aiStatusBadge.textContent = "AI 配置检测失败";
            els.aiStatusBadge.className = "status-badge not-configured";
        }
    }

    // ============================================================
    // 模式切换逻辑
    // ============================================================

    function switchMode(mode) {
        currentMode = mode;

        // 更新标签按钮状态
        if (mode === "fofa") {
            els.tabFofa.classList.add("active");
            els.tabManual.classList.remove("active");
            show(els.fofaModeContent);
            hide(els.manualModeContent);
        } else {
            els.tabManual.classList.add("active");
            els.tabFofa.classList.remove("active");
            show(els.manualModeContent);
            hide(els.fofaModeContent);
        }
    }

    // ============================================================
    // 提交分析请求
    // ============================================================

    async function startAnalysis() {
        // 禁用按钮，防止重复提交
        els.startBtn.disabled = true;
        els.startBtn.textContent = "分析中...";

        // 隐藏之前的结果和错误
        hide(els.resultsSection);
        hide(els.errorSection);
        show(els.progressSection);

        // 重置进度条
        updateProgress(0, "正在提交分析请求...", 0, 0);

        try {
            let resp;
            const scanApi = els.scanApi.checked;
            const onlineQuery = els.onlineQuery.checked;

            if (currentMode === "fofa") {
                // FOFA 搜索模式
                const query = els.fofaQuery.value.trim();
                if (!query) {
                    throw new Error("请输入资产查询语句");
                }

                resp = await fetch("/api/analyze", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        query: query,
                        fofa_key: els.fofaKey.value.trim(),
                        size: parseInt(els.fofaSize.value) || 100,
                        scan_api: scanApi,
                        online_query: onlineQuery,
                    }),
                });
            } else {
                // 手动输入模式
                const urls = els.manualUrls.value.trim();
                if (!urls) {
                    throw new Error("请输入至少一个 URL");
                }

                resp = await fetch("/api/manual", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        urls: urls,
                        scan_api: scanApi,
                        online_query: onlineQuery,
                    }),
                });
            }

            const data = await resp.json();

            if (!resp.ok) {
                throw new Error(data.error || "提交分析请求失败");
            }

            // 开始轮询进度
            currentTaskId = data.task_id;
            pollFailures = 0;
            pollStartedAt = Date.now();
            startPolling(currentTaskId);

        } catch (e) {
            showError(e.message);
            resetButton();
        }
    }

    // ============================================================
    // 轮询分析进度
    // ============================================================

    function startPolling(taskId) {
        // 清除之前的定时器
        if (pollTimer) clearInterval(pollTimer);

        // 立即查询一次
        pollStatus(taskId);

        // 每 1.5 秒轮询一次
        pollTimer = setInterval(() => pollStatus(taskId), 1500);
    }

    async function pollStatus(taskId) {
        try {
            const resp = await fetch(`/api/analyze/status/${taskId}`);
            const data = await resp.json();

            if (!resp.ok) {
                stopPolling();
                showError(data.error || "获取进度失败");
                resetButton();
                return;
            }

            pollFailures = 0;

            // 更新进度显示
            updateProgress(
                data.progress,
                data.current_step,
                data.analyzed_count,
                data.total_count
            );

            if (data.status === "completed") {
                stopPolling();
                // 获取完整结果
                await fetchResults(taskId);
                resetButton();
            } else if (data.status === "error") {
                stopPolling();
                showError(data.error || "分析过程中发生错误");
                resetButton();
            } else if (data.status === "cancelled") {
                stopPolling();
                hide(els.progressSection);
                resetButton();
                currentTaskId = null;
            }
        } catch (e) {
            pollFailures += 1;
            if (pollFailures >= 4 || Date.now() - pollStartedAt > 30 * 60 * 1000) {
                stopPolling();
                showError("无法获取分析进度。请检查服务是否仍在运行，然后重新提交任务。");
                resetButton();
            } else {
                els.progressStep.textContent = `连接中断，正在重试（${pollFailures}/4）...`;
            }
        }
    }

    async function cancelAnalysis() {
        if (!currentTaskId) return;
        els.cancelBtn.disabled = true;
        els.cancelBtn.textContent = "正在取消...";
        try {
            const resp = await fetch(`/api/analyze/cancel/${currentTaskId}`, { method: "POST" });
            const data = await resp.json();
            if (!resp.ok && resp.status !== 409) {
                throw new Error(data.error || "取消失败");
            }
            els.progressStep.textContent = resp.status === 409 ? "任务已经结束" : "正在停止分析...";
        } catch (e) {
            showError(e.message);
            stopPolling();
            resetButton();
        }
    }

    function stopPolling() {
        if (pollTimer) {
            clearInterval(pollTimer);
            pollTimer = null;
        }
    }

    // ============================================================
    // 获取并渲染分析结果
    // ============================================================

    async function fetchResults(taskId) {
        try {
            const resp = await fetch(`/api/results/${taskId}`);
            const data = await resp.json();

            if (!resp.ok && resp.status !== 202) {
                throw new Error(data.error || "获取结果失败");
            }

            if (resp.status === 202) {
                // 结果尚未就绪，稍后重试
                setTimeout(() => fetchResults(taskId), 1000);
                return;
            }

            analysisResults = data;
            renderResults(data);
            hide(els.progressSection);
            show(els.resultsSection);

            // 滚动到结果区
            els.resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });

        } catch (e) {
            showError(e.message);
        }
    }

    // ============================================================
    // 进度更新
    // ============================================================

    function updateProgress(progress, step, analyzed, total) {
        els.progressBar.style.width = progress + "%";
        els.progressText.textContent = progress + "%";
        els.progressStep.textContent = step || "正在分析...";

        if (total > 0) {
            els.progressCount.textContent = `已分析 ${analyzed} / ${total} 个资产`;
        } else {
            els.progressCount.textContent = "";
        }
    }

    // ============================================================
    // 渲染结果 - 汇总卡片
    // ============================================================

    function renderResults(data) {
        const summary = data.summary || {};
        renderSummaryCards(summary);
        // 渲染 AI 深度分析（可选，未启用时不展示面板）
        renderAIAnalysis(data.ai_analysis);
        renderSeverityChart(summary.severity_distribution || {});
        renderAssetTable(data.assets || []);
    }

    function renderSummaryCards(summary) {
        const cards = [];

        // 总资产数
        cards.push(`
            <div class="summary-card">
                <div class="summary-card-label">总资产数</div>
                <div class="summary-card-value">${summary.total_assets || 0}</div>
                <div class="summary-card-sub">已分析的目标资产</div>
            </div>
        `);

        // 发现技术数
        cards.push(`
            <div class="summary-card">
                <div class="summary-card-label">发现技术</div>
                <div class="summary-card-value accent-blue">${summary.total_technologies || 0}</div>
                <div class="summary-card-sub">检测到的技术组件</div>
            </div>
        `);

        // 漏洞数量
        cards.push(`
            <div class="summary-card">
                <div class="summary-card-label">漏洞数量</div>
                <div class="summary-card-value accent-red">${summary.total_vulnerabilities || 0}</div>
                <div class="summary-card-sub">已知安全漏洞</div>
            </div>
        `);

        // 利用方式数
        cards.push(`
            <div class="summary-card">
                <div class="summary-card-label">利用方式</div>
                <div class="summary-card-value accent-orange">${summary.total_exploits || 0}</div>
                <div class="summary-card-sub">可用的漏洞利用信息</div>
            </div>
        `);

        // API 端点数
        cards.push(`
            <div class="summary-card">
                <div class="summary-card-label">API 端点</div>
                <div class="summary-card-value">${summary.total_api_endpoints || 0}</div>
                <div class="summary-card-sub">发现的 API 端点</div>
            </div>
        `);

        // 风险评分
        const score = summary.risk_score || 0;
        const level = summary.risk_level || "INFO";
        cards.push(`
            <div class="summary-card risk-score-card">
                <div class="summary-card-label">风险评分</div>
                <div class="summary-card-value ${severityClass(level)}">${score}<span style="font-size:16px;color:var(--text-muted)">/100</span></div>
                <div class="summary-card-sub">风险等级: <span class="severity-tag ${severityClass(level)}">${riskLevelLabel(level)}</span></div>
                <div class="risk-score-bar">
                    <div class="risk-score-fill" style="width:${score}%;background-color:${riskScoreColor(score)}"></div>
                </div>
            </div>
        `);

        els.summaryCards.innerHTML = cards.join("");
    }

    // ============================================================
    // 渲染结果 - AI 深度分析
    // ============================================================

    /**
     * 渲染 AI 深度分析面板
     * 处理以下情况：
     *   - ai_analysis 为 null/undefined：隐藏面板（未启用 AI）
     *   - ai_analysis.error：展示错误信息
     *   - ai_analysis.disabled：展示未启用提示
     *   - 正常结果：渲染完整分析内容
     */
    function renderAIAnalysis(aiAnalysis) {
        // 未启用或无 AI 分析结果时隐藏面板
        if (!aiAnalysis) {
            hide(els.aiAnalysisPanel);
            return;
        }

        // AI 分析出错
        if (aiAnalysis.error) {
            els.aiAnalysisContent.innerHTML = `
                <div class="ai-error-box">
                    <div class="ai-error-title">AI 分析失败</div>
                    <div class="ai-error-message">${escapeHtml(aiAnalysis.error)}</div>
                    <div class="ai-error-hint">请检查 DEEPSEEK_API_KEY 配置、网络连接及 API 额度。</div>
                </div>
            `;
            show(els.aiAnalysisPanel);
            return;
        }

        // AI 分析被禁用
        if (aiAnalysis.disabled) {
            els.aiAnalysisContent.innerHTML = `
                <div class="ai-disabled-box">
                    <div class="ai-disabled-title">AI 分析未启用</div>
                    <div class="ai-disabled-message">${escapeHtml(aiAnalysis.reason || "未配置 DeepSeek API Key")}</div>
                    <div class="ai-disabled-hint">配置 DEEPSEEK_API_KEY 环境变量后即可启用 AI 深度安全分析（参考 .env.example）。</div>
                </div>
            `;
            show(els.aiAnalysisPanel);
            return;
        }

        // 正常渲染 AI 分析结果
        const parts = [];

        // 1. 总体评估
        if (aiAnalysis.overall_assessment) {
            parts.push(`
                <div class="ai-section">
                    <h3 class="ai-section-title">&#128221; 总体安全评估</h3>
                    <div class="ai-assessment-text">${escapeHtml(aiAnalysis.overall_assessment)}</div>
                </div>
            `);
        }

        // 2. 关键发现
        if (Array.isArray(aiAnalysis.key_findings) && aiAnalysis.key_findings.length > 0) {
            const findings = aiAnalysis.key_findings.map(f =>
                `<li class="ai-finding-item">${escapeHtml(f)}</li>`
            ).join("");
            parts.push(`
                <div class="ai-section">
                    <h3 class="ai-section-title">&#128161; 关键发现</h3>
                    <ul class="ai-findings-list">${findings}</ul>
                </div>
            `);
        }

        // 3. 攻击链分析
        if (Array.isArray(aiAnalysis.attack_chains) && aiAnalysis.attack_chains.length > 0) {
            parts.push(`
                <div class="ai-section">
                    <h3 class="ai-section-title">&#128279; 攻击链分析</h3>
                    ${renderAttackChains(aiAnalysis.attack_chains)}
                </div>
            `);
        }

        // 4. 修复计划
        if (Array.isArray(aiAnalysis.remediation_plan) && aiAnalysis.remediation_plan.length > 0) {
            parts.push(`
                <div class="ai-section">
                    <h3 class="ai-section-title">&#128737; 修复计划</h3>
                    ${renderRemediationPlan(aiAnalysis.remediation_plan)}
                </div>
            `);
        }

        // 5. 风险洞察
        if (aiAnalysis.risk_insights) {
            parts.push(`
                <div class="ai-section">
                    <h3 class="ai-section-title">&#128269; 风险洞察</h3>
                    <div class="ai-insights-text">${escapeHtml(aiAnalysis.risk_insights)}</div>
                </div>
            `);
        }

        // 6. 总体建议
        if (Array.isArray(aiAnalysis.recommendations) && aiAnalysis.recommendations.length > 0) {
            const recs = aiAnalysis.recommendations.map(r =>
                `<li class="ai-recommendation-item">${escapeHtml(r)}</li>`
            ).join("");
            parts.push(`
                <div class="ai-section">
                    <h3 class="ai-section-title">&#9989; 总体建议</h3>
                    <ul class="ai-recommendations-list">${recs}</ul>
                </div>
            `);
        }

        // 如果没有任何内容，展示空状态
        if (parts.length === 0) {
            els.aiAnalysisContent.innerHTML = `
                <div class="empty-state">AI 分析未返回有效内容</div>
            `;
        } else {
            els.aiAnalysisContent.innerHTML = parts.join("");
        }

        show(els.aiAnalysisPanel);
    }

    /**
     * 渲染攻击链卡片列表
     * @param {Array} chains 攻击链数组
     */
    function renderAttackChains(chains) {
        if (!chains || chains.length === 0) {
            return '<div class="empty-state">未识别到明显的攻击链</div>';
        }

        return chains.map((chain, idx) => {
            const severity = (chain.severity || "MEDIUM").toUpperCase();
            const sevCls = severityClass(severity);
            const sevLabel = severityLabel(severity);
            const description = chain.description || "无描述";
            const chainPath = chain.chain || "未命名攻击链";

            // 受影响资产列表
            const affectedAssets = Array.isArray(chain.affected_assets)
                ? chain.affected_assets
                : [];
            const assetsHtml = affectedAssets.length > 0
                ? `<div class="ai-chain-assets">
                       <span class="ai-chain-assets-label">受影响资产:</span>
                       ${affectedAssets.map(a => `<span class="ai-chain-asset-tag" title="${escapeHtml(a)}">${escapeHtml(a)}</span>`).join("")}
                   </div>`
                : "";

            return `
                <div class="ai-chain-card severity-${sevCls}">
                    <div class="ai-chain-header">
                        <span class="ai-chain-index">#${idx + 1}</span>
                        <span class="ai-chain-path">${escapeHtml(chainPath)}</span>
                        <span class="severity-tag ${sevCls}">${sevLabel}</span>
                    </div>
                    <div class="ai-chain-description">${escapeHtml(description)}</div>
                    ${assetsHtml}
                </div>
            `;
        }).join("");
    }

    /**
     * 渲染修复计划表格
     * @param {Array} plan 修复计划数组（已按优先级排序）
     */
    function renderRemediationPlan(plan) {
        if (!plan || plan.length === 0) {
            return '<div class="empty-state">暂无修复建议</div>';
        }

        const rows = plan.map(item => {
            const priority = (item.priority || "P3").toUpperCase();
            const effort = (item.effort || "medium").toLowerCase();
            return `
                <tr class="ai-remediation-row">
                    <td><span class="ai-priority-tag priority-${priority.toLowerCase()}">${priority}</span></td>
                    <td>${escapeHtml(item.action || "-")}</td>
                    <td>${escapeHtml(item.component || "-")}</td>
                    <td>${escapeHtml(item.reason || "-")}</td>
                    <td><span class="ai-effort-tag effort-${effort}">${effortLabel(effort)}</span></td>
                </tr>
            `;
        }).join("");

        return `
            <div class="table-container ai-remediation-table-container">
                <table class="ai-remediation-table">
                    <thead>
                        <tr>
                            <th>优先级</th>
                            <th>修复动作</th>
                            <th>组件/资产</th>
                            <th>修复原因</th>
                            <th>工作量</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;
    }

    /**
     * 工作量等级中文显示
     */
    function effortLabel(effort) {
        const e = (effort || "medium").toLowerCase();
        const map = { "low": "低", "medium": "中", "high": "高" };
        return map[e] || "中";
    }

    // ============================================================
    // 渲染结果 - 严重等级分布图
    // ============================================================

    function renderSeverityChart(dist) {
        const severities = [
            { key: "CRITICAL", label: "严重", cls: "critical" },
            { key: "HIGH", label: "高危", cls: "high" },
            { key: "MEDIUM", label: "中危", cls: "medium" },
            { key: "LOW", label: "低危", cls: "low" },
        ];

        const maxCount = Math.max(1, ...severities.map(s => dist[s.key] || 0));
        const total = severities.reduce((sum, s) => sum + (dist[s.key] || 0), 0);

        if (total === 0) {
            els.severityChart.innerHTML = '<div class="empty-state">未发现漏洞</div>';
            return;
        }

        const bars = severities.map(s => {
            const count = dist[s.key] || 0;
            const width = (count / maxCount) * 100;
            return `
                <div class="severity-bar-item">
                    <span class="severity-bar-label">${s.label}</span>
                    <div class="severity-bar-track">
                        <div class="severity-bar-fill ${s.cls}" style="width:${width}%"></div>
                    </div>
                    <span class="severity-bar-count">${count}</span>
                </div>
            `;
        }).join("");

        els.severityChart.innerHTML = bars;
    }

    // ============================================================
    // 渲染结果 - 资产列表表格
    // ============================================================

    function renderAssetTable(assets) {
        if (!assets || assets.length === 0) {
            els.assetTableBody.innerHTML = '<tr><td colspan="7" class="empty-state">未找到任何资产</td></tr>';
            return;
        }

        const rows = assets.map((assetData, index) => {
            const asset = assetData.asset || {};
            const url = asset.url || asset.host || "未知";
            const ip = asset.ip || "-";
            const title = asset.title || "-";
            const techs = assetData.technologies || [];
            const vulnCount = assetData.vuln_count || 0;
            const riskLevel = assetData.risk_level || "INFO";

            // 技术标签（最多显示 3 个）
            const techTags = techs.slice(0, 3).map(t => {
                const ver = t.version ? ` ${t.version}` : "";
                return `<span class="tech-tag">${escapeHtml(t.name)}${escapeHtml(ver)}</span>`;
            }).join("");
            const moreTechs = techs.length > 3 ? `<span class="tech-tag">+${techs.length - 3}</span>` : "";
            const techDisplay = techs.length > 0
                ? `<div class="tech-tags">${techTags}${moreTechs}</div>`
                : '<span style="color:var(--text-muted)">未检测到</span>';

            // 漏洞数量徽章
            const vulnBadge = vulnCount > 0
                ? `<span class="vuln-count-badge has-vulns">${vulnCount}</span>`
                : `<span class="vuln-count-badge no-vulns">0</span>`;

            // 风险等级标签
            const riskTag = `<span class="severity-tag ${severityClass(riskLevel)}">${riskLevelLabel(riskLevel)}</span>`;

            return `
                <tr class="asset-row" data-index="${index}">
                    <td><span class="asset-url" title="${escapeHtml(url)}">${escapeHtml(url)}</span></td>
                    <td>${escapeHtml(ip)}</td>
                    <td><span class="asset-title-cell" title="${escapeHtml(title)}">${escapeHtml(title)}</span></td>
                    <td>${techDisplay}</td>
                    <td style="text-align:center">${vulnBadge}</td>
                    <td>${riskTag}</td>
                    <td><button class="btn btn-primary btn-sm toggle-detail-btn" data-index="${index}">详情</button></td>
                </tr>
                <tr class="asset-detail-row hidden" id="detailRow${index}">
                    <td colspan="7"></td>
                </tr>
            `;
        }).join("");

        els.assetTableBody.innerHTML = rows;

        // 绑定详情展开事件
        document.querySelectorAll(".toggle-detail-btn").forEach(btn => {
            btn.addEventListener("click", function () {
                toggleAssetDetail(parseInt(this.dataset.index), this);
            });
        });
    }

    // ============================================================
    // 资产详情展开/折叠
    // ============================================================

    function toggleAssetDetail(index, btn) {
        const detailRow = document.getElementById(`detailRow${index}`);
        const assetRow = document.querySelector(`.asset-row[data-index="${index}"]`);

        if (detailRow.classList.contains("hidden")) {
            // 展开：渲染详情内容
            const assetData = analysisResults.assets[index];
            const detailContent = renderAssetDetail(assetData);
            detailRow.querySelector("td").innerHTML = detailContent;
            detailRow.classList.remove("hidden");
            assetRow.classList.add("expanded");
            btn.textContent = "收起";

            // 绑定详情内标签页切换事件
            bindDetailTabs(detailRow);
        } else {
            // 折叠
            detailRow.classList.add("hidden");
            detailRow.querySelector("td").innerHTML = "";
            assetRow.classList.remove("expanded");
            btn.textContent = "详情";
        }
    }

    // ============================================================
    // 渲染资产详情
    // ============================================================

    function renderAssetDetail(assetData) {
        const template = document.getElementById("assetDetailTemplate");
        const clone = template.content.cloneNode(true);

        // 技术栈表格
        const techTbody = clone.querySelector(".tech-tbody");
        const techs = assetData.technologies || [];
        if (techs.length === 0) {
            techTbody.innerHTML = '<tr><td colspan="5" class="empty-state">未检测到技术组件</td></tr>';
        } else {
            techTbody.innerHTML = techs.map(t => `
                <tr>
                    <td>${escapeHtml(t.name)}</td>
                    <td>${escapeHtml(t.version) || "-"}</td>
                    <td>${escapeHtml(t.category) || "-"}</td>
                    <td>${escapeHtml(t.vendor) || "-"}</td>
                    <td>${escapeHtml(t.supply_chain) || "-"}</td>
                </tr>
            `).join("");
        }

        // 供应链列表
        const supplyList = clone.querySelector(".supply-chain-list");
        const chains = assetData.supply_chains || [];
        if (chains.length === 0) {
            supplyList.innerHTML = '<div class="empty-state">未检测到供应链信息</div>';
        } else {
            supplyList.innerHTML = chains.map(sc => {
                const components = (sc.components || []).map(c => {
                    const ver = c.version ? `<span class="comp-version">${escapeHtml(c.version)}</span>` : "";
                    return `<span class="supply-chain-component">${escapeHtml(c.name)} ${ver}</span>`;
                }).join("");
                return `
                    <div class="supply-chain-item">
                        <div class="supply-chain-header">
                            <span class="supply-chain-name">${escapeHtml(sc.name)}</span>
                            <span class="supply-chain-meta">生态系统: ${escapeHtml(sc.ecosystem)} | 厂商: ${escapeHtml(sc.vendor) || "-"} | 组件: ${sc.component_count || 0}</span>
                        </div>
                        <div class="supply-chain-components">${components}</div>
                    </div>
                `;
            }).join("");
        }

        // 漏洞列表
        const vulnList = clone.querySelector(".vuln-list");
        const vulns = assetData.vulnerabilities || [];
        if (vulns.length === 0) {
            vulnList.innerHTML = '<div class="empty-state">未发现已知漏洞</div>';
        } else {
            vulnList.innerHTML = vulns.map(v => {
                const refs = (v.references || []).map(r =>
                    `<a href="${escapeHtml(r)}" target="_blank" rel="noopener">${escapeHtml(r)}</a>`
                ).join("");
                const sevCls = severityClass(v.severity);
                return `
                    <div class="vuln-item severity-${sevCls}">
                        <div class="vuln-header">
                            <span class="vuln-cve">${escapeHtml(v.cve_id)}</span>
                            <div>
                                <span class="severity-tag ${sevCls}">${severityLabel(v.severity)}</span>
                                <span class="cvss-badge ${sevCls}">CVSS ${v.cvss_score || 0}</span>
                            </div>
                        </div>
                        <div class="vuln-title">${escapeHtml(v.title)}</div>
                        <div class="vuln-description">${escapeHtml(v.description)}</div>
                        <div class="vuln-meta">
                            <span class="vuln-meta-item"><span class="vuln-meta-label">组件:</span> <span class="vuln-meta-value">${escapeHtml(v.component)}</span></span>
                            <span class="vuln-meta-item"><span class="vuln-meta-label">已安装版本:</span> <span class="vuln-meta-value">${escapeHtml(v.installed_version) || "-"}</span></span>
                            <span class="vuln-meta-item"><span class="vuln-meta-label">受影响版本:</span> <span class="vuln-meta-value">${escapeHtml(v.affected_versions) || "-"}</span></span>
                            ${v.exploit_type ? `<span class="vuln-meta-item"><span class="vuln-meta-label">利用类型:</span> <span class="vuln-meta-value">${escapeHtml(v.exploit_type)}</span></span>` : ""}
                            ${v.exploit_difficulty ? `<span class="vuln-meta-item"><span class="vuln-meta-label">利用难度:</span> <span class="vuln-meta-value">${escapeHtml(v.exploit_difficulty)}</span></span>` : ""}
                            <span class="vuln-meta-item"><span class="vuln-meta-label">来源:</span> <span class="vuln-meta-value">${escapeHtml(v.source)}</span></span>
                        </div>
                        ${refs ? `<div class="vuln-references">${refs}</div>` : ""}
                    </div>
                `;
            }).join("");
        }

        // 利用方式列表
        const exploitList = clone.querySelector(".exploit-list");
        const exploits = assetData.exploits || [];
        if (exploits.length === 0) {
            exploitList.innerHTML = '<div class="empty-state">暂无可用的漏洞利用方式信息</div>';
        } else {
            exploitList.innerHTML = exploits.map(e => {
                const diffCls = (e.difficulty || "").toLowerCase();
                const tools = (e.tools || []).map(t =>
                    `<span class="exploit-tool">${escapeHtml(t)}</span>`
                ).join("");
                const refs = (e.references || []).map(r =>
                    `<a href="${escapeHtml(r)}" target="_blank" rel="noopener" style="font-size:12px;color:var(--accent-blue);text-decoration:none;margin-right:12px;">${escapeHtml(r)}</a>`
                ).join("");
                return `
                    <div class="exploit-item">
                        <div class="exploit-header">
                            <span class="exploit-cve">${escapeHtml(e.cve_id)}</span>
                            <span class="difficulty-badge ${diffCls}">${escapeHtml(e.difficulty) || "Unknown"}</span>
                        </div>
                        <div class="exploit-section">
                            <div class="exploit-section-label">漏洞</div>
                            <div class="exploit-section-content">${escapeHtml(e.vuln_title)}</div>
                        </div>
                        <div class="exploit-section">
                            <div class="exploit-section-label">利用入口</div>
                            <div class="exploit-section-content">${escapeHtml(e.exploit_entry)}</div>
                        </div>
                        <div class="exploit-section">
                            <div class="exploit-section-label">利用步骤</div>
                            <div class="exploit-section-content">${escapeHtml(e.exploit_steps)}</div>
                        </div>
                        ${tools ? `
                        <div class="exploit-section">
                            <div class="exploit-section-label">所需工具</div>
                            <div class="exploit-tools">${tools}</div>
                        </div>` : ""}
                        ${e.payload_example ? `
                        <div class="exploit-section">
                            <div class="exploit-section-label">Payload 示例（仅供防御分析）</div>
                            <div class="exploit-payload">${escapeHtml(e.payload_example)}</div>
                        </div>` : ""}
                        <div class="exploit-section">
                            <div class="exploit-section-label">修复建议</div>
                            <div class="exploit-mitigation">${escapeHtml(e.mitigation)}</div>
                        </div>
                        ${refs ? `
                        <div class="exploit-section">
                            <div class="exploit-section-label">参考链接</div>
                            <div>${refs}</div>
                        </div>` : ""}
                    </div>
                `;
            }).join("");
        }

        // API 安全报告
        const apiReport = clone.querySelector(".api-report");
        const apiEndpoints = assetData.api_endpoints || [];
        const apiReportData = assetData.api_report;

        if (apiEndpoints.length === 0 && !apiReportData) {
            apiReport.innerHTML = '<div class="empty-state">未进行 API 扫描或未发现 API 端点</div>';
        } else {
            let html = "";

            // 报告摘要和风险评分
            if (apiReportData) {
                const score = apiReportData.risk_score || 0;
                html += `
                    <div class="api-report-score">
                        <span class="api-score-label">API 风险评分:</span>
                        <span class="api-score-value" style="color:${riskScoreColor(score)}">${score}/100</span>
                        <span class="api-score-label">| 端点总数: ${apiReportData.total_endpoints || 0}</span>
                    </div>
                    <div class="api-report-summary">${escapeHtml(apiReportData.summary || "")}</div>
                `;
            }

            // 端点列表
            if (apiEndpoints.length > 0) {
                html += '<div class="api-endpoint-list">';
                apiEndpoints.forEach(ep => {
                    const riskCls = (ep.risk_level || "info");
                    const issues = (ep.security_issues || []).map(issue =>
                        `<div class="api-security-issue">${escapeHtml(issue)}</div>`
                    ).join("");

                    const params = (ep.params || []).map(p => escapeHtml(p)).join(", ");

                    html += `
                        <div class="api-endpoint-item risk-${riskCls}">
                            <div class="api-endpoint-header">
                                <span class="api-method">${escapeHtml(ep.method)}</span>
                                <span class="api-endpoint-url">${escapeHtml(ep.url)}</span>
                                <span class="severity-tag ${riskCls}">${escapeHtml(riskLevelLabel(ep.risk_level))}</span>
                            </div>
                            <div class="api-endpoint-desc">${escapeHtml(ep.description)}</div>
                            ${issues ? `<div class="api-security-issues">${issues}</div>` : ""}
                            <div class="api-endpoint-meta">
                                ${ep.response_code ? `<span>状态码: ${ep.response_code}</span>` : ""}
                                ${ep.auth_required !== undefined ? `<span>需认证: ${ep.auth_required ? "是" : "否"}</span>` : ""}
                                ${ep.auth_type ? `<span>认证类型: ${escapeHtml(ep.auth_type)}</span>` : ""}
                                ${ep.content_type ? `<span>内容类型: ${escapeHtml(ep.content_type)}</span>` : ""}
                                ${params ? `<span>参数: ${params}</span>` : ""}
                            </div>
                        </div>
                    `;
                });
                html += '</div>';
            }

            apiReport.innerHTML = html;
        }

        // 返回克隆的 DOM 的 HTML
        const tempDiv = document.createElement("div");
        tempDiv.appendChild(clone);
        return tempDiv.innerHTML;
    }

    // ============================================================
    // 详情标签页切换
    // ============================================================

    function bindDetailTabs(container) {
        const tabs = container.querySelectorAll(".detail-tab");
        const panels = container.querySelectorAll(".detail-panel");

        tabs.forEach(tab => {
            tab.addEventListener("click", function () {
                const target = this.dataset.tab;

                // 取消所有激活状态
                tabs.forEach(t => t.classList.remove("active"));
                panels.forEach(p => p.classList.remove("active"));

                // 激活当前标签
                this.classList.add("active");
                const panel = container.querySelector(`.detail-panel[data-panel="${target}"]`);
                if (panel) panel.classList.add("active");
            });
        });
    }

    // ============================================================
    // 错误显示与按钮重置
    // ============================================================

    function showError(message) {
        hide(els.progressSection);
        els.errorMessage.textContent = message;
        show(els.errorSection);
        els.errorSection.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    function resetButton() {
        els.startBtn.disabled = false;
        els.startBtn.innerHTML = "&#9654; 开始分析";
        els.cancelBtn.disabled = false;
        els.cancelBtn.textContent = "取消分析";
    }

    // ============================================================
    // 认证相关逻辑
    // ============================================================

    /**
     * 检查当前登录状态
     */
    async function checkAuthStatus() {
        try {
            const resp = await fetch("/api/auth/status");
            const data = await resp.json();
            if (data.logged_in) {
                currentRole = data.role;
                isLoggedIn = true;
            } else {
                currentRole = "guest";
                isLoggedIn = false;
            }
            updateRoleUI(currentRole, data.is_admin);
        } catch (e) {
            console.error("检查登录状态失败:", e);
        }
    }

    /**
     * 根据角色更新界面显示
     * - 管理员：显示所有操作按钮
     * - 游客：隐藏操作按钮（admin-only 类元素），但可查看所有数据
     */
    function updateRoleUI(role, isAdmin) {
        const roleBadge = document.getElementById("userRole");
        const loginBtn = document.getElementById("loginBtnNav");
        const logoutBtn = document.getElementById("logoutBtnNav");

        // 更新角色徽章
        if (roleBadge) {
            roleBadge.textContent = isAdmin ? "管理员" : "只读";
            roleBadge.className = "role-badge " + (isAdmin ? "admin" : "guest");
        }

        // 显示/隐藏登录和登出按钮
        // 已登录时（无论管理员还是游客）隐藏登录按钮，显示登出按钮
        if (loginBtn) loginBtn.style.display = isLoggedIn ? "none" : "";
        if (logoutBtn) {
            logoutBtn.style.display = isLoggedIn ? "" : "none";
            logoutBtn.classList.toggle("hidden", !isLoggedIn);
        }

        // 根据角色显示/隐藏操作区域（admin-only 类元素）
        const actionElements = document.querySelectorAll(".admin-only");
        actionElements.forEach(el => {
            el.classList.toggle("hidden", !isAdmin);
            el.style.display = isAdmin ? "" : "none";
        });
        const permissionHint = document.getElementById("scanPermissionHint");
        if (permissionHint) {
            permissionHint.textContent = isAdmin ? "已获得扫描权限" : "登录管理员后可开始扫描";
            permissionHint.classList.toggle("ready", isAdmin);
        }
    }

    /**
     * 打开登录模态框
     */
    function openLoginModal() {
        const modal = document.getElementById("loginModal");
        if (modal) {
            modal.style.display = "block";
            document.getElementById("loginError").textContent = "";
            document.getElementById("adminPassword").value = "";
            document.getElementById("adminPassword").focus();
        }
    }

    /**
     * 关闭登录模态框
     */
    function closeLoginModal() {
        const modal = document.getElementById("loginModal");
        if (modal) {
            modal.style.display = "none";
        }
    }

    /**
     * 执行登录
     */
    async function doLogin() {
        const password = document.getElementById("adminPassword").value;
        const errorEl = document.getElementById("loginError");
        errorEl.textContent = "";

        try {
            const resp = await fetch("/api/auth/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    role: "admin",
                    password: password,
                }),
            });
            const data = await resp.json();

            if (resp.ok) {
                currentRole = data.role;
                isLoggedIn = true;
                updateRoleUI(data.role, data.role === "admin");
                closeLoginModal();
            } else {
                errorEl.textContent = data.error || "登录失败";
            }
        } catch (e) {
            errorEl.textContent = "登录失败，请检查网络连接";
        }
    }

    /**
     * 执行登出
     */
    async function doLogout() {
        try {
            await fetch("/api/auth/logout", { method: "POST" });
            currentRole = "guest";
            isLoggedIn = false;
            updateRoleUI("guest", false);
        } catch (e) {
            console.error("登出失败:", e);
        }
    }

    // ============================================================
    // 事件绑定与初始化
    // ============================================================

    function init() {
        // 模式切换
        els.tabFofa.addEventListener("click", () => switchMode("fofa"));
        els.tabManual.addEventListener("click", () => switchMode("manual"));

        // 开始分析
        els.startBtn.addEventListener("click", startAnalysis);
        els.cancelBtn.addEventListener("click", cancelAnalysis);

        // 回车提交（FOFA 查询框）
        els.fofaQuery.addEventListener("keypress", function (e) {
            if (e.key === "Enter") startAnalysis();
        });

        // 检测 FOFA 配置
        checkFofaConfig();
        // 检测 AI 配置状态
        checkAiConfig();
        loadShowcase();
        loadResearchOverview();
        loadLabOverview();
        window.setInterval(loadResearchOverview, 60000);
        window.setInterval(loadLabOverview, 60000);
        els.publicAssetSearch.addEventListener("input", renderPublicAssets);
        els.publicRiskFilter.addEventListener("change", renderPublicAssets);

        // 检查登录状态
        checkAuthStatus();

        // 登录按钮事件
        const loginBtnNav = document.getElementById("loginBtnNav");
        if (loginBtnNav) {
            loginBtnNav.addEventListener("click", openLoginModal);
        }

        // 登出按钮事件
        const logoutBtnNav = document.getElementById("logoutBtnNav");
        if (logoutBtnNav) {
            logoutBtnNav.addEventListener("click", doLogout);
        }

        // 登录模态框关闭按钮
        const modalClose = document.getElementById("loginModalClose");
        if (modalClose) {
            modalClose.addEventListener("click", closeLoginModal);
        }

        // 点击模态框外部关闭
        const loginModal = document.getElementById("loginModal");
        if (loginModal) {
            loginModal.addEventListener("click", function (e) {
                if (e.target === loginModal) closeLoginModal();
            });
        }

        // 登录提交按钮
        const loginSubmitBtn = document.getElementById("loginSubmitBtn");
        if (loginSubmitBtn) {
            loginSubmitBtn.addEventListener("click", doLogin);
        }

        // 密码框回车提交
        const adminPassword = document.getElementById("adminPassword");
        if (adminPassword) {
            adminPassword.addEventListener("keypress", function (e) {
                if (e.key === "Enter") doLogin();
            });
        }
    }

    // DOM 加载完成后初始化
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }

})();
