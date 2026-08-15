"""Passive infrastructure supply-chain enrichment.

The collector intentionally uses registration, routing and DNS metadata only.
It does not scan provider ranges, enumerate neighbouring hosts, or turn a
supplier entity into an executable Worker target.
"""
from __future__ import annotations

import ipaddress
import hashlib
import socket
import ssl
import time
from typing import Any, Callable, Dict, Iterable, List
from urllib.parse import quote, urlparse

import requests


JsonGetter = Callable[[str], Dict[str, Any]]
DnsGetter = Callable[[str, str], Iterable[str]]
CertificateGetter = Callable[[str], Dict[str, Any]]


def _entity(entity_type: str, key: str, name: str = "", scope: str = "observed",
            source: str = "passive", confidence: float = 0.8,
            attributes: Dict[str, Any] | None = None) -> Dict[str, Any]:
    return {"type": entity_type, "key": key, "name": name or key, "scope": scope,
            "source": source, "confidence": confidence, "attributes": attributes or {}}


def _relation(subject_type: str, subject_key: str, predicate: str,
              object_type: str, object_key: str, source: str,
              confidence: float, evidence: Dict[str, Any] | None = None,
              status: str = "observed") -> Dict[str, Any]:
    return {
        "subject": {"type": subject_type, "key": subject_key},
        "predicate": predicate,
        "object": {"type": object_type, "key": object_key},
        "source": source, "confidence": confidence, "status": status,
        "evidence": evidence or {},
    }


def _vcard_name(entity: Dict[str, Any]) -> str:
    card = entity.get("vcardArray") or []
    fields = card[1] if len(card) > 1 and isinstance(card[1], list) else []
    organizations = []
    names = []
    for field in fields:
        if not isinstance(field, list) or len(field) < 4:
            continue
        if field[0] == "org" and isinstance(field[3], str):
            organizations.append(field[3])
        if field[0] == "fn" and isinstance(field[3], str):
            names.append(field[3])
    return next(iter(organizations or names), "")


def _registrants(payload: Dict[str, Any]) -> List[str]:
    names = []
    for entity in payload.get("entities") or []:
        if "registrant" in (entity.get("roles") or []):
            name = _vcard_name(entity)
            if name and name not in names:
                names.append(name)
        for nested in entity.get("entities") or []:
            if "registrant" in (nested.get("roles") or []):
                name = _vcard_name(nested)
                if name and name not in names:
                    names.append(name)
    return names


def merge_graphs(*graphs: Dict[str, Any]) -> Dict[str, Any]:
    """Combine independent evidence sources before one snapshot upsert."""
    entities = []
    relations = []
    errors = []
    for graph in graphs:
        entities.extend(graph.get("entities") or [])
        relations.extend(graph.get("relations") or [])
        errors.extend(graph.get("errors") or [])
    return {"entities": entities, "relations": relations, "errors": errors}


def declared_services_graph(system_key: str, services: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Model configured platform providers without persisting credentials."""
    key = system_key.strip().lower()
    entities = [_entity("system", key, system_key, "owned", "runtime configuration", 1.0)]
    relations = []
    for service in services:
        name = str(service.get("name") or "").strip()
        if not name:
            continue
        base_url = str(service.get("base_url") or "").strip()
        host = (urlparse(base_url).hostname or "").lower()
        service_key = (host or name).lower()
        enabled = bool(service.get("enabled"))
        provider = str(service.get("provider") or name).strip()
        safe_attributes = {
            "base_host": host, "purpose": str(service.get("purpose") or ""),
            "enabled": enabled, "model": str(service.get("model") or ""),
        }
        entities.append(_entity("external_service", service_key, name, "supplier",
                                "runtime configuration", 1.0, safe_attributes))
        relations.append(_relation("system", key, "DEPENDS_ON_SERVICE",
                                   "external_service", service_key,
                                   "runtime configuration", 1.0, safe_attributes,
                                   "configured" if enabled else "disabled"))
        if provider:
            provider_key = provider.lower()
            entities.append(_entity("organization", provider_key, provider, "supplier",
                                    "runtime configuration", 0.95,
                                    {"role": "external service provider"}))
            relations.append(_relation("external_service", service_key, "PROVIDED_BY",
                                       "organization", provider_key,
                                       "runtime configuration", 0.95,
                                       {"enabled": enabled},
                                       "configured" if enabled else "disabled"))
    return {"entities": entities, "relations": relations, "errors": []}


def evidence_supply_chain_graph(target: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Convert existing Worker evidence into routes/components/dependencies.

    No network request is made. Absolute third-party URLs become supplier
    observations only and are never promoted to executable scan targets.
    """
    parsed_target = urlparse(target if "://" in target else "//" + target)
    hostname = (parsed_target.hostname or "").lower()
    asset_key = target.rstrip("/").lower()
    entities = [_entity("url", asset_key, target, "owned", "Worker evidence", 1.0)]
    relations = []

    for technology in analysis.get("technologies") or []:
        if not isinstance(technology, dict) or not technology.get("name"):
            continue
        name = str(technology["name"]).strip()
        version = str(technology.get("version") or "").strip()
        component_key = (name + ("@" + version if version else "")).lower()
        entities.append(_entity("component", component_key, name, "supplier",
                                "Worker technology fingerprint", 0.8,
                                {"version": version,
                                 "category": technology.get("category", "")}))
        relations.append(_relation("url", asset_key, "RUNS_COMPONENT",
                                   "component", component_key,
                                   "Worker technology fingerprint", 0.8,
                                   {"version": version}))

    route_sources = (("api_endpoints", "api_route", "EXPOSES_API"),
                     ("exposure_findings", "web_route", "DISCOVERED_ROUTE"))
    for field, entity_type, predicate in route_sources:
        for item in analysis.get(field) or []:
            if not isinstance(item, dict):
                continue
            raw_url = str(item.get("url") or item.get("endpoint") or item.get("path") or "").strip()
            if not raw_url:
                continue
            parsed = urlparse(raw_url)
            observed_host = (parsed.hostname or "").lower()
            if observed_host and hostname and observed_host != hostname:
                entities.append(_entity("domain", observed_host, observed_host,
                                        "supplier_observation", "Worker evidence", 0.75,
                                        {"discovered_from": field}))
                relations.append(_relation("url", asset_key, "CALLS_EXTERNAL_SERVICE",
                                           "domain", observed_host, "Worker evidence", 0.75,
                                           {"url": raw_url, "discovered_from": field},
                                           "unverified"))
                continue
            path = parsed.path if parsed.scheme else raw_url.split("?", 1)[0]
            if not path.startswith("/"):
                path = "/" + path
            route_key = f"{hostname}:{path}".lower()
            try:
                status_code = int(item.get("status_code") or item.get("status") or 0)
            except (TypeError, ValueError):
                status_code = 0
            attributes = {
                "path": path, "method": str(item.get("method") or "GET").upper(),
                "status_code": status_code,
                "auth_required": item.get("auth_required"),
                "source": item.get("source", ""),
            }
            entities.append(_entity(entity_type, route_key, path, "owned",
                                    "Worker evidence", 0.85 if status_code else 0.6,
                                    attributes))
            relations.append(_relation("url", asset_key, predicate, entity_type,
                                       route_key, "Worker evidence",
                                       0.85 if status_code else 0.6, attributes,
                                       "observed" if status_code else "unverified"))
    return {"entities": entities, "relations": relations, "errors": []}


def generate_infrastructure_decision_cards(database: Any, project_slug: str) -> Dict[str, int]:
    """Turn current relationship facts into idempotent operational cards."""
    from core.analyst import build_card

    overview = database.supply_chain_overview(project_slug)
    summary = overview.get("summary") or {}
    created = 0
    updated = 0

    def persist(card: Dict[str, Any]):
        nonlocal created, updated
        if database.card_insert(card):
            created += 1
        else:
            updated += 1

    if summary.get("single_provider_dependency"):
        providers = sorted({row.get("name") for row in overview.get("suppliers", [])
                            if row.get("role") in ("OPERATED_BY", "ASSIGNED_TO")
                            and row.get("name")})
        provider_text = "、".join(providers) or "单一网络供应商"
        persist(build_card(
            "基础设施单点：网络与主机",
            severity="MEDIUM", evidence_level=1,
            asset_count=int(summary.get("current_hosts") or 0),
            source="DNS + BGP + RDAP", card_type="infrastructure",
            confidence="high",
            change_text=(f"当前 {summary.get('current_hosts', 0)} 个主机 / "
                         f"{summary.get('current_ips', 0)} 个 IP 依赖 {provider_text}"),
            why_worth="主机、IP 与网络供应商均未形成冗余，故障会同时影响全部入口",
            evidence_says=(f"当前 DNS、BGP 与 RDAP 共同指向 {summary.get('providers', 0)} "
                           f"个主要网络提供方；URL 入口 {summary.get('url_entries', 0)} 个"),
            evidence_limits="公开路由与登记信息不能确认物理机房，也不能证明供应商当前存在故障",
            next_step="准备第二部署节点、数据库备份恢复演练，并评估 CDN/双入口切换",
            abort_condition="出现已验证的第二独立主机、IP 与网络提供方后关闭此卡",
            payload={"project_slug": project_slug, "summary": summary,
                     "providers": providers},
        ))

    if int(summary.get("historical_ips") or 0) > 0:
        persist(build_card(
            "基础设施变化：历史 IP",
            severity="LOW", evidence_level=1,
            asset_count=int(summary.get("historical_ips") or 0),
            source="资产历史 + 当前 DNS", card_type="infrastructure-change",
            confidence="high",
            change_text=f"发现 {summary.get('historical_ips')} 个历史 IP，已与当前 DNS 分离标记",
            why_worth="旧 IP 若仍提供内容、保留证书或未回收，可能形成遗留入口",
            evidence_says="资产历史记录与当前 DNS 结果不一致，系统保留历史但不视为当前解析",
            evidence_limits="仅证明地址曾被观测，未主动验证旧地址当前是否仍属于本项目",
            next_step="核对迁移记录和云厂商控制台；仅在确认仍属自有资产后进行验证",
            abort_condition="确认旧 IP 已释放且不再承载任何自有服务",
            payload={"project_slug": project_slug,
                     "historical_ips": summary.get("historical_ips")},
        ))

    for certificate in database.supply_chain_certificates(project_slug):
        attributes = certificate.get("attributes") or {}
        days = attributes.get("days_remaining")
        if days is None or int(days) > 60:
            continue
        severity = "HIGH" if int(days) <= 30 else "MEDIUM"
        persist(build_card(
            f"证书到期：{certificate.get('display_name', '')[:16]}",
            severity=severity, evidence_level=1,
            asset_count=int(certificate.get("asset_count") or 0),
            source="TLS handshake", card_type="certificate",
            confidence="high",
            change_text=f"当前 TLS 证书剩余 {int(days)} 天",
            why_worth="证书到期会导致浏览器和 API 客户端拒绝连接",
            evidence_says=f"TLS 握手返回 notAfter={attributes.get('not_after', '')}",
            evidence_limits="仅观测当前对外证书，不代表自动续期机制一定失败",
            next_step="检查 ACME 自动续期、续期定时器和到期前告警",
            abort_condition="新证书生效且剩余有效期超过 60 天",
            payload={"project_slug": project_slug,
                     "certificate": certificate.get("entity_id"), "days_remaining": days},
        ))
    return {"created": created, "updated": updated}


class PassiveInfrastructureCollector:
    def __init__(self, timeout: float = 8.0, json_getter: JsonGetter | None = None,
                 resolver: Callable[[str], Iterable[str]] | None = None,
                 dns_getter: DnsGetter | None = None,
                 certificate_getter: CertificateGetter | None = None):
        self.timeout = timeout
        self._json_getter = json_getter or self._get_json
        self._resolver = resolver or self._resolve
        self._dns_getter = dns_getter or self._dns_records
        self._certificate_getter = certificate_getter or self._certificate

    def _get_json(self, url: str) -> Dict[str, Any]:
        response = requests.get(url, timeout=self.timeout,
                                headers={"User-Agent": "SupplyChainBrain/1.0 passive-enrichment"})
        response.raise_for_status()
        return response.json()

    @staticmethod
    def _resolve(hostname: str) -> Iterable[str]:
        return sorted({row[4][0] for row in socket.getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM)})

    def _dns_records(self, hostname: str, record_type: str) -> Iterable[str]:
        payload = self._get_json(
            f"https://dns.google/resolve?name={quote(hostname)}&type={quote(record_type)}")
        expected_type = {"NS": 2, "CNAME": 5, "MX": 15}.get(record_type.upper())
        return [str(row.get("data") or "").strip() for row in payload.get("Answer") or []
                if row.get("data") and (expected_type is None or row.get("type") == expected_type)]

    def _certificate(self, hostname: str) -> Dict[str, Any]:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=self.timeout) as raw:
            with context.wrap_socket(raw, server_hostname=hostname) as connection:
                parsed = connection.getpeercert()
                binary = connection.getpeercert(binary_form=True)
        issuer = {key: value for group in parsed.get("issuer") or [] for key, value in group}
        subject = {key: value for group in parsed.get("subject") or [] for key, value in group}
        expires_at = ssl.cert_time_to_seconds(parsed["notAfter"]) if parsed.get("notAfter") else 0
        return {
            "fingerprint_sha256": hashlib.sha256(binary).hexdigest(),
            "serial_number": parsed.get("serialNumber", ""),
            "issuer": issuer, "subject": subject,
            "not_before": parsed.get("notBefore", ""), "not_after": parsed.get("notAfter", ""),
            "expires_at": expires_at,
            "days_remaining": int((expires_at - time.time()) / 86400) if expires_at else None,
            "subject_alt_names": [value for kind, value in parsed.get("subjectAltName") or []
                                  if kind == "DNS"],
        }

    @staticmethod
    def _apex_domain(hostname: str) -> str:
        # Conservative fallback without a public-suffix dependency.  Querying
        # the hostname itself first still works for delegated subdomains.
        labels = hostname.split(".")
        return ".".join(labels[-2:]) if len(labels) > 2 else hostname

    @staticmethod
    def _public_ips(values: Iterable[str]) -> List[str]:
        result = []
        for value in values:
            try:
                address = ipaddress.ip_address(value)
            except ValueError:
                continue
            if address.is_global and str(address) not in result:
                result.append(str(address))
        return result

    def collect(self, target: str, known_ips: Iterable[str] = ()) -> Dict[str, Any]:
        parsed = urlparse(target if "://" in target else "//" + target)
        hostname = (parsed.hostname or "").rstrip(".").lower()
        if not hostname:
            return {"entities": [], "relations": [], "errors": ["target has no hostname"]}

        entities = {}
        relations = []
        errors = []

        def add(entity: Dict[str, Any]):
            entities[(entity["type"], entity["key"])] = entity

        asset_key = target.rstrip("/").lower()
        add(_entity("url", asset_key, target, "owned", "asset inventory", 1.0))
        add(_entity("domain", hostname, hostname, "owned", "URL parser", 1.0))
        relations.append(_relation("url", asset_key, "SERVED_BY", "domain", hostname,
                                   "URL parser", 1.0))

        self._enrich_dns(hostname, add, relations, errors)
        self._enrich_tls(hostname, add, relations, errors)

        known = self._public_ips(known_ips)
        resolved = []
        try:
            resolved = self._public_ips(self._resolver(hostname))
        except Exception as exc:
            errors.append(f"DNS: {exc}")

        for ip in self._public_ips([*resolved, *known]):
            current = ip in resolved
            add(_entity("ip", ip, ip, "owned_observation",
                        "DNS" if current else "asset inventory", 0.95 if current else 0.7,
                        {"current_dns": current}))
            relations.append(_relation(
                "domain", hostname, "RESOLVES_TO" if current else "OBSERVED_AT", "ip", ip,
                "DNS" if current else "asset inventory", 0.95 if current else 0.7,
                {"hostname": hostname, "address": ip, "current_dns": current},
                "current" if current else "historical"))
            self._enrich_ip(ip, add, relations, errors)
        return {"entities": list(entities.values()), "relations": relations,
                "errors": errors, "target": target}

    def _enrich_dns(self, hostname: str, add: Callable[[Dict[str, Any]], None],
                    relations: List[Dict[str, Any]], errors: List[str]):
        apex = self._apex_domain(hostname)
        if apex != hostname:
            add(_entity("domain", apex, apex, "owned_observation",
                        "registrable-domain heuristic", 0.8))
        for record_type, predicate, entity_type in (
                ("NS", "USES_NAMESERVER", "nameserver"),
                ("MX", "USES_MAIL_EXCHANGER", "mail_exchanger"),
                ("CNAME", "CNAME_TO", "domain")):
            query_name = hostname if record_type == "CNAME" else apex
            try:
                records = self._dns_getter(query_name, record_type)
                for raw in records:
                    value = str(raw).strip().rstrip(".")
                    if record_type == "MX":
                        fields = value.split()
                        value = fields[-1].rstrip(".") if fields else ""
                    if not value:
                        continue
                    key = value.lower()
                    add(_entity(entity_type, key, value, "supplier", "DNS-over-HTTPS", 0.95,
                                {"record_type": record_type, "query_name": query_name}))
                    relations.append(_relation("domain", query_name, predicate,
                                               entity_type, key, "DNS-over-HTTPS", 0.95,
                                               {"record_type": record_type, "value": value}))
            except Exception as exc:
                errors.append(f"DNS {record_type} {query_name}: {exc}")

    def _enrich_tls(self, hostname: str, add: Callable[[Dict[str, Any]], None],
                    relations: List[Dict[str, Any]], errors: List[str]):
        try:
            certificate = self._certificate_getter(hostname)
            fingerprint = str(certificate.get("fingerprint_sha256") or "").lower()
            if not fingerprint:
                return
            add(_entity("certificate", fingerprint, fingerprint[:16], "observed",
                        "TLS handshake", 1.0, certificate))
            relations.append(_relation("domain", hostname, "PRESENTS_CERTIFICATE",
                                       "certificate", fingerprint, "TLS handshake", 1.0,
                                       {"expires_at": certificate.get("expires_at"),
                                        "days_remaining": certificate.get("days_remaining")}))
            issuer = certificate.get("issuer") or {}
            issuer_name = str(issuer.get("organizationName") or
                              issuer.get("commonName") or "").strip()
            if issuer_name:
                issuer_key = issuer_name.lower()
                add(_entity("organization", issuer_key, issuer_name, "supplier",
                            "TLS certificate", 0.95, {"role": "certificate issuer"}))
                relations.append(_relation("certificate", fingerprint, "ISSUED_BY",
                                           "organization", issuer_key,
                                           "TLS certificate", 0.95))
            for name in (certificate.get("subject_alt_names") or [])[:100]:
                name_key = str(name).rstrip(".").lower()
                if not name_key:
                    continue
                add(_entity("domain", name_key, name, "certificate_observation",
                            "TLS certificate SAN", 0.9))
                relations.append(_relation("certificate", fingerprint, "COVERS_DOMAIN",
                                           "domain", name_key, "TLS certificate SAN", 0.9))
        except Exception as exc:
            errors.append(f"TLS {hostname}: {exc}")

    def _enrich_ip(self, ip: str, add: Callable[[Dict[str, Any]], None],
                   relations: List[Dict[str, Any]], errors: List[str]):
        try:
            route = self._json_getter(
                f"https://stat.ripe.net/data/network-info/data.json?resource={ip}")
            route_data = route.get("data") or {}
            prefix = str(route_data.get("prefix") or "")
            asns = [str(value) for value in route_data.get("asns") or []]
            if prefix:
                add(_entity("prefix", prefix, prefix, "supplier", "RIPEstat BGP", 0.95))
                relations.append(_relation("ip", ip, "IN_PREFIX", "prefix", prefix,
                                           "RIPEstat BGP", 0.95))
            for asn in asns:
                asn_key = "AS" + asn.removeprefix("AS")
                add(_entity("asn", asn_key.lower(), asn_key, "supplier", "RIPEstat BGP", 0.95))
                subject_type, subject_key = ("prefix", prefix) if prefix else ("ip", ip)
                relations.append(_relation(subject_type, subject_key, "ANNOUNCED_BY",
                                           "asn", asn_key.lower(), "RIPEstat BGP", 0.95))
                self._enrich_asn(asn, add, relations, errors)
        except Exception as exc:
            errors.append(f"BGP {ip}: {exc}")

        try:
            rdap = self._json_getter(f"https://rdap.arin.net/registry/ip/{ip}")
            network = str(rdap.get("name") or rdap.get("handle") or ip)
            for index, name in enumerate(_registrants(rdap)):
                org_key = name.strip().lower()
                add(_entity("organization", org_key, name, "supplier", "ARIN RDAP", 0.9,
                            {"role": "IP registrant", "network": network}))
                predicate = "ASSIGNED_TO" if index == 0 else "RESOURCE_MANAGED_BY"
                relations.append(_relation("ip", ip, predicate, "organization", org_key,
                                           "ARIN RDAP", 0.9,
                                           {"network": network, "handle": rdap.get("handle", "")}))
        except Exception as exc:
            errors.append(f"RDAP {ip}: {exc}")

    def _enrich_asn(self, asn: str, add: Callable[[Dict[str, Any]], None],
                    relations: List[Dict[str, Any]], errors: List[str]):
        asn_number = asn.removeprefix("AS")
        asn_key = "as" + asn_number
        try:
            rdap = self._json_getter(f"https://rdap.arin.net/registry/autnum/{asn_number}")
            names = _registrants(rdap)
            if not names and rdap.get("name"):
                names = [str(rdap["name"])]
            for name in names:
                org_key = name.strip().lower()
                add(_entity("organization", org_key, name, "supplier", "ARIN RDAP", 0.95,
                            {"role": "ASN registrant", "asn": "AS" + asn_number}))
                relations.append(_relation("asn", asn_key, "OPERATED_BY",
                                           "organization", org_key, "ARIN RDAP", 0.95,
                                           {"handle": rdap.get("handle", "")}))
        except Exception as exc:
            errors.append(f"ASN RDAP AS{asn_number}: {exc}")
