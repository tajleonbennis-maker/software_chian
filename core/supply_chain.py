"""
供应链映射器 - 将检测到的技术映射到供应链和组件关系

本模块负责将技术检测器识别出的技术列表，按照生态系统进行分组，
并映射到对应的供应链和厂商关系，构建供应链视图。

主要功能：
1. 加载组件-厂商映射数据库
2. 将技术列表按生态系统分组为供应链
3. 查询组件的厂商、生态系统等详细信息
"""
import json
import os
import logging
from typing import List, Dict, Optional, Any
from dataclasses import dataclass, field


logger = logging.getLogger(__name__)


@dataclass
class Technology:
    """技术组件数据模型

    存储单个检测到的技术信息，与 tech_detector.Technology 兼容。
    """
    name: str
    version: str = ""
    category: str = ""
    vendor: str = ""
    supply_chain: str = ""


@dataclass
class SupplyChain:
    """供应链数据模型

    表示一个生态系统下的供应链，包含该供应链涉及的所有组件。
    """
    name: str  # 供应链名称，如 "Java/Maven"、"Node.js/npm"
    ecosystem: str  # 生态系统名称
    components: List[Technology] = field(default_factory=list)  # 包含的组件列表
    vendor: str = ""  # 主要厂商（取该供应链中组件最常见的厂商）

    def add_component(self, tech: Technology):
        """添加组件到供应链"""
        if tech not in self.components:
            self.components.append(tech)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典，便于序列化"""
        return {
            "name": self.name,
            "ecosystem": self.ecosystem,
            "vendor": self.vendor,
            "component_count": len(self.components),
            "components": [
                {"name": c.name, "version": c.version, "vendor": c.vendor,
                 "category": c.category, "supply_chain": c.supply_chain}
                for c in self.components
            ],
        }


class SupplyChainMapper:
    """供应链映射器

    将检测到的技术列表映射到供应链关系。
    通过组件-厂商映射数据库，将技术按生态系统分组，
    并补充厂商、供应链等元信息。

    使用示例::

        mapper = SupplyChainMapper()
        technologies = [
            Technology(name="Apache Tomcat", version="8.5.50"),
            Technology(name="jQuery", version="3.5.1"),
        ]
        supply_chains = mapper.map(technologies)
        for sc in supply_chains:
            print(f"{sc.name}: {[c.name for c in sc.components]}")
    """

    def __init__(self, vendor_map_path: Optional[str] = None):
        """初始化供应链映射器

        Args:
            vendor_map_path: 组件厂商映射文件路径，为空时使用默认路径
        """
        self.vendor_map: Dict[str, Dict] = {}
        self.components_list: List[Dict] = []
        self._load_vendor_map(vendor_map_path)
        logger.info("已加载 %d 个组件的厂商映射", len(self.vendor_map))

    def _get_default_data_path(self) -> str:
        """获取默认的数据目录路径

        自动定位项目结构中的 data 目录。

        Returns:
            data 目录的绝对路径
        """
        # 本文件位于 core/ 目录下，数据文件位于 ../data/
        current_dir = os.path.dirname(os.path.abspath(__file__))
        data_dir = os.path.join(current_dir, "..", "data")
        return os.path.abspath(data_dir)

    def _load_vendor_map(self, vendor_map_path: Optional[str] = None):
        """加载组件-厂商映射数据库

        从 JSON 文件加载组件信息，并构建以组件名为键的索引。
        同时为每个组件的别名建立索引，支持多名称查找。

        Args:
            vendor_map_path: 映射文件路径，为空时使用默认路径
        """
        if vendor_map_path is None:
            vendor_map_path = os.path.join(
                self._get_default_data_path(), "component_vendors.json"
            )

        logger.debug("加载组件厂商映射文件: %s", vendor_map_path)

        if not os.path.exists(vendor_map_path):
            logger.error("组件厂商映射文件不存在: %s", vendor_map_path)
            return

        try:
            with open(vendor_map_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            logger.error("组件厂商映射文件 JSON 解析失败: %s", e)
            return
        except IOError as e:
            logger.error("读取组件厂商映射文件失败: %s", e)
            return

        # 兼容两种结构：直接是列表，或者包含 components 字段的字典
        if isinstance(data, list):
            components = data
        elif isinstance(data, dict):
            components = data.get("components", [])
        else:
            logger.warning("组件厂商映射文件格式异常")
            return

        self.components_list = components

        # 构建索引：以组件名和别名为键，指向组件信息
        for comp in components:
            name = comp.get("name", "")
            if name:
                self.vendor_map[name.lower()] = comp
            # 为别名也建立索引
            for alias in comp.get("aliases", []):
                if alias:
                    self.vendor_map[alias.lower()] = comp

    def get_component_info(self, tech_name: str) -> Dict:
        """获取组件详细信息

        通过组件名称（或别名）查询厂商、生态系统、供应链等信息。

        Args:
            tech_name: 技术组件名称

        Returns:
            组件信息字典，包含 name、vendor、ecosystem、supply_chain 等字段。
            如果未找到匹配，返回包含默认值的字典。
        """
        if not tech_name:
            return {}

        # 大小写不敏感查找
        key = tech_name.lower()
        if key in self.vendor_map:
            return dict(self.vendor_map[key])

        # 模糊匹配：如果精确匹配失败，尝试包含关系匹配
        for map_key, comp_info in self.vendor_map.items():
            if map_key in key or key in map_key:
                return dict(comp_info)

        # 未找到匹配，返回带默认值的字典
        return {
            "name": tech_name,
            "vendor": "",
            "ecosystem": "Unknown",
            "supply_chain": "Unknown",
        }

    def _enrich_technology(self, tech: Technology) -> Technology:
        """用厂商映射数据库补充技术的元信息

        如果技术对象缺少厂商、供应链等信息，从映射数据库中查找补充。

        Args:
            tech: 待补充的技术对象

        Returns:
            补充后的技术对象（原地修改并返回）
        """
        comp_info = self.get_component_info(tech.name)
        if comp_info:
            # 仅在原值为空时补充，不覆盖已有信息
            if not tech.vendor:
                tech.vendor = comp_info.get("vendor", "")
            if not tech.supply_chain:
                tech.supply_chain = comp_info.get("supply_chain", "")
            # 如果有生态系统信息，临时存储在 category 后面（不影响原有逻辑）
            # 这里不直接覆盖 category，而是通过 _get_ecosystem 获取
        return tech

    def _get_ecosystem(self, tech: Technology) -> str:
        """获取技术所属的生态系统

        优先使用厂商映射数据库中的 ecosystem 字段，
        如果未找到则根据 supply_chain 推断。

        Args:
            tech: 技术对象

        Returns:
            生态系统名称，如 "Java/Maven"、"Node.js/npm"
        """
        comp_info = self.get_component_info(tech.name)
        ecosystem = comp_info.get("ecosystem", "")
        if ecosystem:
            return ecosystem

        # 如果数据库中没有，根据 supply_chain 推断
        sc = tech.supply_chain.lower()
        if sc in ("apache", "spring"):
            return "Java/Maven"
        if sc in ("node.js", "npm"):
            return "Node.js/npm"
        if sc in ("php",):
            return "PHP/Composer"
        if sc in ("python",):
            return "Python/PyPI"
        if sc in ("microsoft", ".net"):
            return ".NET/NuGet"
        if sc in ("ruby",):
            return "Ruby/RubyGems"
        if sc in ("go",):
            return "Go/GoModules"
        if sc in ("red hat",):
            return "Java/Maven"
        if sc in ("oracle",):
            return "Java/Maven"

        return "Unknown"

    def _determine_primary_vendor(self, components: List[Technology]) -> str:
        """确定供应链的主要厂商

        统计该供应链下所有组件的厂商，返回出现次数最多的厂商。
        如果存在并列，返回第一个。

        Args:
            components: 组件列表

        Returns:
            主要厂商名称
        """
        if not components:
            return ""

        vendor_count: Dict[str, int] = {}
        for comp in components:
            if comp.vendor:
                vendor_count[comp.vendor] = vendor_count.get(comp.vendor, 0) + 1

        if not vendor_count:
            return ""

        # 按出现次数降序排序，取第一个
        sorted_vendors = sorted(vendor_count.items(), key=lambda x: x[1], reverse=True)
        return sorted_vendors[0][0]

    def map(self, technologies: List[Technology]) -> List[SupplyChain]:
        """将技术列表映射到供应链

        按照生态系统对技术进行分组，每组构建一个 SupplyChain 对象。
        同时利用厂商映射数据库补充技术缺失的元信息。

        Args:
            technologies: 检测到的技术列表

        Returns:
            供应链列表，按组件数量降序排列

        示例::

            mapper = SupplyChainMapper()
            techs = [Technology(name="Spring Framework"), Technology(name="jQuery")]
            chains = mapper.map(techs)
            for chain in chains:
                print(f"{chain.name}: {len(chain.components)} 个组件")
        """
        if not technologies:
            return []

        # 第一步：补充每个技术的厂商和供应链信息
        enriched_techs = []
        for tech in technologies:
            enriched = self._enrich_technology(tech)
            enriched_techs.append(enriched)

        # 第二步：按生态系统分组
        ecosystem_groups: Dict[str, List[Technology]] = {}
        for tech in enriched_techs:
            ecosystem = self._get_ecosystem(tech)
            if ecosystem not in ecosystem_groups:
                ecosystem_groups[ecosystem] = []
            ecosystem_groups[ecosystem].append(tech)

        # 第三步：构建供应链列表
        supply_chains: List[SupplyChain] = []
        for ecosystem, comps in ecosystem_groups.items():
            # 去重：同一名称的组件只保留一个（保留有版本号的）
            unique_comps = self._deduplicate_components(comps)
            primary_vendor = self._determine_primary_vendor(unique_comps)
            sc = SupplyChain(
                name=ecosystem,
                ecosystem=ecosystem,
                components=unique_comps,
                vendor=primary_vendor,
            )
            supply_chains.append(sc)

        # 按组件数量降序排列
        supply_chains.sort(key=lambda x: len(x.components), reverse=True)

        logger.info("技术映射完成: %d 项技术映射到 %d 个供应链",
                    len(technologies), len(supply_chains))
        return supply_chains

    def _deduplicate_components(self, components: List[Technology]) -> List[Technology]:
        """对组件列表去重

        同名组件保留版本号非空的那个；如果都有版本号，保留第一个。

        Args:
            components: 待去重的组件列表

        Returns:
            去重后的组件列表
        """
        seen: Dict[str, Technology] = {}
        for comp in components:
            name_key = comp.name.lower()
            if name_key not in seen:
                seen[name_key] = comp
            else:
                # 已存在同名组件，如果当前有版本而已有的没有，则替换
                existing = seen[name_key]
                if comp.version and not existing.version:
                    seen[name_key] = comp
        return list(seen.values())

    def get_supply_chain_summary(self, technologies: List[Technology]) -> Dict[str, Any]:
        """获取供应链映射的摘要信息

        适用于生成报告或展示统计概览。

        Args:
            technologies: 检测到的技术列表

        Returns:
            摘要字典，包含总数、生态系统分布、厂商分布等
        """
        supply_chains = self.map(technologies)
        total_components = sum(len(sc.components) for sc in supply_chains)
        total_vendors = len(set(
            comp.vendor for sc in supply_chains
            for comp in sc.components if comp.vendor
        ))

        ecosystem_distribution = {
            sc.ecosystem: len(sc.components) for sc in supply_chains
        }

        vendor_distribution: Dict[str, int] = {}
        for sc in supply_chains:
            for comp in sc.components:
                if comp.vendor:
                    vendor_distribution[comp.vendor] = \
                        vendor_distribution.get(comp.vendor, 0) + 1

        # 厂商分布按数量降序
        vendor_distribution = dict(
            sorted(vendor_distribution.items(), key=lambda x: x[1], reverse=True)
        )

        return {
            "total_technologies": len(technologies),
            "total_components": total_components,
            "total_supply_chains": len(supply_chains),
            "total_vendors": total_vendors,
            "ecosystem_distribution": ecosystem_distribution,
            "vendor_distribution": vendor_distribution,
            "supply_chains": [sc.to_dict() for sc in supply_chains],
        }

    def find_related_components(self, tech_name: str) -> List[Dict]:
        """查找与指定组件相关的其他组件

        返回同一生态系统下的其他组件，用于分析供应链关联关系。

        Args:
            tech_name: 技术组件名称

        Returns:
            相关组件信息列表
        """
        comp_info = self.get_component_info(tech_name)
        ecosystem = comp_info.get("ecosystem", "")
        if not ecosystem or ecosystem == "Unknown":
            return []

        related = []
        for comp in self.components_list:
            if comp.get("ecosystem") == ecosystem and comp.get("name", "").lower() != tech_name.lower():
                related.append(dict(comp))
        return related

    def reload(self, vendor_map_path: Optional[str] = None):
        """重新加载厂商映射数据库

        Args:
            vendor_map_path: 映射文件路径，为空时使用默认路径
        """
        self.vendor_map = {}
        self.components_list = []
        self._load_vendor_map(vendor_map_path)
        logger.info("重新加载厂商映射数据库完成，共 %d 个组件", len(self.vendor_map))


if __name__ == "__main__":
    # 模块直接运行时的演示
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    print("=" * 60)
    print("供应链映射器测试")
    print("=" * 60)

    mapper = SupplyChainMapper()
    print(f"\n已加载 {len(mapper.components_list)} 个组件映射")

    # 模拟检测到的技术列表
    test_technologies = [
        Technology(name="Apache Tomcat", version="8.5.50", category="web_server"),
        Technology(name="Spring Framework", version="5.3.16", category="web_framework"),
        Technology(name="Log4j", version="2.14.1", category="web_framework"),
        Technology(name="jQuery", version="3.5.1", category="frontend_library"),
        Technology(name="Vue.js", version="2.6.14", category="frontend_library"),
        Technology(name="PHP", version="7.4.3", category="web_server"),
        Technology(name="WordPress", version="5.6", category="cms"),
        Technology(name="Django", version="3.1", category="web_framework"),
        Technology(name="Nginx", version="1.18.0", category="web_server"),
    ]

    print("\n--- 供应链映射结果 ---")
    supply_chains = mapper.map(test_technologies)
    for sc in supply_chains:
        print(f"\n  供应链: {sc.name}")
        print(f"  生态系统: {sc.ecosystem}")
        print(f"  主要厂商: {sc.vendor}")
        print(f"  组件数量: {len(sc.components)}")
        for comp in sc.components:
            version_str = f" v{comp.version}" if comp.version else ""
            print(f"    - {comp.name}{version_str} [{comp.vendor}]")

    print("\n--- 组件信息查询 ---")
    for name in ["Spring Framework", "jQuery", "Apache Tomcat", "Unknown Tech"]:
        info = mapper.get_component_info(name)
        print(f"  {name}: vendor={info.get('vendor')}, ecosystem={info.get('ecosystem')}")

    print("\n--- 供应链摘要 ---")
    summary = mapper.get_supply_chain_summary(test_technologies)
    print(f"  总技术数: {summary['total_technologies']}")
    print(f"  总组件数: {summary['total_components']}")
    print(f"  供应链数: {summary['total_supply_chains']}")
    print(f"  厂商数: {summary['total_vendors']}")
    print(f"  生态系统分布: {summary['ecosystem_distribution']}")
    print(f"  厂商分布: {dict(list(summary['vendor_distribution'].items())[:5])}")

    print("\n--- 相关联组件查询 (Spring Framework) ---")
    related = mapper.find_related_components("Spring Framework")
    for r in related[:5]:
        print(f"  - {r['name']} ({r['vendor']})")
    print("=" * 60)
