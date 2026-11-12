"""从资产和观测证据生成可解释的授权范围内关系边。"""

from __future__ import annotations

from collections import defaultdict

from assetops.models.asset import Asset
from assetops.models.relation import AssetRelation


_RELATION_KEYS = {
    "ip": "same_ip",
    "asn": "same_asn",
    "cname": "same_cname",
    "cert_cn": "same_certificate",
    "favicon_hash": "same_favicon",
    "jarm_hash": "same_jarm",
}


def derive_relations(assets: list[Asset]) -> list[AssetRelation]:
    """按共享稳定指纹生成关系；不从关系反向扩展 Scope。"""
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for asset in assets:
        if asset.ip:
            groups[("ip", asset.ip.strip().lower())].add(asset.id)
        for observation in asset.observations:
            for key, relation_type in _RELATION_KEYS.items():
                value = observation.evidence.get(key)
                if isinstance(value, str) and value.strip():
                    groups[(key, value.strip().lower())].add(asset.id)

    relations: dict[tuple[str, str, str], AssetRelation] = {}
    for (key, value), asset_ids in groups.items():
        if len(asset_ids) < 2:
            continue
        relation_type = _RELATION_KEYS[key]
        ordered = sorted(asset_ids)
        for index, source_id in enumerate(ordered):
            for target_id in ordered[index + 1:]:
                relation = AssetRelation(
                    source_asset_id=source_id,
                    target_asset_id=target_id,
                    relation_type=relation_type,
                    confidence="medium" if key in {"ip", "cert_cn", "cname"} else "low",
                    evidence={"key": key, "value": value},
                )
                relations[(source_id, target_id, relation_type)] = relation
    return list(relations.values())
