---
name: asset-analysis
description: 对玄鸟当前Run已有证据执行离线五维评分并解释优先级，不进行主动探测。
---

# 资产分析

先确认用户指定的 Run ID。使用 MCP `analyze(run_id)` 或 CLI `assetops analyze RUN_ID`；再调用 `export_signals(run_id)` / `assetops export-signals RUN_ID`。

读取 `data_root/runs/RUN_ID/signals/analysis.json` 的 `data.results`，资产清单读取 `assets.json` 的 `data.assets`。公共字段是 schema_version、run_id、kind、status、data、warnings。不得套用旧英招脚本的冲突字段。

解释 exposure / technical_risk / data_value / attack_surface / uniqueness 五项、score、priority、reasons、input_observation_ids 和 missing_information。yingzhao-v1 理论满分100，实际最高97；高≥60、中≥35。按主机取最高分展示Top20。产品名不是漏洞证据，未知不代表安全。

仅分析该Run观测；不得自动执行httpx、枚举、碰撞或外部搜索。主动功能默认关闭，只有用户明确授权相应目标、动作及限额后才能单独执行。报告用 `assetops export-report --run-id RUN_ID --format markdown` 或 MCP `export_report(run_id, format="markdown")`，不导出正文、凭据。
