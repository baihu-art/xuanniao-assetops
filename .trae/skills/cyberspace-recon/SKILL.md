---
name: cyberspace-recon
description: 使用玄鸟共享CLI/MCP在明确授权范围内进行被动资产发现与当前Run报告。
---

# 被动资产发现

先明确用户授权的目标、Provider、预算；用 MCP `check_scope(target)` 或 `assetops scope-check TARGET` 检查，但服务端仍需逐结果执行范围校验。不得读取真实.env或输出密钥。

离线演示使用 `assetops run TARGET --providers mock`；实际被动查询仅在明确授权后使用 `assetops run TARGET --providers fofa,quake`，或 MCP `recon_domain(target, providers=["fofa", "quake"])`。缺凭据skipped，错误和部分完成必须如实呈现，不把0发现解释为成功覆盖。

查询使用 MCP `list_assets(run_id=RUN_ID, limit=50, offset=0)` 并分页。随后可显式离线分析 `analyze(run_id)`。导出 `assetops export-signals RUN_ID` / MCP `export_signals(run_id)`，资产信号位于 `data_root/runs/RUN_ID/signals/assets.json`，读取 `data.assets`；其他六类信号读取 `data.results`，核对schema_version、run_id、kind、status、warnings。

报告 `assetops export-report --run-id RUN_ID --format markdown`。只含该Run数据，不宣称旧英招脚本直接兼容。主动探测默认关闭，不因被动发现或相似指纹自动触发httpx、碰撞、枚举或未授权引擎搜索。
