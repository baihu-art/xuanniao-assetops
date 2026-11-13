---
name: jarm-fingerprint-review
description: 审阅玄鸟当前Run的JARM相似性证据，明确授权后才尝试受控TLS指纹采集。
---

# JARM关联审阅

先离线 `assetops export-signals RUN_ID` / MCP `export_signals(run_id)`。读取 `data_root/runs/RUN_ID/signals/jarm.json` 的 `data.results`；公共字段schema_version、run_id、kind、status、warnings必须检查，assets.json读取data.assets。

JARM要求合法62位格式，过滤全零值；缺失不代表安全。相同JARM仅为低置信度服务相似性，不证明组织归属、漏洞或恶意性质。MCP `list_relations(relation_type="same_jarm")` 可能含其他Run，须与当前Run资产、观测交叉核对。

主动默认关闭。显式配置 `ASSETOPS_HTTPX_ENABLED=true` 后，`httpx --jarm` 走Python受控标准10握手采集，不依赖外部httpx路径；普通httpx探活仍需配置绝对工具路径。核对handshakes_attempted/handshakes_completed、certificate_verified、fingerprint_version、truncated，握手不完整不得宣称完整指纹。仅在用户明确授权目标、额外TLS握手和预算后执行 `assetops httpx RUN_ID --jarm` 或 MCP `active_httpx(run_id, favicon=False, jarm=True)`。显式指纹模式只采指纹，普通探活需另行显式调用 `assetops httpx RUN_ID`。共享核心受控采集的多次TLS握手必须计入持久化预算；安全能力不足则skipped/unsupported，禁止用无约束外部httpx或其他命令代替。

不得自动触发外部引擎搜索、范围扩张、枚举、碰撞或漏洞利用。报告 `assetops export-report --run-id RUN_ID --format markdown`，不输出正文或密钥。
