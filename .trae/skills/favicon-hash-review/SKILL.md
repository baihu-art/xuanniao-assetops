---
name: favicon-hash-review
description: 审阅当前Run的favicon哈希关联线索，显式授权后才请求受控采集。
---

# favicon关联审阅

先离线 `assetops export-signals RUN_ID` / MCP `export_signals(run_id)`，读取 `data_root/runs/RUN_ID/signals/favicon.json` 的 `data.results`。核对schema_version、run_id、kind、status、warnings；资产清单仅在assets.json的data.assets。

favicon_hash可能是负数字符串，不能当作无效值丢弃。相同图标可能是通用模板，仅作为低置信度关联线索，不证明同一组织、漏洞或授权关系。可查询 MCP `list_relations(relation_type="same_favicon")`，但须以当前Run资产及观测交叉核对，不能把其他Run关系当成本次证据。

主动默认关闭。显式配置 `ASSETOPS_HTTPX_ENABLED=true` 后，`httpx --favicon` 走Python受控采集，不依赖外部httpx路径；普通httpx探活仍需配置绝对工具路径。仅用户明确授权目标、favicon额外请求及预算后执行 `assetops httpx RUN_ID --favicon` 或 MCP `active_httpx(run_id, favicon=True, jarm=False)`。显式指纹模式只采集指纹，不包含普通探活；需要探活时另行显式调用 `assetops httpx RUN_ID`。采集由共享核心的受控实现执行，无法证明请求、DNS与预算受控时应skipped/unsupported；不降级为无限制外部httpx执行、不自行安装未知二进制。

不得根据图标自动调用外部引擎搜索、扩大scope、枚举或碰撞；不导出正文、凭据。报告 `assetops export-report --run-id RUN_ID --format markdown`。
