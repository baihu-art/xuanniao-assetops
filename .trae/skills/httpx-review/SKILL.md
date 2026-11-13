---
name: httpx-review
description: 审阅玄鸟当前Run探活证据；仅在显式授权后执行受控httpx主动步骤。
---

# HTTP探活审阅

默认只读取已有信号。确认Run ID，离线执行 `assetops export-signals RUN_ID` 或 MCP `export_signals(run_id)`。读取 `data_root/runs/RUN_ID/signals/httpx.json` 的 `data.results`，核对schema_version、run_id、kind、status、warnings；资产映射读取assets.json的data.assets。

主动默认关闭，须显式配置 `ASSETOPS_HTTPX_ENABLED=true`；普通httpx探活还需外部httpx绝对路径。`--favicon`/`--jarm` 则由Python受控采集、不依赖外部路径，且只采指纹不包含普通探活。只有用户明确授权目标、HTTP探测及限额后，才执行 `assetops httpx RUN_ID` 或 MCP `active_httpx(run_id, favicon=False, jarm=False)`。不得追加任意命令参数或绕过服务端范围/预算控制，不自动开启favicon/JARM。缺工具、disabled、unsupported是skipped，不伪装成功；部分完成和预算停止保留已有证据。

解释状态码、标题、服务端及技术栈；禁止导出响应正文、Cookie、认证信息或密钥。重定向不得扩展授权范围。可用 `assetops export-report --run-id RUN_ID --format markdown` 生成当前Run报告。不得自动串联枚举、碰撞、外部搜索或漏洞利用。
