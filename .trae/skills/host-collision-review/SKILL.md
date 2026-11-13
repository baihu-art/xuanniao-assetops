---
name: host-collision-review
description: 审阅当前Run的Host碰撞候选差异，仅显式双重授权后进行Python受控验证。
---

# Host候选差异审阅

默认离线 `assetops export-signals RUN_ID` / MCP `export_signals(run_id)`，读取 `data_root/runs/RUN_ID/signals/host_collision.json` 的 `data.results`。核对schema_version、run_id、kind、status、warnings；assets.json读取data.assets。

主动默认关闭。先获得用户对连接IP/CIDR与域名两者的明确授权、动作和限额；域名授权或历史DNS不能代替IP授权。仅当前Run已有候选，显式列表只能缩小：`assetops host-collision RUN_ID --hosts app.example.com --ips 203.0.113.10`；MCP `host_collision(run_id, hosts=["app.example.com"], ips=["203.0.113.10"])`。示例不是实际目标授权。

由服务端Python受控传输执行，不使用ffuf/curl，不自定义Header/路径，不关TLS验证、不跟重定向。基线也计预算；429/503应停止，limited/失败/部分完成如实报告。

保留connect_ip、port、scheme、host、sni完整元组。比较状态码、摘要、标题与长度，不只按长度判断；相同403不是有效命中。candidate/differential/unconfirmed均不证明绕过成功。缺基线或受限基线降低置信度。不得自动扩展到枚举或外部搜索，不导出响应正文、凭据。
