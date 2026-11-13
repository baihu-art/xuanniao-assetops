---
name: subdomain-brute-review
description: 审阅玄鸟子域名DNS候选；仅用户明确授权后用小字典受控枚举，可单独显式HTTP验证。
---

# 子域名枚举审阅

默认离线 `assetops export-signals RUN_ID` / MCP `export_signals(run_id)`，读取 `data_root/runs/RUN_ID/signals/subdomain_brute.json` 的 `data.results`。核对schema_version、run_id、kind、status、warnings；assets.json使用data.assets。

主动默认关闭。获得用户对候选域名、DNS枚举与预算的明确授权后，选择一种输入：`assetops subdomain-brute RUN_ID example.com --labels www api` 或 `assetops subdomain-brute RUN_ID example.com --wordlist ./small-labels.txt`。MCP对应 `subdomain_brute(run_id, domain="example.com", labels=["www", "api"], verify_http=False)`；本地字典可用wordlist参数代替labels。示例域名不构成授权。

只允许显式提供的本地UTF-8小字典或标签；不下载字典、不递归、不用dig/ffuf。每个完整候选与随机泛解析基线必须单独通过scope；只授权根域不代表子域通配授权。缺字典应参数错误，不伪装零发现。

DNS命中、HTTP可达、HTTP差异必须区分；泛解析或基线不足保持candidate，不宣称独立已验证资产。HTTP验证需另获明确授权后加 `--verify-http` 或MCP `verify_http=True`；不能自动串联指纹、碰撞或外部搜索。保留同IP的多个完整域名、有限额/部分完成证据，不导出正文、密钥。
