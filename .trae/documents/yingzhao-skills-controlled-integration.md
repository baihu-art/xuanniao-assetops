# 英招七技能受控兼容计划

## 摘要

在现有玄鸟 AssetOps 核心上增量兼容英招七个 Skill，补齐五维评分、favicon/JARM 实际采集、Host 碰撞、子域名枚举。不是重写项目，但属于跨模块功能扩展，不是只复制 Skill 文档。

用户已选择：Host 碰撞和子域名爆破使用 Python 受控实现，不依赖 ffuf。保留 httpx 用于指纹采集。实现后只做离线验证，不执行真实目标探测，不修改现有授权和凭据，不提交或推送 Git。

## 当前状态分析

- `assetops/core/run_manager.py` 已统一编排 Provider、Run、独立 `execute_httpx` 步骤和持久化；CLI/MCP 应继续共用它。
- `assetops/active/httpx_probe.py` 已有绝对可执行路径、参数白名单、输出裁剪和可注入 subprocess，但未开启 favicon/JARM，字段别名和负数 favicon 处理不完整。
- `assetops/core/scope_guard.py` 支持域名、IP/CIDR、黑名单和路径规则；域名授权不等于任意连接 IP 授权，Host 碰撞需额外双重检查。
- `assetops/config/loader.py` 有默认关闭的 httpx 配置，需要扩展主动模块限额与安全配置视图。
- `assetops/models/asset.py` 的主键优先 IP:port，同 IP 多 Host 不能靠覆盖 Asset.host 保存，应保留完整 Observation。
- `assetops/recon/relations.py` 已支持 favicon_hash/jarm_hash 关系，但主动采集后需重新加载观测并刷新关系。
- `assetops/core/http.py` 的 Provider HTTP 客户端不直接用于任意主动 URL，避免继承自动重定向等不合适行为。
- 英招源目录 `.trae/skills/` 包含 asset-analysis、cyberspace-recon、favicon-hash-review、host-collision-review、httpx-review、jarm-fingerprint-review、subdomain-brute-review。其工作流和脚本存在 signals 的 assets/results 字段冲突，不原样搬运。

## 实施顺序与具体变更

### 1. 配置与统一主动边界

修改 `assetops/config/loader.py`、`assetops/core/scope_guard.py`，新增必要的 `assetops/active/transport.py`。

- 保留旧入口默认行为；新增 host_collision_enabled、subdomain_brute_enabled，默认 false；favicon/JARM 使用独立显式采集选项，不能通过被动 run 自动触发。
- 主动默认串行、每秒最多 2 次、每步最多 100 次连接尝试、每次超时 10 秒、响应读取上限 256 KiB；允许通过配置降低或显式提高限额。数值必须为正，且不得越过 Run 剩余主动预算。
- 为每 Run 持久化主动预算消耗，通过 RunStep 结构化字段记录请求/握手已预留及已使用量；涉及 `assetops/models/run.py` 和保存 Run 的现有查询路径。请求前预留，异常/重试/基线都计入；重复调用不得重置预算。并发同 Run 执行须互斥或原子预留。
- 新传输层使用标准库 http.client/socket/ssl，可注入解析器、连接器、时钟。仅 GET /，禁用代理、自动重定向、认证、Cookie、任意 Header 和任意路径；不复用 Provider 密钥。
- Host 碰撞连接 IP 必须显式匹配授权 IP/CIDR，Host 必须显式匹配域名白名单且不在排除项；二者均需通过。缺少 IP 授权时拒绝，不能拿历史 DNS 结果代替授权。
- 普通子域请求需域名匹配授权；解析所有候选地址后固定本次连接地址，禁止再次 DNS 解析，遵守显式 IP 限制；域名授权可访问其解析地址，但默认拒绝私网、回环、链路本地、组播等特殊地址，除非该地址另有明确 IP/CIDR 授权。HTTPS 使用候选域名作为 SNI 并正常校验证书。
- Host 碰撞 HTTPS 使用指定 Host 作为 SNI、固定授权 IP 连接；记录证书校验失败，不自动关闭 TLS 验证。
- 429/503 停止当前主动步骤并保留部分结果；不自动重试主动请求。超时/网络错误与零发现分开记录。

### 2. favicon/JARM 实际采集

修改 `assetops/active/httpx_probe.py`、`assetops/core/run_manager.py`、`assetops/recon/relations.py`。

- 使用类型化采集选项生成 -favicon、-jarm 和技术栈采集参数，禁止向用户开放任意 extra_args；shell=False，支持 Windows .exe 绝对路径，不把二进制加入仓库。
- 规范化 favicon/favicon_hash → favicon_hash，jarm/jarm_hash → jarm_hash；favicon 接受带符号整数并转字符串；JARM 检查格式、62位长度并过滤全零值。保持证据长度和敏感字段限制。
- 固定输入集合，对输出 input/url/地址重新检查，禁止跨输入资产污染或用重定向结果归属别的资产。
- 校验所支持 httpx 版本和安全能力：禁止跟随重定向，固定探测端口，限制速率、重试和工具总超时，校验 favicon 附加 URL 的访问边界。JARM 的多次 TLS 握手及 favicon 请求纳入保守上界预留。无法证明其附加请求、DNS或连接预算受控时，必须拒绝该模式并报告 unsupported，不能静默降级为无约束执行；如需补足，使用受控传输层采集 favicon、受控连接器执行 JARM 握手，保持同一字段契约。
- 采集结果存为 Observation；按当前 Run 重载资产和观测，刷新指纹关系；相同指纹仅为低置信度线索，不扩展 Scope。

### 3. 五维评分

新增 `assetops/analysis/scoring.py`，从 `assetops/core/run_manager.py` 暴露独立分析步骤。

- 以英招 `.trae/skills/asset-analysis/SKILL.md` 的实际评分分支为基线，抽取为纯函数、版本标记 yingzhao-v1；暴露度30、技术风险25、数据价值20、宽度15、独特性10，分值直接相加，不再乘权重。
- 保留源规则实际最高97分，不擅自补满100；高≥60、中≥35。报告同时展示理论满分100及规则实际最高97，避免误读。
- 每资产输出五项分数、总分、等级、规则命中理由、输入 Observation ID、缺失信息；未知不是安全证明，不根据产品名宣称已存在漏洞。
- 使用当前 Run 的观测，明确优先使用本次最新主动证据，再参考本次被动来源；禁止直接使用别的 Run 最新状态造成历史报告漂移。
- 评分结果以 analysis Observation 保存，更新 priority；重复分析依据输入证据和规则版本去重。Top20按主机取最高分。

### 4. Python Host 碰撞

新增 `assetops/active/host_collision.py`，RunManager 新增独立执行方法。

- 输入为当前 Run 已有授权 IP 和已有授权域名，可显式提供缩小后的候选列表；不自动生成全网目标。先去重并计算候选组合，超出预算只执行有界前缀并明确 limited。
- HTTP/HTTPS分别建基线；仅当随机 Host 仍在域名授权模式内时才发送随机基线，否则使用默认 Host 基线并标记置信度限制。所有基线计预算。
- 保存状态、内容长度、响应摘要哈希、标题和基线差异；不能只按长度认定命中，也不把相同403等直接当作有效站点。
- 结果区分 candidate/differential/unconfirmed，不宣称绕过成功；保留 (connect_ip, port, scheme, host, sni) 完整元组到 Observation，不覆盖合并资产的其他虚拟主机。

### 5. Python 子域名枚举

新增 `assetops/active/subdomain_brute.py`，RunManager 新增独立执行方法。

- 使用用户显式提供的本地 UTF-8 小字典路径或候选标签列表；不附带大型字典、不自动下载、不做递归枚举。逐标签校验合法域名，限制文件体积、条目数量并去重。
- 根域在 scope 内不代表所有子域在 scope 内；生成的每个完整候选名都必须单独通过域名授权检查。仅授权根域而无通配范围时，拒绝越界候选。
- DNS是独立阶段：使用可注入解析器，执行3个随机且授权的标签基线检测泛解析；泛解析结果只标候选，默认不把通配响应当作独立已验证资产。
- DNS命中可通过同一受控传输层执行显式开启的 HTTP 验证，区分 DNS发现、HTTP可达、HTTP差异；HTTP验证不自动转入指纹/Host碰撞。
- 新发现依现有模型入库，保存完整域名与 DNS/HTTP 证据，避免 IP 主键合并后丢失别名。

### 6. CLI/MCP、信号与七 Skill

修改 `assetops/cli.py`、`assetops/mcp_server.py`、`assetops/storage/queries.py`，新增必要的 `assetops/analysis/signals.py`。

- 两入口共享 RunManager，新增 analyze、host-collision、subdomain-brute、export-signals 命令及相应 MCP 工具；现有 httpx 入口增加 favicon/jarm 显式布尔参数。工具描述写清主动性质、限额与所需授权。
- 对 disabled/missing-tool/missing-wordlist 返回明确 skipped 或参数错误；运行失败不能伪装成0发现成功。步骤结果支持部分完成、预算停止和错误摘要，保留已完成结果。
- 信号统一使用 schema_version、run_id、kind、status、data、warnings；data 内固定 assets/results 语义，不沿用英招相互冲突的读取方式。先保证玄鸟七技能内部一致，不声称任意旧英招脚本可直接执行。
- export-signals 将已有数据原子导出至该 Run 的受控数据目录，分别输出资产、httpx、favicon、JARM、碰撞、子域、评分信号；不触发网络。所有查询按 Run 过滤并分页，敏感信息和响应正文不导出。
- 现有 Markdown/JSON 报告加入五维评分、指纹关联和候选验证状态，保持表格转义；不改造成新的前端。
- 在 `.trae/skills/` 新建七个相应 SKILL.md，以英招工作流意图改写为玄鸟 MCP/CLI 调用；移除 Bash/curl/dig/ffuf 内嵌执行和硬编码绝对目录。指纹相似性仅做范围内关联；不得自动触发枚举或未授权引擎搜索。
- 保留 `.trae/skills/assetops-development/SKILL.md`，只更新本次新增模块对应开发约束。只修改必要配置模板（如仓库已有 .env.example），绝不读取或写入真实 .env。

## 假设与范围决策

- 兼容定义是七 Skill 的受控工作流和可解释结果，不是复制英招所有脚本、命令参数和历史 signals 文件。
- 保留现有数据库实体与 Run 模型，新增结构化预算字段时提供向前兼容加载；尽量用 Observation 扩展证据，不做资产主键全局重构。
- 不增加全网检索、自动递归、漏洞利用、截图系统或大型字典管理；已有 Provider 查询模式不在本次扩展为任意查询语法。
- 不默认复用用户机器上的未知二进制；工具配置和安全能力不符合要求时明确拒绝，不假称模块可安全执行。
- 本次授权仅为开发和离线测试，不构成任何真实域名/IP的探测授权。

## 验证步骤

1. 扩展已有 `tests/test_httpx_probe.py`、`tests/test_scope_guard.py`；为评分、主动传输、枚举、入口及信号增加必要测试。全部用 fixtures、假解析器、假连接器、假 subprocess，无真实网络。
2. 评分固定样本覆盖所有源规则优先顺序、五维分数、最高97、35/60边界、未知数据、Top20、重复运行及跨Run隔离。
3. 指纹测试覆盖负数favicon、字段别名、无效/全零JARM、缺工具/不支持版本、禁止参数、范围外favicon、输出污染、预算不足与关系刷新。
4. 主动边界覆盖域名排除、IP未授权、DNS重绑定、IPv6、多地址、特殊地址、禁止路径、重定向不跟随、HTTPS SNI、TLS失败、响应大小、超时、429/503、基线与重试计预算、跨步骤/重复调用预算和并发预留；越界必须零连接。
5. 枚举覆盖泛解析、多Host同IP不丢失、随机基线越界拒绝、零长度响应、相同403不误报、字典非法标签、缺字典、限额和部分完成。
6. 运行 `python -m pytest -q`，执行注入假传输的 CLI/MCP 核心闭环：Mock Run → 探活/指纹 → 枚举 → 分析 → list_assets/list_relations → 导出报告与信号；核对stdout不污染MCP协议。
7. 完成交付时列出新增命令、配置开关和七Skill使用方法，明确离线测试结果、未安装工具和未做真实网络验证项。不得用删除用户数据规避测试失败。
