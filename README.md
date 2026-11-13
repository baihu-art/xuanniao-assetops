# 玄鸟 AssetOps

玄鸟 AssetOps 是一个面向**明确授权目标**的资产收集、归一化、关联与分析工具。它提供统一的 Python 核心服务、CLI 和 MCP 接口，支持被动资产发现、HTTP 探活、favicon/JARM 指纹、Host 碰撞候选验证、子域名枚举、五维评分和结构化信号导出。

> 仅对你拥有或明确获得授权的域名、IP 和 CIDR 使用。AssetOps 不执行漏洞利用、爆破登录或破坏性操作。

## 功能概览

- 被动 Provider：Mock、FOFA、Quake、Hunter、Shodan，以及可配置的被动 JSON 接口。
- 授权范围：通过 `scope.json` 强制校验域名、IP、CIDR 和禁止路径。
- 数据管理：SQLite 保存 Run、Step、Asset、Observation 和关系；原始响应单独归档。
- 主动能力：受控 HTTP 探活、favicon 哈希、JARM、Host 碰撞和子域名枚举。
- 分析能力：基于当前 Run 证据的 YingZhao v1 五维评分。
- 输出：Markdown/JSON 报告和七类结构化信号。
- 接口：命令行 CLI 和 MCP Server 共用同一套核心逻辑。

## 环境要求

- Python 3.11+
- Windows、Linux 或 macOS
- 主动 HTTP 探活如需使用外部 httpx，需要单独安装并配置其绝对路径；favicon/JARM 使用 Python 受控采集器。

## 安装

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Linux/macOS：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
```

## 配置

复制配置模板：

```powershell
Copy-Item .env.example .env
Copy-Item scope.example.json scope.json
```

编辑 `.env`，至少确认基础项：

```dotenv
ASSETOPS_DATA_ROOT=./data
ASSETOPS_SCOPE_FILE=./scope.json
ASSETOPS_TIMEOUT=30
ASSETOPS_RATE_LIMIT=5
ASSETOPS_BUDGET_MAX=10000
ASSETOPS_INSECURE_TLS=0
```

`ASSETOPS_INSECURE_TLS` 默认为 `0`，仅在受控测试环境中针对自签名证书的授权目标临时开启。

### Provider 凭据

只有填入对应凭据的 Provider 才会实际发起查询，其余步骤标记为 `skipped`：

```dotenv
FOFA_EMAIL=your_email@example.com
FOFA_KEY=your_fofa_api_key
QUAKE_TOKEN=your_quake_token
HUNTER_KEY=your_hunter_api_key
SHODAN_KEY=your_shodan_api_key
```

### 被动 JSON 接口（可选）

除内置 Provider 外，还可以接入 DNS、CT、WHOIS、ASN 的被动 JSON 接口。不填写对应的 `*_ENDPOINT` 时该 Provider 不启用：

```dotenv
PASSIVE_DNS_ENDPOINT=
PASSIVE_DNS_KEY=
CT_ENDPOINT=
CT_KEY=
WHOIS_ENDPOINT=
WHOIS_KEY=
ASN_ENDPOINT=
ASN_KEY=
```

DNS 与 CT 的 KEY 可选；WHOIS 与 ASN 必须同时提供 `ENDPOINT` 和 `KEY` 才会被识别为已配置。KEY 以 `Authorization: Bearer` 形式发送。

将实际授权目标写入 `scope.json`。例如：

```json
{
  "version": 1,
  "targets": [
    {
      "name": "example-corp",
      "domains": ["example.com", "*.example.com"],
      "cidrs": []
    }
  ],
  "rules": {
    "out_of_scope_domains": [],
    "prohibited_paths": ["/admin/logout"],
    "max_recursion_depth": 1
  }
}
```

`scope.json` 和 `.env` 默认被 Git 忽略，避免把本地授权范围或凭据提交到仓库。真实 API 密钥只放在本地 `.env`，不要写入代码、报告或提交记录。

查看脱敏配置：

```bash
assetops config
```

## 快速开始：Mock 离线测试

Mock 不访问网络，适合验证 Run、入库、评分和报告闭环：

```bash
assetops scope-check example.com
assetops run example.com --providers mock
```

命令输出会包含 Run ID。使用 Run ID 执行离线分析和导出：

```bash
assetops analyze <RUN_ID>
assetops export-signals <RUN_ID>
assetops export-report --run-id <RUN_ID> --format markdown
assetops list-assets --json
assetops runs --run-id <RUN_ID>
```

数据默认写入：

```text
data/assetops.db
data/archives/
data/runs/<RUN_ID>/report.md
data/runs/<RUN_ID>/signals/
```

## 被动资产发现

默认建议先使用 Mock，再根据授权和凭据选择 Provider：

```bash
assetops run example.com --providers mock
assetops run example.com --providers fofa,quake,hunter,shodan
```

Provider 行为：

- 缺少凭据时标记为 `skipped`，不会伪装成成功发现 0 个资产。
- API 错误、超时和限流会保留失败原因或部分完成状态。
- 每条结果都会再次执行 ScopeGuard 过滤。
- 真实 Provider 的网络请求必须由用户明确授权，并且需要相应 API 凭据。

常用查询：

```bash
assetops list-assets --domain example.com --limit 50
assetops list-assets --priority high
assetops runs
assetops export-report --run-id <RUN_ID> --format json
```

## 主动模块

主动能力默认关闭，不会因为被动发现、favicon 或 JARM 相似性自动扩大授权范围。所有主动步骤都需要已有 Run、明确开关、范围校验和剩余预算。

### HTTP 探活、favicon 和 JARM

```dotenv
ASSETOPS_HTTPX_ENABLED=1
ASSETOPS_HTTPX_PATH=C:\\tools\\httpx.exe
ASSETOPS_HTTPX_MAX_TARGETS=100
ASSETOPS_HTTPX_OUTPUT_LIMIT=100
```

```bash
assetops httpx <RUN_ID>
assetops httpx <RUN_ID> --favicon
assetops httpx <RUN_ID> --jarm
```

`--favicon` 和 `--jarm` 必须显式指定；JARM 的 TLS 握手也计入主动预算。

### Host 碰撞

Host 碰撞需要域名和连接 IP 均在授权范围内，并且需要显式启用：

```dotenv
ASSETOPS_HOST_COLLISION_ENABLED=1
```

```bash
assetops host-collision <RUN_ID> --hosts app.example.com api.example.com --ips 192.0.2.10
```

### 子域名枚举

子域名枚举需要显式启用，并且必须提供小型标签列表或本地字典：

```dotenv
ASSETOPS_SUBDOMAIN_BRUTE_ENABLED=1
```

```bash
assetops subdomain-brute <RUN_ID> example.com --labels dev staging --verify-http
assetops subdomain-brute <RUN_ID> example.com --wordlist ./small-wordlist.txt
```

候选会逐条进行授权校验；HTTP 验证必须通过 `--verify-http` 显式开启。请不要对未授权目标使用大字典或高并发。

主动限额由以下变量控制，括号内为默认值；任一值必须为正，实际用量不得超过 Run 的剩余主动预算：

```dotenv
ASSETOPS_ACTIVE_RATE_LIMIT=2               # 每秒最多请求数
ASSETOPS_ACTIVE_MAX_REQUESTS=100           # 每步最多连接尝试
ASSETOPS_ACTIVE_TIMEOUT=10                 # 单次连接超时（秒）
ASSETOPS_ACTIVE_MAX_RESPONSE_BYTES=262144  # 单个响应读取上限（256 KiB）
```

主动步骤当前串行执行，不提供并发配置项。

## 五维评分

评分只使用当前 Run 已保存的观测，不联网、不证明漏洞。执行：

```bash
assetops analyze <RUN_ID>
```

当前规则为 `yingzhao-v1`，包含暴露度、技术风险、数据价值、宽度和独特性五个维度。理论满分 100，受证据规则约束时实际最高为 97。评分结果会作为 `source=analysis` 的观察保存。

## 结构化信号和报告

```bash
assetops export-signals <RUN_ID>
assetops export-report --run-id <RUN_ID> --format markdown
assetops export-report --run-id <RUN_ID> --format json
```

信号文件位于 `data/runs/<RUN_ID>/signals/`，包含资产、HTTP、favicon、JARM、Host 碰撞、子域名和分析信号。信号带有 `schema_version`、`run_id`、`kind`、`status`、`data` 和 `warnings` 字段，并且只包含指定 Run 的数据。

## MCP Server

MCP Server 与 CLI 共用核心服务。安装依赖后可通过：

```bash
python -m assetops.mcp_server
```

主要工具：

- `check_scope`
- `create_run`
- `recon_domain`
- `list_assets`
- `list_relations`
- `get_run_state`
- `active_httpx`
- `analyze`
- `host_collision`
- `subdomain_brute`
- `export_signals`
- `export_report`

MCP 工具返回摘要，大结果写入 SQLite 或 Run 输出目录；主动工具不会绕过 ScopeGuard 或预算限制。

## 测试

运行完整离线测试：

```bash
python -m pytest -q
```

测试覆盖 Mock Provider、ScopeGuard、分页和错误处理、主动预算、HTTP fixture、favicon/JARM、评分、信号导出、报告和 CLI/MCP 相关流程。除非用户明确提供授权目标、Provider、凭据和验证范围，否则不执行真实网络验证。

## 安全边界

- 只处理明确授权范围内的目标。
- favicon、JARM 和其他相似性只能作为授权范围内的关联线索，不能自动扩展范围。
- 不自动利用漏洞、不进行登录爆破、不进行破坏性操作。
- 所有 Provider 请求前和主动候选验证时都执行服务端范围校验。
- 配置视图、错误信息、报告和信号不得输出真实凭据。
- 没有真实网络证据时，只报告 Mock、fixture 或离线分析结果。

## 项目结构

```text
assetops/
├── active/       受控 HTTP、favicon、JARM、Host 碰撞、子域名模块
├── analysis/     五维评分和信号/报告导出
├── config/       环境变量和配置加载
├── core/         Run 编排、范围校验和公共 HTTP
├── providers/    Mock、FOFA、Quake、Hunter、Shodan 等 Provider
├── storage/      SQLite 和原始归档
└── mcp_server.py MCP 接口

tests/             离线测试
scope.example.json 授权范围模板
.env.example      环境变量模板
```

## 许可证

MIT
