---
name: assetops-development
description: Develop and maintain the 玄鸟 AssetOps authorized asset-discovery project. Use when implementing providers, MCP or CLI flows, scope enforcement, storage, tests, or reviewing related changes. Do not use for real target scanning without explicit authorization.
---

# 玄鸟 AssetOps Development

在 `D:\github\xuanniao-main` 中维护玄鸟 AssetOps。遵循“模型负责规划，Python 服务负责精确执行，服务端强制安全校验”的边界。

## 安全与范围

- 只处理明确授权的域名、IP 和 CIDR；默认拒绝没有 scope 配置的目标。
- 每个 Provider 在发起请求前都必须校验目标，不要依赖模型先调用 `check_scope`。
- 仅做被动资产发现、HTTP 探活、指纹、关联、分类和报告；不自动利用漏洞、不进行破坏性操作。
- favicon、JARM 等相似性只能作为授权范围内的关联线索，不能扩展授权范围。
- 不读取、提交或输出真实凭据；配置视图和错误信息必须脱敏。
- 没有真实网络证据时，只报告离线测试、导入检查或 Mock 验证结果，不声称真实 API 已跑通。

## 项目结构与实现约定

- MCP 和 CLI 必须共用 `assetops` Python 核心服务，不在入口层复制业务逻辑。
- 主要模块包括：
  - `assetops/core/scope_guard.py`：授权范围检查。
  - `assetops/core/http.py`：公共 HTTP、限速、429 有界退避和数据清洗。
  - `assetops/providers/base.py`：Provider 抽象接口与 Asset/Observation 构造。
  - `assetops/providers/`：Mock、FOFA、Quake、Hunter、Shodan Provider。
  - `assetops/core/run_manager.py`：Run 状态、Provider 编排、归一化、持久化。
  - `assetops/storage/`：SQLite 和原始归档。
  - `assetops/recon/normalizer.py`：合并、去重和优先级排序。
- 使用 Python 3.11+、dataclasses、SQLite、pytest；优先复用现有接口，不为一次性操作新增抽象。
- Provider 必须继承 `BaseProvider`，使用注入的 `AssetOpsConfig` 和 `self._http`，实现 `is_configured()` 与 `search()`。
- Provider 查询必须有最大页数、请求超时、速率限制和有限重试；结果逐条执行授权过滤，并保存来源、证据和置信度。
- Asset 与 Observation 分离。持久化时使用 `upsert_asset()` 返回的数据库真实资产 ID，再插入 Observation，避免重复 Run 的外键错误。
- 原始响应和归一化资产要区分归档；大结果应返回摘要和分页，而不是无界地返回全部内容。
- SQLite 启用 WAL 与外键；避免把 `executescript` 和手工事务控制混用。数据库和临时资源在测试中显式关闭。

## Provider 迁移规范

迁移英招 `D:\github\YingZhao-main\.trae\scripts\cyberspace_collect.py` 时，保留 API 请求意图但不要盲信旧实现：

- FOFA 使用 `qbase64`、分页和字段解析。
- Hunter 使用 URL-safe Base64 查询和 `search` 接口。
- Quake 使用 `X-QuakeToken`、POST 查询、分页和服务字段解析。
- Shodan 使用 hostname 搜索；额度或计划受限时可使用 DNS 结果作为低置信度降级。
- 先使用不联网的 HTTP fixture/mock 测试覆盖成功、分页、API 错误、429、越界过滤和降级分支，再考虑有明确授权的真实 API 验证。
- 对迁移代码特别检查 host/URL/path、IPv6、分页边界、非 dict 响应、HTTPError 响应正文和敏感信息泄露。

## 状态、失败与报告

- Provider 缺凭据应是 `skipped`；API 或网络失败不能伪装成成功的 `fetched 0 assets`。
- 保留失败原因和部分完成状态；不要在统一收尾逻辑中覆盖 skipped/failed 的摘要。
- `budget_max`、取消、恢复和 Run 过滤必须在实际实现前明确测试边界。
- 报告按 Run 过滤，Markdown 表格内容需转义；报告和归档使用原子写入。
- CLI 参数必须真正传给 `create_run`；MCP 工具命名不得覆盖导入的存储查询函数，Provider 不应向 stdout 打印污染 stdio 协议。

## 验证流程

修改后至少执行：

1. `python -m pytest -q`
2. 必要时执行导入检查和仅 Mock 的 CLI/MCP 闭环。
3. 对真实 Provider 只做离线 mock HTTP 测试，除非用户明确提供授权目标、Provider、凭据和验证范围。
4. 在交付中明确列出已验证和未验证项；不删除数据库或其他用户数据来绕过失败。

引用代码时使用 `file:///D:/github/xuanniao-main/...` 链接；交互和解释使用中文。
