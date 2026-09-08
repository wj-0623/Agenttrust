# AgentTrust v1.0.0 运维与演示手册

所有命令先在隔离环境执行。本轮没有执行删除数据库、删除卷或覆盖恢复。已有数据升级前必须备份并审批；不要使用 `docker compose down -v` 或向原数据目录恢复备份。

## 1. 本地启动

后端虚拟环境安装 `requirements-dev.txt`；前端 `npm ci`、`npm run build`。在 backend 下执行：

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8010
```

打开 `http://127.0.0.1:8010`。已有 `.env` 不会隐式读取，需显式加 `--env-file .env`。不要在非隔离网络以免认证的 development 模式启动。真实模型 Key 非演示必需。

开发环境验证真实纠错灰度：启动前配置 `AGENTTRUST_CORRECTION_AUTO_PROMOTE_DEVELOPMENT=false`。默认生产始终使用 canary；不要为演示而关闭生产门禁。

## 2. PostgreSQL 角色与迁移

- 首次 Compose 启动需要 POSTGRES_PASSWORD、POSTGRES_APP_PASSWORD、AGENTTRUST_BOOTSTRAP_TOKEN、AGENTTRUST_AUDIT_ANCHOR_SECRET，均使用不同的高熵随机值。数据库 DSN 中密码必须 URL 编码，模板建议使用 URL-safe 密码。
- `ops/postgres-init/010-agenttrust-app-role.sh` 只在空数据卷运行。已存在的卷需要 DBA 检查/创建 `agenttrust_app` 非超级用户角色，不能认为重启会执行初始化脚本。
- `migrate` 单次任务拥有 DDL 权限；API/Worker 只持应用角色凭据。生产 `AGENTTRUST_AUTO_INITIALIZE=false`。迁移当前是加法/兼容式初始化与版本记录，不提供自动 downgrade。
- 升级旧多工作空间共享项目时，迁移拒绝含混所有权，先由管理员确定唯一 workspace。不得用任意 MIN(workspace) 结果悄悄分配归属。
- 业务 RLS 基于 `app.current_workspace_id`，认证成员预查询基于 `app.auth_identity_id`，都在事务内 set_config。PgBouncer 使用 transaction 模式；psycopg 禁用服务端自动 prepare。
- 运行角色不能拥有受保护表、继承表所有者角色、使用超级用户/BYPASSRLS/CREATEROLE。启动校验覆盖预期业务表 ENABLE/FORCE RLS；更细的角色权限仍需 DBA 审核。
- RLS 假定应用认证上下文可信。SQL 注入/泄露数据库账号后可自行设置 GUC；需出站隔离、参数化 SQL、凭据轮换以及进一步拆分认证角色，不把 GUC 当密码。
- api_keys、api_usage_events、identities、organizations、workspaces 等引导/控制表当前不是完整数据库级租户隔离，授权还依赖服务层。

独立迁移：仅在迁移任务环境配置管理员 DSN，然后执行 `python -m app.migrate`。不要把管理员 DSN 留在 API 环境。

真实测试：只向专用测试库设置 `AGENTTRUST_TEST_RLS_ADMIN_URL`，执行 `python -m pytest tests/test_postgres_rls.py -q`。它会建测试角色和隔离租户，不删除资源；绝不能指向生产。普通本地测试的 3 个 skip 不是 RLS 验收通过。

## 3. 备份、WAL 与 PITR

PostgreSQL 18 镜像模板挂载 `/var/lib/postgresql`。旧版本若挂载 `/var/lib/postgresql/data`，需要先确认现有 PGDATA、版本与卷布局；不得盲目替换/移动旧卷。参见 [官方镜像说明](https://hub.docker.com/_/postgres)。

```powershell
docker compose --profile backup run --rm postgres-backup
```

该命令运行单次容器，备份保存在命名卷：新的唯一目录中执行 pg_basebackup，然后 pg_verifybackup；另生成 pg_dump 自定义格式及 manifest。`--rm` 仅移除本次一次性容器，不移除数据卷；如你的环境禁止移除容器，可省略该参数。备份脚本无文件清理/保留删除逻辑，需监测卷空间。

PITR 需要物理基础备份和连续 WAL，pg_dump 本身不能作为 PITR 基础。当前 archive_command 是基础模板，未实现异地备份、原子上传/fsync 完整验证和归档积压告警。推荐下一阶段采用 pgBackRest/Barman，而非将此脚本当完整备份平台。[PostgreSQL PITR](https://www.postgresql.org/docs/17/continuous-archiving.html)

恢复验收流程（本轮未执行）：校验基础备份及 manifest → 创建**全新**隔离卷/恢复实例 → 指定只读 WAL 源和恢复时间点 → 验证业务行数、关键订单、审计链、RLS 与登录 → 记录 RPO/RTO → 人工批准切流。任何清理/覆盖旧数据都要单独确认。

## 4. 初始化与身份

生产首次 `POST /api/v1/access/bootstrap` 必须带部署注入的 `X-AgentTrust-Bootstrap`。返回 API Key 仅一次，保存到 Secret Manager；初始化成功后移除/轮换 bootstrap token。OIDC 由固定 issuer/audience/JWKS 验证后映射已存在成员，不自动赋予高权限。

控制台“连接凭证”可输入 API Key 或 OIDC Bearer Token；多工作空间 OIDC 身份填写 Workspace ID。Token 只在内存中，刷新后重新连接。目前是令牌接入界面，不是完整 Authorization Code + PKCE 登录门户。

## 5. 纠错灰度演示

1. 生成 policy-only 修复候选，通过主集与 holdout，得到 correction_id、release.stage=canary。
2. 向 `/api/v1/gateway/invoke` 发送业务样本；响应 details 返回 cohort、release_id、release_traffic_id。用稳定 metadata.session_id 保持分桶；当前 session 仍由调用方提供。
3. 管理员向 `/api/v1/corrections/{correction_id}/canary-observations` 提交：

```json
{"traffic_id":"服务端返回的traffic_id","expected_action":"allow","reason":"人工审核：合法查询"}
```

4. 不要提交伪造的成功率/延迟。allow、block、approval_required 是支持的期望动作；重复 traffic 不增加样本。
5. 满足样本/时间/准确性/SLO 门槛后才晋级。误杀过高拒绝；晋级后 SLO 异常回滚。后续人工策略更新与旧回滚冲突返回 409，不覆盖新版本。

标注应通过带外受控数据集保存样本与人工结论。当前服务端采样表不存原始敏感 Prompt，浏览器也没有完整双人标注工作台。不要用本项目自身检测结果自动生成 ground truth。

## 6. 安全响应与外部导出

- `PUT /security/controls/kill-switch?project_id=...`（完整前缀 `/api/v1`），body 为 enabled/actor/reason；启用后阻止新网关/工具/退款/MCP/A2A 执行。已经分发的远端副作用无法由开关撤回。
- `POST /security/audit-anchors` 原子写入签名锚点及 Outbox。`POST /security/siem/export` 将当前事件排入投递队列。两者不是自动无限循环任务。
- `POST /security/outbox/deliver` 显式尝试至多 50 个 pending/failed。失败保留且只记录异常类型；投递可能重复，接收端须按 event_id 去重并验证 HMAC/时间窗口。当前没有指数退避、抢占租约、死信调度器。
- Webhook 需 URL 和独立签名 secret；生产 HTTPS、禁止重定向、DNS/IP 防 SSRF。仍需出站代理关闭 DNS 重绑定窗口。
- S3 可选 `pip install -r requirements-integrations.txt`，使用部署的 AWS 短期身份凭据链，显式配置桶和保留期。当前 API 镜像默认未安装可选 boto3，启用时须重建含该依赖的镜像。不要在仓库放 AWS Key。
- 写入前检查 Object Lock；COMPLIANCE 保留期具有强不可撤回性，使用前由管理员批准。测试不应向真实归档桶写入。当前未保存 VersionId/回读证明，也未自动归档完整审计事件。
- audit_anchors.exported 保持不可变 False；实际投递状态在 Outbox。仅签名/本地链不能抵御掌握签名密钥和数据库的同一攻击者；外部锚点由独立系统保管才形成另一信任域。

## 7. Temporal、Phoenix、检测模型

- v0.5 Workflow 参数改为 `{refund_id, workspace_id}`，默认队列 `agenttrust-refunds-v2`。旧队列在途工作流应由旧 Worker 完成，或实施 Temporal 版本路由；不要直接让新 Worker 接管旧历史。当前 24 小时审批超时未配运营告警/补偿台。
- Temporal 内网接口目前没有 TLS/mTLS/命名空间细分；不允许不可信服务直连并自行发起 Activity。真实支付未接入。
- OTel SDK 导出至配置端点；Phoenix 接收 Trace 依赖下游可用性，当前无 Collector 持久缓冲。Phoenix 仅供平台运维，不与租户隔离等同。
- `PHOENIX_BASE_URL` 配置后管理员可调用 `/observability/phoenix/{correction_id}/publish?project_id=...`。只上传内置回归案例和脱敏 Prompt，不自动上传客户 Trace。真实服务不配置时返回 not_configured。
- `/observability/replay/{trace_id}?project_id=...` 只回放已脱敏记录的策略决策，不复现原始模型环境/所有上下文，更不再次付款。
- 自托管检测服务设置 URL/key/required；POST 接收 `{text: ...}`，返回有限 score（0..1）和 model_version（其他字段以适配器为准）。required=true 时服务不可用则阻断。模型许可、权重、GPU 和独立准确性校准由部署方准备。默认不外传给商业分类器。
- MCP 对敏感参数保守拒绝，直到引入受控凭据代理；不要把脱敏后的参数误当作可直接执行的原始业务参数。

## 8. 商用验收停止线

只有配置文件/测试桩不算外部服务验收。上线前必须拿到：非超级用户 RLS 证据、完整恢复演练、支付幂等对账、OIDC 生命周期、网络隔离、WORM 回执、双人评测与误杀申诉、跨节点负载和故障注入结果。当前剩余缺口见 [交付记录](P0_P1_DELIVERY_2026-08-30.md)。
