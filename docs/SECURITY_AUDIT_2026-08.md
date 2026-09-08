# AgentTrust 安全与架构审计（2026-08）

> **历史快照（2026-08）**：本文保留原始审计过程，部分问题已在后续版本修复。当前实现和剩余边界见 [Portfolio Evidence](PORTFOLIO_EVIDENCE.md) 与 README，不应把本文件的旧状态当作 v1.0.0 结论。

> 2026-08-29 v0.4 更新：本文早期“SQLite-only、OIDC 未验签、OTel-shaped、Temporal 未接入”等结论已被本轮实现取代。当前生产路径已支持 PostgreSQL、严格 OIDC/JWKS、OTel/Phoenix 和 Temporal 退款 Worker；最新边界与待办以 `PRODUCTION_ARCHITECTURE.md` 为准。

## 审计范围

- FastAPI API、SQLite 数据边界、React 控制台与 Docker 默认配置。
- Gateway、Policy、MCP、A2A、Sandbox、Workflow、Access Control、Observability 和 Auto-Correction。
- Python/npm 依赖漏洞、静态质量、安全扫描、并发与跨租户回归。

## 已确认并修复

| 等级 | 问题 | 修复 |
|---|---|---|
| Critical | 任意非空 approval token 可绕过工具审批 | 外部 token 不再影响 Gateway；MCP 副作用调用必须原子消费真实 Capability Lease |
| Critical | Starlette/pytest 版本包含 9 条公开漏洞 | 升级 FastAPI、Starlette、Pydantic、Uvicorn、pytest；pip-audit 复查为 0 |
| High | API Key 有 Scope 但缺少 Workspace 资源边界 | 中间件提取项目/资源归属并执行租户授权；项目列表和 Access Summary 按 Workspace 过滤 |
| High | Capability Lease 校验和标记分离，存在并发重放窗口 | 使用 `BEGIN IMMEDIATE`，在同一事务中校验约束并抢占消费 |
| High | MCP/A2A SSRF 仅识别字面私网地址 | 禁止 URL 内嵌凭据，校验 DNS 所有解析地址，并拒绝 private/loopback/link-local/reserved/multicast/unspecified |
| Medium | 上游可返回无限响应体 | 流式读取并执行可配置字节上限 |
| Medium | 生产 Compose 没有强制认证 | 生产默认 `AGENTTRUST_REQUIRE_API_KEY=true`，并关闭 Docs/OpenAPI |
| Medium | Bootstrap 首 Key 存在竞争窗口 | Bootstrap 检查与写入放入 SQLite 立即事务 |
| Medium | 模型异常文本直接返回 | 客户端只收到稳定脱敏错误；详细诊断保留在受控服务端边界 |
| Medium | 缺少持续安全门禁 | 增加 Ruff、Bandit、pip-audit、npm audit、GitHub CI 和 Dependabot |
| Low | 大请求、Clickjacking、MIME sniffing 等基础防护缺失 | 增加请求上限、Request ID 和基础安全响应头，修正 wildcard CORS credentials |

## 验证证据

- pytest：11 组集成/安全测试通过。
- Ruff：通过。
- Bandit：通过，0 finding。
- pip-audit：0 已知漏洞。
- npm audit（production）：0 已知漏洞。
- TypeScript 类型检查和 Vite production build：通过。
- 新增回归覆盖：伪造审批、并发 Capability 重放、租户越权、SSRF 特殊地址、超大请求。

## 仍然存在的边界

1. DNS 检查与实际连接之间仍存在很小的 DNS rebinding 时间窗。生产环境必须在 egress proxy、NetworkPolicy 或防火墙重复执行目标地址策略。
2. SQLite 与进程内限流不适合多实例强一致生产部署。建议迁移 PostgreSQL + Redis，并使用数据库 RLS 作为第二层租户隔离。
3. OIDC 当前只有配置展示，没有 JWKS 获取、JWT signature/issuer/audience 验证和 SCIM。
4. Sandbox 是注册 Adapter 隔离，不是恶意代码隔离；不能将任意用户代码接入当前执行器。
5. OTLP JSON 的时间字段和 Span 结构是兼容方向，不等于完整 OTLP protobuf exporter。
6. A2A 尚未验证 JWS Agent Card；MCP 尚未实现 OAuth 2.1 resource/audience 验证和 token passthrough 禁止链路。
7. Policy 仍以确定性规则为主，对语义变体、跨模态攻击和长上下文间接注入需要独立 Guardrail 模型与持续红队数据。

## 参考开源系统后的优先建议

### 下一批 P0

- 原生 OpenTelemetry SDK + Collector，并对接 Phoenix 或 Langfuse，实现嵌套 Span、Prompt 版本、Trace 评分和回放实验。
- PostgreSQL RLS + Redis 限流/预算预留，消除单机控制面限制。
- OIDC/JWKS、Key revoke/rotate、审计导出和组织级管理员模型。
- A2A 1.0 JWS/JCS Agent Card 验签、securitySchemes、HTTPS/mTLS 与凭据绑定。

### P1

- Promptfoo/garak 外部红队适配器、基于轨迹的 tool-use grader 和 CI 安全基线比较。
- Temporal Worker 适配层、Activity heartbeat、真正的重试策略和补偿 Activity。
- MCP OAuth 2.1、动态 Client Registration、token audience 校验、禁止 token passthrough。
- Prompt Registry：版本、标签、发布审批、实验对照和一键回滚。

### P2

- Docker/gVisor/Firecracker/WASM 工具运行时和 egress sidecar。
- PII/DLP、Secret Scanner、内容来源 Provenance 与审计日志哈希链。
- SLO/告警、Webhook、SIEM 导出、策略仿真和异常成本检测。
- Agent Registry、能力搜索、信誉评分和跨组织联邦策略。

## 主要开源参考

- Temporal Python SDK：https://github.com/temporalio/sdk-python
- OpenTelemetry GenAI conventions：https://github.com/open-telemetry/semantic-conventions-genai
- Arize Phoenix：https://github.com/Arize-ai/phoenix
- Langfuse：https://github.com/langfuse/langfuse
- NeMo Guardrails：https://github.com/NVIDIA-NeMo/Guardrails
- garak：https://github.com/NVIDIA/garak
- MCP-scan：https://github.com/invariantlabs-ai/mcp-scan
- Promptfoo：https://github.com/promptfoo/promptfoo
- A2A specification：https://github.com/a2aproject/A2A
- MCP specification：https://github.com/modelcontextprotocol/modelcontextprotocol
