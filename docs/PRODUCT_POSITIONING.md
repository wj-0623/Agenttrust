> 当前产品定位以 v1.0.0 Portfolio Release 为准。个人配置、人工发布与评测边界见 [PERSONAL_USE.md](PERSONAL_USE.md)，可复核证据见 [PORTFOLIO_EVIDENCE.md](PORTFOLIO_EVIDENCE.md)。下文的企业能力仍是参考实现，不代表生产验收。

# AgentTrust 产品定位与人工评审说明

## 一句话定位

AgentTrust 是部署在业务 Agent 与模型、工具、MCP Server、远程 Agent 之间的“Agent Security Runtime 与可信自动纠错 SaaS”。它不是新的聊天机器人框架，也不是通用 RAG 平台；首个业务演示是客服退款，解决 Agent 上线后能否被约束、追踪、评测、纠错、审批和审计。

## 目标客户与核心价值

- 平台团队：统一接入多个 Agent/模型/工具，减少每个业务重复建设治理能力。
- 安全团队：把 Prompt Injection、工具越权、MCP 投毒、A2A 不可信消息和数据泄漏转化为可执行策略。
- Agent 研发团队：通过轨迹、评测集、红队扫描和失败聚类定位问题，并验证修复是否真的提升质量。
- 管理者：通过租户、权限、预算和审计记录获得可解释的上线依据。

## 当前完整功能

### 1. Agent Runtime Gateway

- 接收 Demo 或 OpenAI-compatible Agent 请求。
- 输入、外部上下文、工具选择、输出四个阶段执行策略。
- 记录状态、风险等级、质量分、延迟、Token、成本和策略版本。
- 对异常返回脱敏后的公共错误，不把上游异常细节直接暴露给调用方。

### 2. Policy-as-Code 与人工审批

- 工具 allow/deny/approval 三态控制。
- Prompt Injection、凭据模式和敏感输出检测。
- 审批不再信任调用方提交的任意字符串；只有系统内部已验证的 Capability Lease 才能放行。
- 高风险工具批准绑定具体项目、工具、参数摘要、金额上限、TTL，并且只能使用一次。

### 3. MCP Security Gateway

- 注册和扫描 MCP Manifest，固定 Hash 与历史快照。
- 检测工具描述投毒、隐藏行为、审批绕过、Tool Shadowing、Schema 变化和 Rug Pull。
- JSON-RPC 方法白名单、工具参数检查、请求前策略判断、响应后敏感信息检查。
- 出站地址执行 SSRF 校验；限制上游响应大小；副作用调用消费真实的一次性 Capability Lease。

### 4. A2A Security Gateway

- 注册 Agent Card，验证来源、技能声明和恶意指令。
- Card Hash Pinning、版本 Diff 和运行期 Rug Pull 隔离。
- 跨 Agent 消息按不可信输入检查，限制允许的 JSON-RPC 方法。
- 出站 SSRF 校验和响应体大小限制。

### 5. Customer Refund Security 与 Durable Workflow

- 客户/订单/币种/可退金额验证、Prompt Injection 拒绝、低风险自动处理和高风险人工审批。
- 生产退款使用 Temporal Workflow/Activity 和审批 Signal；SQLite 状态机保留为零依赖本地演示。
- 并发创建采用数据库唯一键；并发审批通过条件更新抢占，避免重复放行。
- 工作流、Gateway 和工具执行共享关联轨迹。

### 6. Sandbox 与 Capability Security

- 只执行代码注册的可信 Adapter，不接受任意 Shell、网络或文件系统调用。
- Calculator 使用 AST 白名单和计算预算，不使用 `eval`。
- Capability Token 只保存 Hash；参数校验与消费在同一事务中完成，阻止并发重放。
- 当前邮件、数据库和支付 Adapter 是模拟副作用，用于展示控制流程。

### 7. Evaluation、Red Team 与 Auto-Correction

- 可版本化评测数据集、规则 Grader、攻击召回率、精确率、误杀率和 Wilson 置信下界。
- 9 类红队插件及 direct、编码、跨语言变异策略。
- 对失败进行归因、聚类、生成受限策略补丁、独立回放、Shadow/Canary 门禁和不可变回滚。
- 自动发布只允许低风险 policy-only 修改；代码和 Prompt 类修复需要人工审核。

### 8. Observability

- Agent、模型、策略、工作流和工具 Span。
- 错误率、平均耗时和操作分布。
- 使用 OTel SDK 和批量 OTLP HTTP Exporter，可直接写入 Phoenix，并保留本地 Span 查询。

### 9. Enterprise Control Plane

- Organization、Workspace、Project、Identity、Membership、RBAC 和 PostgreSQL 存储。
- OIDC discovery/JWKS、固定算法、Issuer/Audience/时效校验；身份必须预先配置成员关系。
- API Key 只返回一次明文，数据库保存 SHA-256；支持 Scope、RPM 和月度预算。
- API Key 被限制在所属 Workspace，不能跨租户读取或调用其他项目。
- 生产 Docker 默认强制 API Key、关闭 API 文档；Bootstrap 使用数据库立即事务避免首 Key 竞争。

### 10. 工程与供应链

- Ruff、Bandit、pytest、TypeScript 和生产构建本地门禁。
- GitHub Actions 执行 Python/npm 漏洞审计与全量构建。
- Dependabot 每周维护 Python、npm 和 Actions 依赖。
- 请求体、上游响应体、CORS credentials、Request ID 和基础安全响应头已纳入控制。

## 功能成熟度说明

| 模块 | 当前状态 | 真实能力 | 尚未完成 |
|---|---|---|---|
| Gateway/Policy | 可运行 MVP | 确定性策略、真实模型适配、轨迹 | 多模型路由、语义 Guardrail 模型 |
| MCP/A2A | 可运行安全代理 | Manifest/Card 扫描、固定、消息与响应检查 | OAuth 2.1、mTLS、JWS、凭据代理、流式会话 |
| Workflow | 生产适配已接入 | Temporal 退款 Workflow/Activity/审批信号；本地状态机 | TLS、Build ID 路由、真实补偿 Activity |
| Sandbox | 可信 Adapter 模式 | 无任意代码入口、一次性能力租约 | 容器/WASM/gVisor 级隔离和网络 egress sidecar |
| Observability | OTel/Phoenix 已接入 | OTel SDK、OTLP exporter、本地 Span 与 Phoenix | Collector HA、SIEM/SOAR、SLO |
| Enterprise | 多租户 SaaS 基础 | PostgreSQL、租户隔离、OIDC/JWKS、API Key、限流、预算 | SCIM、Key 撤销轮换、PostgreSQL RLS |
| Auto-Correction | 离线闭环 MVP | 归因、回放、门禁、版本回滚 | 在线统计显著性、人工反馈学习、真实流量 Canary |

## 最值得人工修改的决策点

1. 产品主线已确定为 Agent Security；Reliability/Evals 作为证明安全策略有效的验证层。
2. 首个场景已确定为客服退款；下一步需确定真实支付提供商、退款政策和 PII/PCI 合规边界。
3. 自动纠错保留为核心差异化，并严格限定为通过统计门禁的策略与配置变更。
4. 多租户 SaaS 基础已完成；下一步是 PostgreSQL RLS、SCIM、审计保留策略和用量计费。
5. 人工产品决策重点转为：目标客户是安全平台团队还是业务 Agent 团队，以及首批商业部署的合规等级。
