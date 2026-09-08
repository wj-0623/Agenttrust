# AgentTrust 架构设计

> v0.4 已将产品主线收敛为 Agent Security 多租户 SaaS，并实现客服退款演示、PostgreSQL、OIDC/JWKS、OTel/Phoenix 与 Temporal。本文保留早期演进记录；最新生产架构见 `PRODUCTION_ARCHITECTURE.md`。

## 1. 产品边界

AgentTrust 位于业务 Agent 与模型、工具、外部数据之间。它不是新的聊天 Agent，而是生产 Agent 的控制平面。

```text
用户 / 业务系统
      │
      ▼
AgentTrust Gateway
  ├─ 输入防护：Prompt Injection、凭据与数据分类
  ├─ 工具策略：allow / deny / require approval
  ├─ 目标 Agent：Demo / OpenAI-compatible / Qwen
  └─ 输出防护：密钥、敏感数据、策略违例
      │
      ├─ MCP Security Gateway
      │   ├─ Manifest hash / Schema diff / Tool pinning
      │   ├─ Prompt poisoning / Tool shadowing / Rug pull scanner
      │   └─ JSON-RPC method、tool、argument 与 output enforcement
      ├─ A2A Security Gateway
      │   ├─ Agent Card origin / hash / skill pinning
      │   └─ Cross-agent message validation + task boundary
      ├─ Durable Workflow → approval pause / resume / retry / compensate
      ├─ Capability Sandbox → registered adapters only + one-time lease
      └─ Agent Spans → invoke_agent / workflow / policy / model / tool
      │
      ├──────────────► Trace + Audit
      ▼
业务结果

失败 Trace
  │
  ▼
Failure Classifier → Candidate Patch → Regression Replay → Promotion Gate
                                                   │
                               ┌───────────────────┴──────────────────┐
                               ▼                                      ▼
                     低风险策略自动发布                     Prompt/代码人工审核
```

## 2. 自动纠错为何不是“让 LLM 自己改自己”

生产系统中，未经约束的自动改 Prompt 或代码会扩大故障半径。本项目将纠错分成两类：

- **Policy-only**：新增拒绝特征、收紧工具权限等单调安全变化，可以自动发布。
- **Prompt/code change**：可能影响业务语义，只生成候选和回放材料，必须人工审核。

自动发布必须同时通过：

1. 修复置信度阈值；
2. 相对基线的质量提升阈值；
3. 正常请求与攻击请求混合回归集；
4. 补丁作用域必须为 `policy-only`；
5. 误杀率不能高于基线；
6. 项目必须显式开启 `auto_correct`。

每次发布创建新的不可变策略版本；Trace 保存实际使用的策略版本，因此能够解释“当时为何允许或阻止”。

## 3. 当前 MVP 的真实能力

- 三段式 Agent Gateway。
- 版本化 Policy-as-Code。
- 工具白名单、拒绝列表和人工审批门。
- 轨迹、评测、红队、纠错与审计数据模型。
- 九类红队插件、三种变异策略和十二条独立核心回归用例。
- 可创建评测数据集，输出 attack recall 与 false-positive rate。
- MCP Server 注册、工具清单快照、Manifest Pinning、Schema Diff、隔离与 JSON-RPC 代理。
- 自动纠错发布状态机、失败聚类、不可变策略回滚。
- SQLite 持久工作流、幂等键、审批恢复、重试和补偿事件。
- 参数绑定且防重放的 Capability Lease，以及无任意 Shell/网络/文件权限的工具 Adapter。
- OTel-shaped Agent、Model、Policy、Workflow 和 Tool Span，指标聚合与 OTLP JSON 导出。
- 组织、工作空间、成员 RBAC、哈希 API Key、Scope、RPM 与月度预算。
- A2A Agent Card 来源验证、Hash Pinning、Skill Diff、Rug Pull 隔离和消息策略。
- Demo Agent 与 OpenAI-compatible 目标适配器。
- 可运行的 React 企业控制台。

## 4. 从 MVP 到企业版

### v0.3 已实现的企业基础

- 单节点持久工作流与能力租约；服务重启后状态仍可恢复。
- 多租户模型、RBAC、API Key Scope、请求速率与预算计数。
- Agent Span 存储、聚合指标和 OTLP-shaped JSON 导出。
- MCP/A2A 双协议信任固定与运行时策略代理。

### 下一阶段：分布式生产化

- PostgreSQL、Redis 和对象存储替换单节点 SQLite。
- Temporal Worker 替换本地状态机，实现跨节点恢复与定时器。
- OTLP Batch Exporter、Collector、Prometheus 和 Trace 后端。
- OIDC JWT/JWKS 校验、SCIM、KMS 与细粒度关系授权。
- MCP OAuth 2.1、stdio/SSE 会话桥接、签名 Manifest。
- Docker/gVisor/E2B 强隔离 Worker 与网络 egress policy。
- A2A 签名消息、push notification 验证和跨组织身份联邦。

### V3：轨迹级评测（数据集/插件/确定性 Grader 已进入 v0.2）

- Step-level evaluator：计划质量、工具选择、参数正确性、证据充分度。
- Trace replay、counterfactual model comparison、shadow traffic。
- LLM-as-a-judge 与确定性 grader 的一致性校准。
- 生产失败聚类和自动生成回归集。

### V4：自进化（策略候选与回滚基础能力已进入 v0.2）

- Prompt、模型和工具策略的候选搜索。
- Canary 发布、Sequential Probability Ratio Test 和自动回滚。
- 将高质量轨迹构造为 SFT/DPO 数据，对小型 Qwen 进行领域适配。
- 以任务成功率、安全率、成本和延迟构建多目标优化器。

## 5. 安全原则

- 外部上下文永远作为不可信数据，而不是系统指令。
- 模型不能直接决定自己的权限。
- 有副作用的工具必须幂等并具备审批或补偿动作。
- 评测器不能只依据当前策略自我打分。
- 自动修复必须可回放、可审计、可回滚。
- 密钥只从环境变量或密钥管理系统读取。
