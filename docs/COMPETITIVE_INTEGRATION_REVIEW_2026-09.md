# AgentTrust 竞品对照与产品成熟度评审

评审日期：2026-09-02，当前版本 v1.0.0。目标是个人简历、面试演示和可继续商用化的工程底座。这里的“成熟”指边界清楚、可运行、可验证、可解释，并不表示已完成企业生产验收。

## 项目隔离原则

AgentTrust 与星限是两个独立项目。二者不共享代码、数据库、部署流程或运行时依赖；AgentTrust 的实现和演示不要求修改星限。简历叙事中，星限证明 Agent 应用与产品交付能力，AgentTrust 证明安全控制面、评测、可观测性与受控发布能力。

仓库中的通用 External Agent Adapter 只是可选黑盒兼容层，目标 URL 白名单默认为空。它只允许调用显式批准的兼容 API，不会配置或写入目标项目；调用后的检查也不能撤销上游已经发生的副作用。

## 对照结论

| 参照项目／产品 | 公开能力重点 | AgentTrust v1.0.0 已实现 | 仍然保留的边界 |
|---|---|---|---|
| [Janus](https://github.com/Agentic-AI-Risk-Mitigation/Janus) | Pre-tool 策略、最小权限、会话污点追踪、框架 Adapter | 五阶段 Guard、来源图、不可信内容到副作用工具的审批、敏感来源到出站工具的阻断、OpenAI Agents SDK function-tool 边界适配 | 尚未提供 LangChain/ADK 等自动 Hook，也没有 SpiceDB ReBAC |
| [AgentDojo](https://github.com/ethz-spylab/agentdojo) | 工具型 Agent 的攻击／防御动态基准与可检查结果 | 独立的策略回放、逐例结果、数据集哈希和基线差异 | 内置集合是小型合成集，不能宣称达到 AgentDojo 基准水平 |
| [promptfoo](https://github.com/promptfoo/promptfoo) | 插件与策略分离、多轮攻击、Token／费用预算、提前停止 | 9 类插件、四种策略、共享会话多轮、轮次／费用／停止条件和随机种子；固定 0.122.2 的公共 API smoke benchmark 当前 4/4 | 多轮攻击器是确定性脚本，四条外部 smoke case 不是独立准确率基准 |
| [Langfuse](https://github.com/langfuse/langfuse) / [Phoenix](https://github.com/Arize-ai/phoenix) | Trace、数据集、实验、评测、Prompt 与 OTel 生态 | OTel/Phoenix 适配、本地 Trace、版本化评测清单和逐例差异 | 不重复建设完整 LLMOps 平台；外部服务需单独部署和验收 |
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Agent/MCP/Skill 发现、供应链风险、扫描授权和可验证发布物 | MCP Manifest Pinning、Schema Diff、工具投毒／Rug Pull 隔离 | 不自动执行未知 stdio Server，不宣称已实现整机资产发现 |

## v1.0.0 选择实现的能力

### 1. 五阶段执行边界

`POST /api/v1/guard/check` 支持 input、context、tool、tool_result 和 output。未知工具默认拒绝；DLP 命中会提高到阻断；副作用工具仍需 Capability Lease 或 Durable Workflow，Guard 的 `approval_required` 不是执行凭证。

### 2. 来源图与污点传播

每个 Guard 节点记录项目、会话、阶段、来源、工具、决策、内容 SHA-256、标签和父节点，不保存原始提示词、参数或工具结果。context 与 tool_result 默认进入不可信域；敏感工具结果和 DLP 命中继续污染会话。两条可演示的强规则是：

- untrusted context → side-effect tool：至少 `approval_required`；
- sensitive source → egress tool：`block`。

查询 `/api/v1/guard/sessions/{session_id}/provenance` 可回放脱敏来源链。父节点必须属于同一项目和会话，避免伪造跨租户／跨会话图。

### 3. 可复现实验凭证

评测和红队运行写入 `agenttrust.run-manifest.v1`，包含策略版本及哈希、数据集哈希、逐例结果哈希、模型快照、是否真实执行模型、构建版本、随机种子、费用报告状态和运行参数。构建版本未由 CI 注入时明确标为 `unreported`。

`GET /api/v1/evaluations/compare/runs` 逐例返回 improved、regressed、unchanged、added 和 removed，避免只用聚合通过率掩盖高风险回归。哈希只能证明产物身份，不能证明数据独立或真实世界准确率。

### 4. 有预算的多轮红队

multi_turn 策略让同一攻击案例共享 session_id，保留每轮 Trace、状态和停止原因。运行限制最大轮数、总费用和命中防护后的提前停止。费用无法由目标可靠报告时，Manifest 会标记 `reported=false`，不能把 0 当作免费。

### 5. 默认关闭外部目标

`AGENTTRUST_EXTERNAL_AGENT_ENDPOINT_ALLOWLIST` 默认为空。任何外部 Agent 目标都必须由部署者加入完整 URL 白名单；生产仍要求 HTTPS 和服务端凭据。该设计消除对具体作品项目的隐式耦合。

## 适合简历展示的主线

三分钟演示只需要一条证据链：正常上下文通过 → 外部内容被标记为不可信 → 读取敏感来源 → 出站工具在执行前被阻断 → 查看脱敏来源图 → 运行单轮／多轮红队 → 导出实验清单 → 比较候选策略逐例差异 → 人工审核发布或回滚。

这条路径能同时展示 Agent runtime、policy-as-code、provenance、DLP、human-in-the-loop、evaluation、observability 和安全发布工程。不要把功能数量、合成通过率或组件清单当成生产成熟度证明。

## 商用化仍需补齐

- 在 LangChain、OpenAI Agents SDK、Google ADK 等真实框架中提供受维护的 pre/post tool Adapter，并验证失败关闭。
- 用 AgentDojo 或独立业务集完成真实模型、多语言、多轮和工具结果攻击评测；冻结数据、模型与策略后再报告统计结果。
- 对字段级 provenance 做 schema 映射和数据保留治理；当前会话标签是保守的控制面实现，不是通用数据流分析器。
- 完成真实 PostgreSQL/RLS、OIDC 生命周期、Temporal 崩溃恢复、备份恢复、容量、渗透和灾备验收。
- 若开放未知代码或 stdio MCP，必须在独立容器／VM／gVisor 等强隔离环境执行，并要求逐个授权；当前明确不开放。
- 扩充框架适配矩阵、冻结的独立数据集和真实模型实验；当前已有 LICENSE、CycloneDX SBOM、校验和与 GitHub provenance 工作流，但必须在公开仓库跑出可查看的绿色记录。

本版已达到“可放在简历中、可现场运行、边界可信”的个人作品标准。它仍应被描述为 Portfolio Release，而不是已经服务真实客户的商业 GA。
