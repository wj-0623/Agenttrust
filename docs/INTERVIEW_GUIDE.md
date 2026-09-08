# AgentTrust 面试讲解指南（v1.0.0）

## 30 秒介绍

“AgentTrust 是我构建的 Agent 运行时安全与评测控制面。它在输入、外部上下文、工具调用、工具结果和输出五个边界执行模型外策略，使用会话来源图追踪不可信数据到副作用工具的传播，并用一次性能力租约控制真实执行。红队与评测运行会生成内容寻址的实验清单，策略候选只有在逐例回归、误杀指标和人工审核通过后才能发布或回滚。”

## 与星限的简历关系

两个项目完全独立，不共享代码或运行时依赖，也不需要修改星限。

- 星限：证明 Agent 应用、编排、记忆、工具与产品体验能力。
- AgentTrust：证明 Agent 安全、评测、可观测性、执行治理与工程边界能力。
- 共同叙事：既能构建可用的 Agent，也理解它在接触不可信数据和副作用工具后为什么会失控，以及如何用确定性控制面降低风险。

不要在面试中声称两个仓库已经集成，也不要把个人合成实验描述为企业生产流量。

## 三分钟演示

1. 调用 Step Guard 检查正常输入，展示 allow、策略版本和内容哈希。
2. 写入一条 external context，打开来源图，展示 `untrusted_content` 标签和父节点。
3. 请求 `email.send`，展示污点传播把结果提升为 `approval_required`。
4. 写入 `vault.read` 工具结果，再请求出站工具，展示 `sensitive_to_egress` 在执行前直接 block。
5. 在红队页运行 direct + multi_turn，展示共享会话、轮次上限、费用上限和提前停止。
6. 打开 Run Manifest，说明策略、数据集、逐例结果、构建版本和随机种子如何被固定。
7. 比较两次评测，逐例查看 regressed／improved，而不是只看总通过率。
8. 展示策略候选的人工审核、Capability Lease 防重放和回滚版本。
9. 打开 OpenAI Agents SDK guarded function tool 和 Promptfoo 结果，说明同一控制面如何进入真实框架与独立评测器。

## 招聘方可能追问

### 为什么 System Prompt 不能承担授权？

Prompt 是模型输入，会受到上下文和间接注入影响。工具权限、参数约束、租户边界和审批必须由模型外代码在副作用发生前执行。

### 来源标签是否可信？

标签由受信 Adapter 和系统阶段推导，只做单调增加，不允许调用者通过省略标签清除既有污点。当前实现是会话级保守传播，不是完整字段级数据流分析；生产还需要框架 Hook、Schema 映射和数据保留策略。

### 哈希清单能证明评测真实吗？

它能证明本次运行使用的策略、数据集、结果和配置身份，并支持逐例差异复核；不能证明数据独立、模型确定或真实世界准确率。构建版本未从 CI 注入时会明确显示 `unreported`。

### 自动纠错会不会放宽安全策略？

候选只允许受约束的 policy-only 变更，发布前再次检查主集、holdout、自定义集和受保护字段。默认必须人工审核；Prompt 和代码修改不会自动发布。

### Sandbox 是否真的隔离任意代码？

不是。当前只运行注册的可信 Adapter，不开放任意 Shell 或代码上传。线程超时不能硬终止副作用。若将来开放不可信代码或 stdio MCP，必须迁移到独立容器、VM 或 gVisor 等强隔离环境。

## 简历 Bullet

- 构建五阶段 Agent Runtime Guard，在输入、RAG／记忆、pre-tool、tool-result 和输出边界执行 fail-closed 策略与 DLP，并通过参数绑定的一次性 Capability Lease 控制副作用。
- 设计脱敏会话 Provenance Graph，仅保存内容哈希、来源标签和父节点，实现 untrusted→side-effect 审批升级与 sensitive→egress 执行前阻断。
- 实现可复现 Agent 安全实验系统：多轮红队的会话、轮次、费用和停止条件受控；Run Manifest 固定策略、数据集、结果、模型、构建版本与随机种子，并支持逐例基线差异。
- 实现 MCP/A2A 供应链安全、工具 Manifest／Agent Card Pinning、Schema Diff、Rug Pull 隔离、哈希审计链、Kill Switch 与可选 WORM Outbox。
- 搭建 React 控制台、FastAPI 控制面、PostgreSQL FORCE RLS、OIDC/JWKS、Temporal、OpenTelemetry/Phoenix 和 Docker Compose 生产参考架构，并明确未完成的真实基础设施验收边界。

## 不能夸大的内容

- 内置数据集规模小且为合成数据，不代表通用攻击防护准确率。
- PostgreSQL、Temporal、OIDC、Phoenix 与 WORM 适配虽有代码，未在本机完成完整生产验收时不能称为 GA。
- 外部 Agent Adapter 是黑盒兼容层，无法撤销上游已发生的副作用。
- 项目可显著增强简历的工程证据，但任何项目都不能保证获得特定公司的 offer。
