# AgentTrust 产品成熟度、安全与功能完整性评估

> **历史快照（2026-08-31）**：本文保留当时发现和修复依据，其中的测试数量、风险状态和版本结论不代表当前 v1.0.0。请以 [Portfolio Evidence](PORTFOLIO_EVIDENCE.md)、[当前竞品评审](COMPETITIVE_INTEGRATION_REVIEW_2026-09.md) 和仓库 CI 为准。

评估日期：2026-08-31。对象：当前工作区 v0.5.0 / Security SaaS Preview。

本报告合并本轮两次“对照开源和商业产品、完整检查功能及安全”的要求。仅评估，不修复业务代码，不升级依赖，不部署外部服务，不执行真实支付，不删除文件。以下是同一份去重后的产品验收基线，不是要求继续无限扩充功能。

## 1. 最终结论

**目前不能认定为成熟、可面向真实客户开放的多租户 SaaS。** 准确定位是：已有较广功能覆盖、可运行的 Agent Security 工程原型。可以用于本地合成数据演示、架构讲解和求职作品；修复阻断项并完成真实基础设施验收后，才适合受控客户试点。

这不是只缺几个页面：本轮复现了跨租户创建密钥、退款先执行后扣余额、DLP 执行不一致、被拦截工作流标记成功等问题。即使现有测试全部通过，也不能据此推断生产安全。

| 使用场景 | 当前判断 | 条件或原因 |
| --- | --- | --- |
| 本地作品演示、合成数据攻防实验 | 可以 | 标注模拟工具、规则评测、外部集成未验收；不暴露敏感管理接口 |
| 求职技术项目 | 有价值，但须补证据 | 能讲清威胁模型、失效模式、修复回归、指标口径，比罗列组件更重要；不保证 offer |
| 外部客户的只读安全观察试点 | 暂不直接开放 | 先修复租户隔离、凭证和隐私问题；观察模式也会处理客户数据 |
| 自动阻断和自动策略发布试点 | 尚不具备条件 | 需要独立准确率证据、硬性安全边界、人工复核与可验证回滚 |
| 真实客服退款/资金执行 | 不可以 | 模拟执行已暴露余额与外部副作用顺序问题，缺支付幂等和对账闭环 |
| 公开多租户 SaaS / 企业级 GA | 不可以 | 应用安全、租户生命周期、真实集成、恢复、容量和运维证据不足 |

不要给项目打一个未经校准的“85 分”或“完成 90%”：严重的租户越权不能被功能数量抵消。

### 建议固定的产品定位

**AgentTrust：面向有工具调用和业务副作用的企业 Agent，提供统一运行时安全决策、受控执行，以及经过验证的策略纠错发布。**

客户是 Agent 应用研发团队和安全团队；客服退款是首个参考业务，而不是把产品发展为完整客服系统或支付平台。自动纠错的对象主要是受约束的安全策略，不是自动修复所有业务逻辑、任意改代码或自动训练出更强模型。

最值得打磨的差异化是“发现风险 → 生成有限策略变更 → 独立验证 → 灰度 → 监测回滚”的可解释证据链。应当把市场承诺从“纠错准确率保证”改为“在明确数据范围和统计置信度下验证策略改进，对证据不足的变更拒绝自动发布”。

## 2. 对照了什么，借鉴什么

以下依据官方仓库/文档截至本次查询所描述的能力。未购买或实测商业服务，不能将厂商宣传当成独立性能证明；开源库、评测工具、网关和商业安全平台也不是同一产品类别。

| 对照对象 | 已核实的参考方向 | AgentTrust 应借鉴的重点 |
| --- | --- | --- |
| LlamaFirewall / PurpleLlama | 多扫描器组合，覆盖输入及多步 Agent 过程，包含 PromptGuard、AlignmentCheck、CodeShield 等。[官方仓库](https://github.com/meta-llama/PurpleLlama/tree/main/LlamaFirewall) | 统一扫描器接口、真实模型评测、动作与用户授权的一致性检查；不要把几组正则称为已落地的语义模型 |
| NVIDIA NeMo Guardrails | 提供可配置护栏、模型/框架集成、评测和可观测性入口。[官方文档](https://docs.nvidia.com/nemo/guardrails/about-nemo-guardrails-library/overview) | 按输入、检索、工具调用、工具结果、最终输出分别挂载策略；策略必须有 schema 和兼容性契约 |
| Promptfoo | 插件、攻击策略、目标与评判器配置，支持 CI/CD 质量门禁。[红队配置](https://www.promptfoo.dev/docs/red-team/configuration/)、[CI/CD](https://www.promptfoo.dev/docs/integrations/ci-cd/) | 独立攻击集、可重复实验、固定版本和失败即阻断发布；避免边测边改策略后再把总通过率当效果 |
| LiteLLM | 虚拟密钥管理、额度和预算、权限约束及相关生命周期能力；部分功能属于企业版。[官方文档](https://docs.litellm.ai/docs/proxy/virtual_keys) | 密钥吊销/到期/轮换、层级额度、真实成本核算、明确授权上限；不是只建一个 api_keys 表 |
| HiddenLayer AI Runtime Security | 文档建议新接入使用 Agentic Runtime Security，强调多轮、工具、多提供商请求构成可回放会话。[官方概览](https://docs.hiddenlayer.ai/docs/products/runtime/overview) | 可信会话身份、完整动作链、调查和处置流程，而不只是单次提示词打分 |
| Check Point AI Agent Security / Lakera 文档 | 区分资产发现与配置风险的 posture 层，以及通过 Guard API 的 runtime 层；AI Agent Security 整体目前明确标为 early access。[官方概览](https://docs.lakera.ai/docs/agent-security) | 区分“已登记资产图”和“自动发现”，区分资产风险与真实行为证据；不能把该 early-access 产品整体当成成熟 GA 基准 |
| Presidio | 支持 NER、规则、校验和、自定义识别器等；官方明确自动识别不保证发现全部敏感信息。[官方仓库](https://github.com/data-privacy-stack/presidio) | 扩展可插拔识别器和中文业务实体，按字段/用途制定策略，同时保留访问控制、加密和最小化采集 |
| Phoenix | 数据集可从生产轨迹积累，并通过版本化固定实验数据。[官方数据集说明](https://arize.com/docs/phoenix/datasets-and-experiments/concepts-datasets) | 将轨迹、经审核标签、数据版本、策略版本、实验结果关联；发送成功或 SDK 可调用不等于完整评测闭环 |

结论：无需把上述产品的功能全部复制。应复用标准协议、成熟基础设施和可替换检测器，自己重点实现统一执行边界、验证式纠错和面向客户的安全运营闭环。

## 3. 当前能力盘点：存在不等于成熟

| 领域 | 当前确有实现 | 边界与缺口 |
| --- | --- | --- |
| 网关与策略 | 输入/输出规则、工具白名单、审批要求、项目策略版本、模型 endpoint allowlist | 自有 invoke API；不是覆盖任意 Agent 的透明安全代理；真实模型路径主要是单次 chat completion |
| 检测 | 规则、DLP、混淆特征、会话阶段检测、ensemble | 大部分为确定性启发式；semantic detector 是可选 HTTP 接口契约，未交付已验收模型 |
| 自动纠错 | 有限 policy-only 候选、回放、holdout、生产灰度、人工标签入口、CAS 发布/回滚 | 样本独立性、全链路指标、盲审、样本充分性和异常观测仍不足 |
| 多租户与身份 | workspace/project、API Key scopes、OIDC JWT 验证、membership、业务表 FORCE RLS、事务级上下文 | 发现控制面越权；密钥/成员生命周期和组织归属授权不完整；本机未验收真实 RLS 栈 |
| DLP | 密钥、部分 PII/PCI/病历标识、嵌套字段脱敏、HMAC 指纹 | 各入口执行不一致；部分原文落库/响应旁路；不是通用中文实体和全媒体 DLP |
| 工具执行 | 受信任工具注册表、一次性 capability、部分参数绑定、超时和输出大小限制 | Python 进程内线程执行，不是 OS 隔离；副作用工具大多模拟 |
| MCP / A2A | 清单/卡片快照、哈希、变更隔离、受限 JSON 转发、部分 DLP 与 SSRF 检查 | 非完整协议网关；缺可信来源、授权委托、流式/会话兼容性与充分参数验证 |
| 客服退款 | 订单/客户/金额规则、审批、退款状态、事件、Temporal 工作流定义 | 模拟订单与支付；缺真正支付幂等、原子资金预留、对账、拒绝/取消/超时终态闭环 |
| 持久流程 | 本地持久状态、人工审批和重试入口；生产退款接 Temporal | 本地 retry_scheduled 没有后台调度；补偿为模拟；跨服务状态恢复未验收 |
| 安全运营 | 事件列表、kill switch、审计链、签名锚点、outbox、Webhook/可选 S3 Object Lock | 缺告警自动派发、认领处置闭环、投递后台 worker、独立归档验收与密钥轮换 |
| 可观测性 | 本地 spans、真实 OTel SDK、Phoenix 数据集/实验/Prompt API 接入 | 不是已验证跨进程追踪；Phoenix 项目命名不是权限隔离；指标与健康检查不能作为 SLO 证据 |
| 资产管理 | 同步注册资源及关系图 | 没有云/框架自动发现；attack_paths 为风险关系展示，不是已验证的可利用攻击路径 |
| 控制台 | 安全、退款、轨迹、协议网关、红队、纠错等页面；凭证仅存内存 | 缺实际 SSO 登录流程、新租户初始化、租户切换清空状态、权限感知交互、完整管理表单 |
| 部署与质量 | Compose、非 root API、部分容器权限限制、PgBouncer、离线迁移、备份模板、CI 文件 | 本机没有整栈运行证据；缺真实恢复/容量/故障演练，CI Compose 目前仅构建与配置验证 |

## 4. 本轮发现的关键问题

证据标签：**复现**＝本机独立 SQLite 测试库或内存模拟实际运行；**静态确认**＝可定位代码路径；**未验收**＝存在实现/配置但没有真实系统证据。优先级 P0＝阻断对应生产用途；P1＝正式产品闭环必需；P2＝定位相关扩展，不等于发现了漏洞。

### F01 / P0：创建密钥存在跨租户越权（复现）

两条路径均已验证：

1. 其他租户管理员省略 workspace_id。请求体授权层未解析 Pydantic 默认值，ApiKeyCreate 却默认为 ws_demo；服务直接创建其密钥。原本读取 demo 项目是 403，获取新密钥后变成 200。
2. 使用 application/problem+json 携带显式其他 workspace_id。框架会解析该 JSON，但中间件只检查包含 application/json 的类型，漏掉资源鉴权。同一跨租户请求由 403 变为 201。

API Key 是控制面表，不在业务 RLS 表清单内。因此不能用“PostgreSQL 已开 RLS”掩盖应用层问题。生产 PostgreSQL 链路在本机未实际运行；依据相同授权代码和未覆盖的表，具有明确风险，不能按安全处理。

来源：[请求解析](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/main.py:178>)、[资源授权](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/access_control.py:297>)、[默认工作空间](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/schemas.py:157>)、[密钥接口](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/main.py:1047>)。

修复要求：在解析完成的类型化请求上绑定服务端租户上下文，所有资源服务再次校验归属；消除生产 demo 默认租户；不支持的媒体类型明确拒绝；控制面专用权限/数据库访问边界。对所有路由测试 JSON 变体、缺省值、参数冲突、不同方法和对象 ID，而不是只修这一处接口。

### F02 / P0：退款外部副作用先于余额原子校验（复现）

测试订单可退 128 元，创建并批准两笔各 80 元的请求，再依次执行：模拟支付接口实际被调用 2 次，总额 160；第一笔数据库扣减成功后余额 48，第二笔这时才被数据库拒绝，状态滞留 settling。**不需要并发也能触发。** 当前是模拟支付，没有产生真实资金操作。

另有崩溃/超时窗口：外部成功而本地未记账，会留下不明状态；捕获工具异常后回退 approved，重试可能重复副作用。请求幂等键也没有绑定完整业务载荷，复用同一个键且更换金额/订单不会明确报冲突。金额为 float，尚未采用货币最小单位或 Decimal 规则。

来源：[退款执行](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/refunds.py:204>)。

修复要求：原子预留余额与业务请求、稳定支付幂等键、事务 outbox、支付回执、未知结果查询与对账、幂等事件消费者、恢复和补偿规则；不能通过把网络调用包在数据库事务中就宣称已解决。Temporal 官方也要求业务 Activity 具备幂等性，重试不会替业务自动实现 exactly-once。[Temporal Activity 定义](https://docs.temporal.io/activity-definition)

### F03 / P0：安全策略没有覆盖所有执行与输出路径（复现）

- 配置 DLP 输入 block 后，退款 reason 中的测试 MRN 被扫描器判定应阻断，RefundService.create 仍得到 approved，因为忽略扫描结果的 blocked。
- 直接执行 knowledge.search，返回中仍有测试 MRN 原值；sandbox 只对存储记录脱敏，不统一阻断/处理实际入参与返回。
- 让模拟模型返回安全正文，但 tool_calls.arguments 中含测试密码，gateway 响应 details 仍返回原值。输出 DLP 只扫描 result.output，没有覆盖全部结构化工具调用结果。
- 静态确认：退款不经过完整 ensemble/trajectory；MCP 工具结果主要经过输出秘密检测，没有等价的指令污染检查；gateway 的输入攻击检测不完整覆盖 tool_arguments。

来源：[退款扫描](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/refunds.py:58>)、[工具执行](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/sandbox.py:94>)、[模型工具结果](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/gateway.py:211>)。

修复要求：统一 Policy Decision Point，并在每个真正跨越信任边界的入口/出口执行；正文、结构化参数、工具输出、错误和辅助字段均受控。不是对所有业务字段无差别脱敏：需要发送收款信息等合法敏感字段时，用用途限定、授权和凭据代理，不能静默改坏签名或业务参数。

### F04 / P0-P1：工作流原文落库与终态错误（复现）

提交包含假密钥的工作流：网关返回 blocked，但数据库 input_json 仍保存原文，工作流最终 status 为 completed。读取结果可见内部 gateway.status=blocked 与外部 completed 矛盾。

静态确认：流程开始先存原输入，之后才做 DLP；真正 sandbox 工具调用仍使用原始参数。重试缺统一原子任务认领，running/approval_in_progress 等中间态没有通用恢复调度，compensate 只记录 simulated。

来源：[工作流输入持久化](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/workflows.py:55>)、[工具执行路径](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/workflows.py:163>)。

修复要求：入库前分类/最小化，确需原文的加密证据库单独授权；block/deny/failed/completed 使用明确不同终态。为每条允许生产使用的工作流指定持久执行引擎和恢复语义，不支持的本地演示路径必须在生产关闭。

### F05 / P0（不可信工具）/ P1（仅受信任工具）：Sandbox 名称超过实际隔离保证（复现）

当前是在 API 进程内 ThreadPoolExecutor 调 Python 回调。network/filesystem/shell=denied 是返回的描述字段，没有操作系统隔离措施。回调超时后 future.cancel 无法终止已运行线程。

无害测试：10ms 超时后接口返回 408，80ms 的回调随后仍完成。说明超时不意味着副作用已停止。当前没有开放任意代码执行接口，本报告**不把它误报成已存在可直接利用的远程代码执行**。

来源：[工具执行器](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/sandbox.py:115>)。

修复要求：V1 可明确只运行审核过的工具适配器并将名称改为受控工具执行器；若承诺承载第三方/不可信代码，就必须有独立进程或隔离容器、网络出口、只读文件系统、CPU/内存/PID 限额、硬终止和凭据隔离。一次性 capability 应强制绑定动作参数、目标服务、调用主体、审批和有效策略；不能只在调用方自愿填写 arguments_sha256 时生效。

### F06 / P0（自动发布承诺）：纠错准确率证据不足，holdout 有重叠（复现+静态确认）

- 内置回归集 30 条，holdout 12 条；按 message/context/tool_name 精确比较，有 **2 条完全相同输入**。其余也多为已知攻击族变体，不能称强独立盲测。
- 纠错器直接追加 ATTACK_SIGNATURES，评估的漏检判断也利用该签名集合，存在明显同源偏差。
- 补丁 confidence=0.94 等为代码常量，不是校准后的成功概率；轨迹 score 和平均分同样不能冒充独立安全准确率。
- 离线回放主要运行 PolicyEngine，不验证完整 DLP、ensemble、真实模型、工具副作用和业务结果；用户上传的自定义数据集不自动成为纠错发布的强制集。
- 在线 ReleaseGuard 有真实流量、人工标签入口和 CAS，这是有效基础；但 candidate_action 仍为 policy-only 计算。标注无独立复核流程，API Key 身份不等于证明有人类完成盲审；5000 条窗口不是按时间、模型、风险族分层的统计方案。
- gateway._invoke 之前/之外的异常可能没有进入 release_traffic 的错误计数，不能把 error_rate 当完整请求失败率。

来源：[评估数据](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/evaluation.py:101>)、[补丁置信度](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/correction.py:261>)、[灰度指标](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/release_guard.py:83>)。

修复要求见第 6 节。保持受限纠错，不自动放宽租户隔离、身份、支付额度、出站访问和审批等硬性规则。

### F07 / P0-P1：策略 schema、MCP 参数与管理授权不够严格（复现+静态确认）

- PolicyUpdate.rules 是任意字典；错误正则被 except re.error 静默忽略。单独测试非法正则 `[`，最终 action=allow。复杂正则可产生 ReDoS 风险；本轮未运行耗尽资源的攻击测试。
- MCP 参数验证只检查必填和顶层额外字段。要求 amount 为数字且 maximum=10 时，传字符串依然通过验证；没有递归执行类型、枚举、数值、数组和嵌套约束。
- A2A 注册和修改卡片都只要求 a2a:send，operator 的“发送消息”能力扩张成资产管理能力。
- 创建 workspace 仅确认 organization_id 存在，没有组织所有权校验。审批没有强制发起人与审批人分离；控制面关键操作审计覆盖不完整。

来源：[策略解析](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/policy.py:59>)、[MCP 验证](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/mcp_gateway.py:245>)、[scope 映射](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/access_control.py:409>)。

修复要求：类型化且版本化的配置、安全正则引擎/复杂度限制、完整 JSON Schema 校验；使用显式路由权限矩阵而非字符串前缀猜测；拆分发送、登记、信任批准、策略发布、密钥管理、资金审批角色。

### F08 / P1：会话与协议边界还不是可验证的完整接入层（静态确认）

session_id 由客户端 metadata 任意指定，缺主体绑定；不传时每次新建，攻击者可换 ID 避开跨轮聚合，也可污染同项目另一会话的风险状态。模型 adapter 主要是一次请求，没有完成“模型提出工具 → 授权执行 → 将结果交回模型”的通用循环，tool_name 输入在真实模型分支没有转成完整工具协议。

MCP/A2A 主要实现受限 JSON 转发，却声明部分流式/通知方法：统一读取 JSON object 无法正确处理 SSE、无正文通知、完整 session 协商/恢复等。哈希固定的是上传的清单，不能证明远端身份或实现未改变；更新隔离还缺明确审核和重新信任生命周期。

修复要求：公布支持版本与方法矩阵，对未支持功能明确拒绝；用官方协议测试套件和真实服务验收。根据选定接入模式实现独立下游凭据、audience/resource、最小 scope、会话主体绑定、来源与工具清单验证。当前没有发现把平台 Bearer 直接透传给下游，但仍缺面向受保护远端服务的完整委托流程。[MCP 安全最佳实践](https://modelcontextprotocol.io/docs/2025-11-25/tutorials/security/security_best_practices)

### F09 / P0-P1：出站和基础设施安全仍依赖未交付的环境控制（静态确认/未验收）

已有正向措施：禁止私网/保留 IP、禁重定向、部分上游响应限长、共享模型 endpoint allowlist、生产认证/RLS 配置约束、API 非 root 和部分容器 capability 限制。

但 DNS 校验和实际连接分离，存在 DNS rebinding 的时间窗口，代码注释也明确要求 egress proxy/firewall 补足。MCP/A2A 的 endpoint 仍允许 HTTP；未形成租户级出站目的地/端口授权。OIDC、Temporal、Phoenix、数据库和 webhook 的信任边界不能仅靠“配置为内部地址”解决。

Compose 的服务共享网络；Temporal 使用数据库管理员凭据，没有独立生产身份/TLS/namespace 授权方案；API/worker 没有完整资源限额与只读部署约束。Phoenix 使用统一接收项目，租户名字前缀不能替代下游访问控制。配置了 HSTS 也不代表已部署 TLS 终止。

来源：[出站校验](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/network_security.py:28>)、[部署文件](<C:/Users/DELL/Documents/ChatGPT/new agent/docker-compose.yml>)。

修复要求：默认拒绝出口、可信代理绑定解析/连接、TLS/mTLS 或等价隔离、平台级与租户级凭证分离、Secret Manager/KMS、短期凭据/轮换、服务网络分区。若客户能够直连模型或工具，网关阻断就是可绕过的可选检查；必须控制凭据与网络路径来证明完整覆盖。

### F10 / P1：SaaS 控制台与租户生命周期没有闭环（静态确认）

API 有部分创建接口，但缺正常的注册/受邀开通、成员移除/降权、workspace 停用、密钥撤销/有效期/轮换和项目配置生命周期。当前前端是手动输入 Key/Token，不是 OIDC 登录、退出和会话管理产品。

前端默认 projectId=proj_demo，并将项目列表与约 19 个请求放在同一个 Promise.all：新租户虽然能拿到自己的项目列表，但 demo 请求 403 会让整组赋值不执行，项目选择器也不能正确初始化。切换凭证时不先清空旧租户数据，失败后可能残留此前画面；这属于浏览器端会话数据隔离问题，不等同于服务端跨租户读取证明。

来源：[初始化和批量请求](<C:/Users/DELL/Documents/ChatGPT/new agent/frontend/src/App.tsx:43>)。

修复要求：先认证和加载可访问 workspace/project，再加载当前视图；按租户隔离/清空缓存和取消过期请求；分页、筛选、局部失败与空状态；按角色显示操作，但后端授权始终独立执行。一般业务用户能独立完成接入与调查才算产品，而不是必须让开发者手工修数据库。

### F11 / P1：真实额度、成本和资源治理存在空档（静态确认）

真实模型分支返回 cost_usd=0.0；max_cost_usd 和 max_tool_calls 在默认策略里存在，但没有对应完整执行限制。API Key 的限流/计数有实现，但 OIDC 路径没有等价的请求配额；没有组织/workspace/Agent/token/并发任务级统一额度。已有按 Key 锁定并记请求，不等于为并发模型费用预留预算。

同步数据库/语义 HTTP/工具执行会在部分 async 请求路径中阻塞；每个 sandbox 请求新建线程池，缺进程级并发闸门。一次红队调用可触发多次模型请求，不能按一次 HTTP 调用成本估算。

来源：[真实模型成本](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/agent_runtime.py:120>)、[默认预算字段](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/db.py:61>)。

修复要求：模型价格版本与用量账本、预留/结算、层级配额、OIDC 一致执行、限额失败策略、最大 token/工具步数、并发和队列容量、超时预算。计费套餐和自动收款可推迟；防滥用与成本封顶不可推迟。

### F12 / P1：运营、可恢复性与审计证据未闭环（静态确认/未验收）

- security_outbox 有重试数据，但缺常驻投递 worker、原子认领/租约、退避、死信和接收端幂等验收。事件有列表，缺负责人、认领、调查、解决、重开、抑制和申诉处理。
- 锚点签名及 S3 Object Lock 接口是有效基础，但独立存储只锚定摘要不等于已归档全部证据；没有证明恢复、保留、签名密钥版本与轮换。默认镜像未安装可选 boto3，需按 RUNBOOK 定制镜像；不能配置一个 bucket 就宣称验收成功。[S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)
- Temporal 审批超时/拒绝只结束 workflow 状态，未完整同步业务终态；审批数据库变更和发送 signal 之间仍有崩溃窗口，需要可恢复的 outbox/状态协调。
- /health 固定返回 healthy，并列出功能名称，不检查数据库/队列/检测器可用性；控制台“节点在线”也不是探针结果。缺分离 liveness/readiness、实际依赖状态和 SLO 告警。
- 本地备份/WAL 模板、迁移记录和连接池存在，但没有恢复/PITR、多节点故障、真实 PgBouncer/RLS、升级回滚证据。备份与原数据处于同类本机卷，不能代替异地恢复能力。
- CI 配置具备 SQLite/PG/RLS 任务，但本机没有远端 CI 成功运行记录；Compose 任务只 build/config，并未启动整栈。

来源：[outbox 投递](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/services/security_response.py:166>)、[健康接口](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/main.py:270>)、[Temporal 业务流](<C:/Users/DELL/Documents/ChatGPT/new agent/backend/app/temporal_workflows.py>)、[CI](<C:/Users/DELL/Documents/ChatGPT/new agent/.github/workflows/ci.yml>)。

## 5. 一份完整的 V1 验收清单

以下是统一范围，不需要再通过“添加一轮 P0、下一轮再想 P1”决定产品边界。每项可以拆工程任务，但上线依据是验收结果，不是文件或页面数量。P0 风险不能通过隐藏页面、修改 README 或跑通演示来关闭。

| 工作包 | 必须补齐/优化 | 可验收的完成条件 |
| --- | --- | --- |
| 01 身份、租户和控制面授权 | 修复 F01；组织/workspace 归属；角色/scope 矩阵；服务端上下文；控制面专用权限 | 所有端点覆盖跨租户读写、缺省参数、JSON 变体、API Key/OIDC、资源关联；真实非特权 PG/PgBouncer 多并发无串租户；拒绝发生在副作用前 |
| 02 租户与密钥生命周期 | 开通/邀请、成员停用降权、Key 到期/撤销/轮换、项目配置、审计 | 无需改库完成新租户接入；撤销在约定时间内对所有节点生效；发起人不能给自己绕过审批/组织权限 |
| 03 统一安全决策与执行 | 所有入口、检索内容、tool arguments/results、输出 details 受控；身份/授权/数据边界优先于模型判断 | 同一风险样本跨 gateway/refund/workflow/MCP/A2A/sandbox 得到一致的按用途决策；禁止的调用在适配器计数中为零 |
| 04 业务副作用与退款正确性 | F02；订单权威来源与客户授权；货币精度、预留、幂等、回执、拒绝/取消/超时、对账 | 超余额并发、重复提交、相同 key 不同 payload、超时未知成功、进程崩溃、重复回调和乱序回调均无重复退款；数据库与支付账可核对 |
| 05 工具与凭据隔离 | 受信任适配器边界；强制 capability 参数/主体/目标绑定；第三方工具才引入 OS 级隔离 | 拒绝越权工具、参数替换、跨服务复用和过期重放；超时处置有明确语义；需要隔离的工具无法读取宿主凭据/网络/文件 |
| 06 安全策略工程化 | 类型化 DSL/schema、静态校验、安全正则、策略模拟、差异、版本/CAS、签名和紧急回滚 | 错误/高复杂度规则不能发布；平台硬规则不可由租户/自动纠错放宽；回滚不覆盖更晚版本 |
| 07 检测效果与可信会话 | 可替换真实检测器；中文/编码/跨轮/间接注入；可信 session、主体/任务目标关联 | 独立标注集逐风险族测误报/漏报/延迟；更换客户端 session_id 不得绕过需绑定主体的防护；缺必需检测器时按风险 fail closed |
| 08 纠错与发布证据 | 第 6 节的数据独立、双人复核、影子全链路、灰度、申诉/反馈与回滚 | 每个候选有固定数据和策略版本、完整指标及理由；证据不足不自动发布；重大越权/数据泄漏/资金错误零容忍回归 |
| 09 标准接入与协议契约 | 选择一个主接入模式并交付可运行 Python/TS 集成示例；完整实现承诺的 MCP/A2A 子集 | 至少一个非演示 Agent 的端到端合同测试；不支持的方法明确拒绝；身份委托、schema、通知、流式、取消、断连均按支持矩阵通过 |
| 10 数据安全与隐私生命周期 | 入库前处理；按用途字段授权；必要原文隔离加密；错误/审计/模型外发/导出同样覆盖；保留和导出策略 | 敏感测试标记扫描所有相关表、日志、响应、Phoenix/Temporal payload，不出现非预期原文；租户无法读取其他租户导出；数据清理实施须单独获得授权 |
| 11 网络与部署安全 | TLS/mTLS、可信出口、DNS 连接绑定、默认拒绝、服务身份、KMS/Secret Manager、容器资源边界 | 恶意 URL/重定向/私网/IPv6/重绑定无法访问禁区；平台凭据不被租户选择的目标接收；服务不共享管理员凭据；直接绕过网关的路径被阻断 |
| 12 安全运营闭环 | 事件关联去重、严重性、负责人、认领/处置/重开、告警、申诉和动作审计 | 一次真实演练能从发现到停用 Agent/撤 Key、通知负责人、恢复和留存证据；重放投递不会重复执行处置 |
| 13 审计与证据导出 | 后台 outbox、投递幂等/回执、异地不可变证据、签名 key_id/轮换、完整性校验 | 对锚点、原始授权证据和业务事件进行篡改/丢失演练；独立接收端可验证；不能只检查本地 exported 字段 |
| 14 持久执行与恢复 | Temporal 状态同步、调度/租约、死信、重试分类、真正补偿；迁移/备份与灾备流程 | 断网、worker 崩溃、重复 signal、服务重启后状态可收敛；全新恢复环境通过租户、订单、审计与权限校验；实测 RPO/RTO |
| 15 可观测性、容量与成本 | trace 上下文跨请求/工具/worker；依赖 readiness；SLO、并发闸门、背压、费用和租户额度 | 给出指定硬件/模型/流量的 p50/p95/p99、吞吐、错误、检测开销、单请求费用；慢租户不拖垮其他租户；OIDC/Key 同等限额 |
| 16 控制台与日常可用性 | 修复新租户启动和缓存；按视图加载、分页、权限感知、表单、错误状态；真实接入向导 | 新用户能完成登录→接入→策略→观察→调查→复核→发布/回滚；切租户/退出不保留旧数据；关键表单通过端到端测试 |
| 17 供应链与发布质量 | 锁定完整依赖/镜像、SBOM、密钥扫描、SAST/DAST、容器扫描、构建来源和签名、真实整栈 CI | 包含本轮复现的回归门禁；干净环境可重现构建；必选 PG/集成测试不能静默 skip；漏洞处理有责任人和时限 |
| 18 商用与交付边界 | API 版本兼容、错误码、支持矩阵、接入文档、版本说明、SLA/SLO 范围、服务支持、安全报告入口、第三方许可清单 | 客户可独立安装/接入，知道数据流向和支持边界；性能和安全宣传均有对应证据；若公开开源需明确 LICENSE/NOTICE，当前根目录未发现相应文件 |

验证应用自身时，至少同时参考一般 Web/API 安全与 Agent 特有风险；不能只测提示词。建议将条目映射到 [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) 和 [OWASP Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)，记录适用/不适用及证据；这不是已经获得认证的声明。

## 6. 如何使“自动纠错”真正可相信

### 数据与实验

1. 分开开发集、候选验证集、锁定盲测集和按时间留出的线上集；按会话/攻击模板族去重，不只按完全相同字符串。避免把失败样例同时放进修复和最终证明集。
2. 每个数据集固定版本、来源、授权、语言、业务类别、攻击族、标注人和争议结果；自定义租户数据须纳入其发布 gate。
3. 除检测准确率，验证业务结果：正确允许的退款、错误拒绝率、未经批准动作数、金额/客户/订单一致性、信息泄漏与延迟/成本。
4. 冻结被测策略/模型/工具版本后比较 baseline 与 candidate。红队探索可启用学习，但效果测量必须另外在不改变策略的条件下完成。
5. 评测完整安全路径，包含 DLP、session、工具参数/结果和失败场景；规则子模块测得的结果要明确命名为 policy-only，不能代表整个 Agent。

### 统计与发布

- 分别报告攻击召回、良性误报、拒绝/升级人工比例、纠错覆盖率、修复后回归率；不能用单个总体通过率掩盖高危类别漏检。
- 发布需要各重要切片的置信区间，而不仅是总体 Wilson 下界 ≥0.80。例：在独立、同分布且零失误的理想假设下，149 个良性样本的误报率单侧 95% 上界约 1.99%；59 个攻击样本的召回率单侧 95% 下界约 95.05%。这只是二项分布计算示例，不证明真实分布独立，也不是达到样本数即可自动上线。
- 当前默认 25 个良性、10 个攻击标签，即使没有错误也不足以强有力证明上述阈值；增加相似模板数量不能代替样本多样性。
- 标签需有复核/仲裁、防自批和抽检；自动代理不能仅使用同一管理员 API Key 就充当“人工验证”。所有展示中的置信度应注明是经验启发值还是统计估计。
- 先做不影响业务的完整影子验证；只对风险可控、平台硬规则不变的候选小流量生效。重大错误立即熔断；上线后按时间、语言、租户和模型监控漂移。
- 钱款、身份、租户、凭据和出站访问的硬性授权不能由模型分数或自动纠错覆盖。对高影响变更保留人工审批。

不需要读取模型的私有推理过程才能做动作一致性验证；应使用明确的任务目标、授权范围、结构化行动计划、工具参数和业务证据。

## 7. 哪些功能现在不必再加

- 不必再做一个私域知识库、虚拟人或全能 Agent Builder；它们偏离第二个项目的差异化。
- 不必自研身份提供商、数据库、Temporal、通用可观测平台或支付处理系统。接入并验证成熟组件，同时保留 AgentTrust 的安全决策和纠错证据模型。
- 不必首版覆盖所有云、所有 Agent 框架、全部 MCP/A2A 特性。选择主接入模式，其他模式明确关闭或标为实验支持，而非半实现也宣称支持。
- 云端自动资产发现、全媒体安全、移动端、多区域 active-active、全套 SCIM/计费自动收款，可按目标客户决定。若承诺这些能力，则相应安全与验收不能省略。
- 不建议为了展示技术复杂度引入自动代码修复/自训练闭环；先证明有限策略纠错对真实业务有益且可回滚。
- 不必追求单一 LLM 判断一切。确定性授权、强执行边界、模型检测和人类复核各自解决不同问题。

## 8. 本轮验证证据与范围限制

### 实际执行结果

| 验证 | 本轮结果 | 不能推出什么 |
| --- | --- | --- |
| 后端 pytest（禁用 pytest cacheprovider） | 32 passed，3 skipped，19.35s | 不能推出生产整栈和新发现路径安全 |
| Ruff | 通过 | 不是逻辑安全审计 |
| Bandit | 本次扫描无报告 | 不是渗透测试或完整漏洞证明 |
| pip check | 通过 | 不代表依赖无漏洞 |
| pip-audit 当前已安装 Python 环境 | 未发现已知漏洞 | 不是对未来解析出来的依赖、OS 镜像或可选未安装组件的证明 |
| npm audit | 0 vulnerabilities | 公告库时间点快照，不包含全部业务漏洞 |
| 前端 app/node TypeScript 检查 | 两项退出码均为 0 | 本轮未重新进行浏览器 UI E2E/生产构建 |
| 独立复现 | 见以下记录 | 真实 PostgreSQL、支付提供商、外部协议服务器未验证 |

漏洞库查询第一次因受限环境网络/缓存访问失败；随后用获准的只读联网审计完成。没有运行 audit fix、安装或升级依赖。

### 独立复现结果摘要

```text
租户密钥：foreign_read_before=403
          explicit_foreign_key_request=403
          omitted_workspace_key_request=201
          created_key_workspace=ws_demo
          foreign_read_after=200

JSON 类型：normal_json_status=403
           application/problem+json_status=201
           foreign_key_created=true

退款顺序：initial_balance=128
          simulated_provider_calls=2
          simulated_total=160
          remaining_balance=48
          second_refund_error=RefundError
          second_status=settling

退款 DLP：scanner_blocks=true / refund_status=approved
流程 DLP：raw_fake_secret_persisted=true
          workflow_status=completed / gateway_status=blocked
工具 DLP：raw_value_in_return=true
网关结构化输出：status=completed / fake_secret_in_response_details=true
工具超时：timeout_code=408 / callback_finished_after_timeout=true
MCP schema：invalid_numeric_type_accepted=true
非法正则：action=allow
评测数据：regression=30 / holdout=12 / identical_holdout_inputs=2
A2A 注册所需 scope：a2a:send
```

复现仅使用自动创建的独立测试租户、合成敏感值与模拟工具；未输出测试 API Key。对应数据库保留在：

- `backend/test-data/audit-auth-f1a11dddcff9409381e005b8d3208f24.db`
- `backend/test-data/audit-runtime-45b249bfc7804626b060498917b2cab1.db`
- `backend/test-data/audit-boundaries-9c5a94ed1a834dd6b4b1bfc5700ba294.db`

这些与正常测试产物位于已忽略的 test-data 目录；未删除。不要将含测试授权凭据的数据库提交到公开仓库。

### 未验收事项

本机命令检查未找到 docker/psql；3 个 PostgreSQL RLS 测试因专用服务器未配置被跳过。未执行真实 PostgreSQL/PgBouncer 整栈、Temporal 崩溃恢复、真实 OIDC 登录生命周期、Phoenix 外部实验、S3 WORM/回执、实际模型准确率、支付网络与对账、负载/渗透/灾备演练。不能将仓库内 CI 配置当成这些验证已成功的证据。

仓库当前文件在 Git 状态中仍为未跟踪集合，未核实任何远端发布记录。本轮没有提交、推送或修改这些既有文件；新增的交付物是本报告。

## 9. 可执行的产品决策

1. 现在保留 Preview 定位，使用合成数据和模拟退款；先不要开放真实多租户访问，也不要接真实资金。
2. 接下来以第 5 节为固定范围，先关闭可复现的阻断项，再补 SaaS/运行闭环和真实验收。不能用新增“高级功能”替代修复。
3. 对外展示一条完整且有证据的路径：新租户接入真实参考 Agent → 正常业务通过 → 攻击被拦截 → 生成有限候选 → 独立复核 → 灰度 → 故障回滚 → 审计导出。
4. 受控试点和 GA 分别签署验收记录，记录仍不支持的能力。真实商用取决于安全、可操作性、稳定性和效果证据同时成立。

本报告完整考虑了当前已识别的产品域，并给出统一边界，但不是“以后永远无需审查”的保证。安全验证、依赖公告处理和模型/业务漂移监控应成为产品自身的持续机制，而不是反复临时构想更多模块。
