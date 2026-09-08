# AgentTrust v0.4 生产架构与安全边界

> 生产参考架构与历史设计记录。当前状态、剩余缺口和实测边界请看 [Portfolio Evidence](PORTFOLIO_EVIDENCE.md)、[当前竞品评审](COMPETITIVE_INTEGRATION_REVIEW_2026-09.md) 和 [运维手册](RUNBOOK.md)。本页不能替代真实环境验收。

## 产品定位

AgentTrust 是 Agent Security Runtime，不是客服机器人本身。客服退款 Agent 只是第一个可直接演示的业务载体：每个输入、检索上下文、模型调用、工具调用和资金副作用都必须经过策略、身份、租户、能力与审计边界。

## 两种运行模式

本地模式使用 SQLite 和进程内持久状态机，保证作品集可以零外部依赖启动。生产 Compose 强制 API Key 或 OIDC 身份，使用 PostgreSQL、Temporal Worker、OTel OTLP 和 Phoenix。显式启用的 OIDC、Temporal 或 OTel 组件初始化失败时，生产进程 fail closed，不会静默退回本地模拟实现。

## 客服退款威胁模型

受保护资产包括退款资金、订单与客户关系、退款规则、客服身份和审计证据。主要攻击面包括直接/间接 Prompt Injection、伪造客户或订单、超额与并发退款、审批重放、工具参数替换、越权读取其他租户退款、恶意附件上下文和审计删除。

安全链路为：租户身份授权 → 输入与证据扫描 → 客户/订单/币种/余额确定性验证 → 风险分级 → Temporal 人工审批（高风险）→ 参数哈希绑定的一次性 Capability → 受信任 Refund Adapter → 原子扣减可退余额 → OTel Trace、安全事件和哈希审计。

## 自动纠错可信门禁

自动纠错只允许 `policy-only` 变更。当前发布门禁要求：30 条主回归和 12 条独立 holdout、回放通过率 ≥ 80%、攻击召回率 ≥ 95%、误杀率 ≤ 2%、95% Wilson 下界 ≥ 80%、置信度与增益达标、主集与 holdout 连续通过，且候选误杀率不得高于基线。Prompt、模型和业务代码修复只生成建议，不自动发布。

这些指标只能证明指定回归集上的行为。要支持商业准确率承诺，必须加入租户级盲测集、时间切分数据、人工双标、类别置信区间、漂移告警和生产抽样复核。

## 系统安全控制

- 身份：OIDC discovery/JWKS、固定算法、Issuer/Audience/exp/iat/sub 校验；API Key 高熵随机、仅存 SHA-256、Scope/RPM/月预算。
- 租户：所有项目与资源路径在 API 中反查所属工作空间；PostgreSQL 模式通过事务和 advisory lock 保护跨节点策略/审计竞争。
- 网络：MCP/A2A 出站执行 DNS 与 IP 分类，阻止环回、内网、链路本地、元数据与保留地址，并限制响应体。
- 执行：无任意 Shell/文件系统/网络工具；副作用工具必须使用参数绑定、短 TTL、单次消费的 Capability。
- Web/API：流式请求体上限、严格 CORS、CSP、HSTS、no-store、frame deny、request ID；生产关闭 OpenAPI 文档。
- 审计：普通事件表加按项目串联的 SHA-256 哈希链；生产应把链头周期性锚定到外部 WORM/SIEM。
- 供应链：Ruff、Bandit、pytest、pip-audit、npm audit、Dependabot；CI 同时运行 SQLite 与 PostgreSQL 测试。

## 仍需增加的产品与安全能力

### P0：商用前必须完成

1. PostgreSQL RLS、独立迁移角色与应用角色、PgBouncer、备份恢复演练和 PITR；当前已有应用层隔离，但数据库运维账号仍是高价值边界。
2. OTel Collector 与 SIEM/SOAR：Phoenix 用于 Agent Trace，安全事件还应标准化为 OCSF/ECS，并接入告警、值班、封禁与 Kill Switch。
3. 多检测器 DLP：PII/PCI/PHI/Secrets 的输入、检索、工具响应和输出检测，支持 redact/tokenize/block；当前只覆盖常见凭据特征。
4. 自动纠错线上验证：按租户时间切分 holdout、样本量估算、顺序检验、真实 canary 流量、自动回滚 SLO 和人工 appeal。
5. Temporal 生产化：TLS/mTLS、命名空间隔离、Worker Build ID/版本路由、死信/超时运营台、补偿退款和支付提供商幂等键。
6. OIDC 生命周期：SCIM、JIT 的受限默认角色、Key/Session 撤销、MFA/Step-up、服务账号和密钥轮换。

### P1：形成市场竞争力

1. Agent 资产发现与风险图谱：自动发现 Agent、模型、MCP、工具、数据源、Owner 和权限路径，映射 OWASP Agentic Top 10 / MITRE ATLAS。
2. Stateful trajectory detection：不只扫描单条 Prompt，重建会话、工具调用和跨 Agent 传播链，检测低频分步攻击、memory poisoning 和目标漂移。
3. MCP 全面授权：OAuth 2.1、Resource Indicators/Audience、token passthrough 检测、动态注册策略、工具影子与跨 Server escalation。
4. 专用检测器插件：接入 LlamaFirewall/Prompt Guard、LLM Guard 或商业分类器，与确定性策略组成 ensemble；每个检测器单独校准阈值和延迟预算。
5. 企业策略治理：策略 GitOps、四眼审批、租户模板继承、例外过期、变更影响分析与合规报表。

### P2：平台化扩展

1. gVisor/Firecracker/WASM 强隔离执行池和细粒度出站 egress broker。
2. 多模态 Prompt Injection、文档隐写、OCR/PDF/图片与代码产物安全扫描。
3. AIBOM、模型/Prompt/数据谱系、签名 Provenance、供应链 SBOM/SLSA 与模型完整性扫描。
4. 区域化部署、BYOK/KMS、字段级加密、数据驻留、保留/删除策略和隐私请求工作流。
