# AgentTrust Portfolio Evidence

本文是招聘方和代码审阅者的最短证据入口。结论只覆盖仓库中可运行、可检查的实现，不把参考架构写成生产验收结果。

## 可验证事实

| 主张 | 代码或接口 | 验证方法 | 边界 |
|---|---|---|---|
| 五阶段模型外策略 | `POST /api/v1/guard/check` | 运行 `test_embedded_guard.py` | 只有已接入边界受保护 |
| 来源图与污点传播 | `GET /api/v1/guard/sessions/{id}/provenance` | context → tool → tool_result 演示 | 标签不是内容真实性证明 |
| 副作用执行授权 | `SandboxService` Capability Lease | 重放、参数篡改和并发测试 | 不运行任意不可信代码 |
| 可复现实验清单 | evaluation/red-team manifest API | 比较 policy/dataset/result/build SHA-256 | 哈希不证明数据独立性 |
| 多轮红队预算 | `multi_turn` strategy | 固定 seed、轮次、费用和 stop reason | 当前攻击器为确定性脚本 |
| 框架工具边界 | `AgentTrustGuardClient` | OpenAI Agents adapter 单元测试与示例 | SDK 示例需要单独安装和 API Key |
| 独立评测入口 | `benchmarks/promptfoo` | Promptfoo 0.122.2 导出 JSON/HTML，当前 4/4 | 四条 smoke case 不代表准确率 |
| 租户隔离参考实现 | PostgreSQL FORCE RLS | GitHub CI 专用 PostgreSQL job | 本机三项测试会在未配置 PG 时跳过 |

## 本地复现

```powershell
.\scripts\verify.ps1
```

预期门禁包括 Ruff、Bandit、后端测试、75% 分支覆盖率门禁和前端生产构建。联网 CI 额外执行依赖漏洞审计、PostgreSQL/RLS、CodeQL、依赖审查与 SBOM 生成。

外部评测：

```powershell
cd benchmarks\promptfoo
npx promptfoo@0.122.2 eval -c promptfooconfig.yaml --no-cache --output results.json --output report.html
```

仓库保留本次 4/4 release-candidate smoke 结果。公开准确率数字前仍须记录 Git SHA、目标模型、价格、随机种子与更大的冻结数据集，并保留原始结果。

## 发布证据

- `CHANGELOG.md`：版本行为与已知限制。
- `.github/workflows/ci.yml`：测试、覆盖率、PostgreSQL、依赖审计和 SBOM。
- `.github/workflows/codeql.yml`：Python 与 JavaScript/TypeScript CodeQL。
- `.github/workflows/release.yml`：源码归档、CycloneDX SBOM、SHA-256 和构建来源证明。
- `.github/SECURITY.md`：私下漏洞报告与授权边界。

## 面试时的准确表述

称它为“Agent runtime security and evaluation control plane 的个人 Portfolio Release”。可以陈述已经实现和测试的边界，不应声称已有真实客户、达到商业 GA、通过第三方安全认证或在通用真实流量上证明了准确率。
