# Shannon 漏检归因排查任务清单

> 目标仓库：https://github.com/GinRawin/Shannon  
> 任务性质：**诊断任务，不是功能开发任务**  
> 适用范围：优先针对 Java 后端测试项目；现有 Source/Sink 辅助工具保留，仅用于对照实验。  
> 核心问题：在原有 Agent 与辅助工具发现的 Source/Sink 高度重合的情况下，Shannon 的漏洞检出率受限于哪个环节？

## 0. 基本原则与交付约束

- 不修改原有安全分析策略、Prompt、模型或 Workflow，以免污染本轮基线。若必须增加日志，须使用观察性记录，不改变 Agent 可见信息；记录变更 commit。
- 使用**固定的目标仓库 commit**、Shannon commit、模型配置、Prompt、Token/时间预算、认证与目标服务环境。确保比较的是同一实验条件。
- **已知漏洞真值只供离线评估使用，不得写入 Agent Prompt、目标仓库标记或其他 Agent 可见环境**，避免答案泄露。
- 不把“出现过函数名”当成“漏洞已分析”；分析与验证必须有可追溯证据。
- 明确两种不同的结论：①工具没有提高检出率；②工具提高效率。不能用前者直接否定后者。
- 对不完整日志使用 `unknown`，不得推断 Agent 一定没看见或一定没分析。
- 仅在明确授权的测试环境分析和验证；分享日志时脱敏 Token、密钥、Cookie、个人数据和 HTTP 报文中的敏感字段。

## 1. 第一批样本（P0）

### 样本怎么选

1. 从已运行的 Java 目标中，选 **3–5 个已知存在但 Shannon 未成功报告**的漏洞，优先覆盖不同漏洞类型和不同复杂度的调用链。
2. 同时选 **2–3 个 Shannon 已经成功发现的漏洞**作正例对照。
3. 对每个漏洞记录：`case_id`、目标名称与 commit、漏洞类别、真实入口/Source、真实 Sink 或缺失控制点、关键方法/文件/行号、最小有效路径、必要权限/前置条件、最终验证条件。
4. 对于 Auth/Authz，不强制映射传统 Source/Sink；记录登录、授权、角色校验、对象所有权检查等关键边界，以及缺失/错误检查的位置。

### 每个样本必须提交的证据

- 真值依据：人工源码分析、可复现的测试结果或可信评测标签（注明来源和置信度）。
- 对应运行 `run_id` 与原始日志路径。
- 目标代码的精确位置（至少文件、类/方法、代码区间；不同 commit 的行号需重定位）。
- 明确漏洞是否**符合 Shannon 当前目标/攻击者模型和验证约束**；不符合的单独标为 `out_of_scope`，不计入漏检。

## 2. P0：逐漏洞追踪每一个 Pipeline 阶段

对每个已知漏洞按以下顺序检查，保存具体证据位置；**第一次证据缺失的阶段**作为主漏检环节，但保留后续可能的次要因素。

| 阶段 | 检查问题 | 主要证据 |
|---|---|---|
| Pre-Recon | 是否找到真实入口、Sink/权限边界？是否仅泛泛提及 API？ | `.shannon/deliverables/pre_recon_deliverable.md` + 对应 Agent/子 Agent trace |
| Recon | 是否保留并识别真实的外部可达入口、参数、认证状态及相关敏感位置？是否误判不可达？ | `.shannon/deliverables/recon_deliverable.md` + trace |
| 阶段交接 | 真正传给 Vuln-Analysis 的输入中是否仍含该线索？有没有在总结、截断、优先级筛选中消失？ | 任务输入、子 Agent prompt、实际读取的文件、上下文压缩记录（若存在） |
| Vuln-Analysis | 是否打开真实函数与其上下游、追踪污染传播/安全控制？是否提出漏洞候选？ | 各 `*_analysis_deliverable.md`、工具调用记录、源码读取证据 |
| 队列/归并 | 若分析阶段识别了漏洞，它是否进入 exploitation queue？是否去重、范围筛选或字段映射时被丢弃？ | `*_exploitation_queue.json`、合并与归并日志 |
| Exploit | Agent 是否实际验证，失败原因是环境、请求、鉴权、载荷、预算还是漏洞不存在？ | `*_exploitation_evidence.md`、请求与报错证据 |
| Record | 是否有有效 `http_replay`；断言是否通过？被排除原因是什么？ | `record_verification.json`、`record-failures.json`、`record-verification-failures.jsonl`、`record_report_exclusions.json` |
| Explore（可选） | 对已验证种子是否本应触发 AST 克隆扩展？扩展是否产生候选及后续验证？ | `explore_*` 结果；不将它混入主流程漏检归因 |

> 文件名称来自仓库 `SHANNON_PIPELINE.md`；以运行实际生成的工件为准。运行日志的真实位置需从代码中 `workflowLogPath` / `TraceEmitter` 配置或部署环境确认，不要猜测路径。

### 关键状态定义（必须统一）

- `not_found`：没有证据表明任何 Agent 定位到关键位置。
- `located_only`：日志或报告提及位置/API，但未打开关键函数并研究其调用关系。
- `inspected`：实际查看相关代码，至少调查一段关键数据传播或权限控制路径，但尚未形成充分判断。
- `analyzed`：有明确的 Source→传播→Sink / 权限边界推理，说明是否存在 Sanitizer、鉴权与可达性，并给出结论或不确定点。
- `candidate_reported`：提出漏洞候选并可定位到具体路径。
- `queued`：进入 Exploit 队列。
- `exploited`：拿到符合验证规则的运行时影响证据。
- `record_verified`：Record 最终核验通过，达到报告条件。
- `unknown`：证据不全，不能判断。

对同一漏洞保存最高状态、第一处流失点和证据引用；仅提及 API 的 `located_only` **不可算作分析覆盖**。

## 3. P0：检查 Source/Sink 工具到底带来了什么

以同一批测试数据，分别查看关闭/启用新工具的运行情况：

1. 子 Agent 是否**看得见并实际调用**工具？从代码中追踪 `securityCandidateTools` 注入到 `createAgentSession`，再核对 trace 中的调用记录。
2. 请求的 `vulnerability_type`、`limit`、`function_name`（若有）是否符合任务；工具是否报错、超时、只返回部分候选？
3. 真实已知漏洞对应的位置是否在**完整扫描索引**中？是否因常量过滤、类型匹配、排序或 `limit` 而未出现在 Agent 可见的返回中？
4. 新工具返回的候选是否已经被原有搜索发现？若没有，Agent 是否实际继续读取该候选对应代码？
5. 工具结果是否通过 Pre-Recon/Recon 总结或子任务交接进入 Vuln-Analysis？
6. 是否存在工具结果占用上下文、挤掉其他线索、引发更多重复搜索的负作用？

> 必须区分 `index_found`（工具底层全量索引命中）、`tool_returned`（本次查询真的返回）、`agent_consumed`（Agent 后续实际使用），三个值不能混为一谈。

## 4. P0：专门排查阶段交接与分析预算

- 子 Agent 完成工作后是否把**具体文件、方法、行号、风险理由**回传，还是只回传模糊摘要？
- `pre_recon_deliverable.md` 中明确列出的重点 Sink/入口，在 `recon_deliverable.md` 中有多少保留？Vuln-Analysis 真正读取到哪些？
- Recon 是否将“未确认网络可达”误写为“不可能可达”，导致后续不分析？
- Vuln-Analysis 的任务是否过于宽泛，导致大量候选只有一句话判断？
- 查看子 Agent 是否提前结束、错误中断、达到时间/工具调用/Token 预算、发生上下文压缩或输出截断。
- 检查专项 Agent 是否把大量时间花在重复枚举 Source/Sink，而不是深入分析已定位的路径。

建议对每个阶段输出两个定性统计：`重点候选数量`、`具备实质分析证据的候选数量`，以相同口径计算。不要把所有格式化调用或 HTTP 参数计入高风险分母而制造虚假的低覆盖率。

## 5. P1：分析层漏检原因细分

仅对 `inspected` 或 `analyzed` 但未成功报告的已知漏洞分类：

| 分类编码 | 含义 | 可供后续改造的方向 |
|---|---|---|
| `path_not_traced` | Agent 定位到 Source/Sink，但没有完成关键跨方法/跨类路径 | 定向路径提示或调用图辅助 |
| `control_misread` | 错判参数化、校验、Sanitizer、对象所有权、鉴权边界 | Java 框架语义知识/专项推理改造 |
| `reachability_misread` | 错判外部入口、权限、部署条件或前置状态 | Recon 与可达性证据增强 |
| `reasoning_incomplete` | 缺少关键推理步骤，过早得出安全结论 | 分析检查点与独立复核 |
| `budget_or_context` | 超时/Token/上下文截断造成分析中断 | 任务切分和预算重分配 |
| `candidate_not_queued` | 已提出候选但未进入 Exploit 队列 | 归并/队列规则核对 |
| `exploit_failed` | 正确漏洞未构造出有效验证步骤 | Exploit 改造 |
| `record_failed` | 已有有效影响证据但重放或断言失败 | Record 排错 |
| `ground_truth_or_scope` | 标签、目标版本、可达性或攻击模型不符合 | 修正评测集合，勿作为算法漏检 |
| `unknown` | 证据不足 | 补全日志后再分类 |

每个案例保留**一个主因**（最早实质性流失）和可选次因；不应为了凑类别凭空推断模型的“心理原因”。

## 6. P1：做小规模对照与效率统计

建议在完成 3–5 个漏检案例的追踪后，再进行可控 A/B 实验：

- A：禁用 Source/Sink 辅助工具，保留原有 Agent 搜索路径。
- B：启用辅助工具，其他条件不变。
- 记录每次 `Shannon commit`、目标项目 commit、模型及采样配置、总预算、认证/服务状态、运行 ID。若不能固定随机性，对每组做多次重复并报告波动；不要凭单次运行断言提升或下降。
- 以**已知真实漏洞**为单位比较：是否定位、是否实质分析、是否提出候选、是否进入队列、最终是否 Record 通过。
- 同时记录：各阶段耗时、LLM 输入/输出 Token、缓存 Token、LLM 花费、工具调用总数、代码搜索/读取次数、静态工具扫描时间、子任务失败数。当前 `task-tool.ts` 的子 Agent 已有 usage 与工具执行 trace 相关机制，可优先复用。
- 两组都要覆盖**相同的真实漏洞标签**，且避免让真值在 A 组与 B 组的 Agent 上下文中出现。

### 推荐指标与口径

- `sink_location_recall = 已知漏洞关键 Sink/边界已定位数 / 适用已知漏洞数`
- `deep_analysis_coverage = 已知漏洞关键路径有实质分析证据数 / 适用已知漏洞数`
- `candidate_recall = 已知漏洞形成明确候选数 / 适用已知漏洞数`
- `final_verified_recall = Record 通过的已知漏洞数 / 适用已知漏洞数`
- `handoff_retention = 上阶段已定位且应交接的关键线索在下阶段实际可见数 / 上阶段应交接关键线索数`
- `incremental_location_recall = B 找到而 A 未找到的已知漏洞关键位置数 / 适用已知漏洞数`
- `efficiency_gain`：在漏洞检出率相近时，比较总耗时、Token、费用相对变化；报告真实数值，避免没有基线的百分比。

## 7. 单漏洞归因记录模板

建议 CSV/JSON 均保存一份；至少有以下字段：

```json
{
  "case_id": "java-case-001",
  "target_commit": "<git_sha>",
  "shannon_commit": "<git_sha>",
  "run_id": "<run_id>",
  "vulnerability_type": "injection",
  "ground_truth": {
    "entry": "Controller.java::query",
    "critical_location": "Repository.java::find",
    "scope_eligible": true,
    "evidence_ref": "<ground_truth_reference>"
  },
  "pre_recon": {"status": "located_only", "evidence": "<trace_or_file_reference>"},
  "recon": {"status": "located_only", "evidence": "<trace_or_file_reference>"},
  "vuln_analysis": {"status": "inspected", "evidence": "<trace_or_file_reference>"},
  "queue": {"status": "not_found", "evidence": "<queue_file_reference>"},
  "exploit": {"status": "not_found", "evidence": "<log_reference>"},
  "record": {"status": "not_found", "evidence": "<log_reference>"},
  "tool": {
    "index_found": true,
    "tool_returned": true,
    "agent_consumed": true,
    "constant_filtered": false
  },
  "first_loss_stage": "vuln_analysis",
  "root_cause_primary": "path_not_traced",
  "root_cause_secondary": "budget_or_context",
  "notes": "<brief factual description>"
}
```

这里的样例字段仅用于说明结构，不代表实际发现；状态必须由日志证据填充。`first_loss_stage` 不等于最后失败阶段。

## 8. 最终交付物（必须）

1. **`diagnosis_summary.md`**：样本表、实验条件、最关键的 3–5 个发现、统计汇总、主要瓶颈排序、每个建议的证据支持。
2. **`case_diagnosis.json` / `.csv`**：每个已知漏洞的逐阶段状态、首次流失点、主因/次因与证据链接。
3. **`tool_ablation.md`**：若已有工具开关可控则提交 A/B 检出率与运行开销；否则注明缺少哪些数据，不能填造数值。
4. **`evidence/`**：必要的脱敏日志摘录、代码位置、阶段工件索引、相关调用轨迹。尽量引用原始运行产物，不复制整份敏感 HTTP 交换数据。
5. **`next_actions.md`**：最多推荐 1–2 项下一步优化，每项都须写明“命中哪类漏检、为什么会改善、怎样做最小 PoC 证伪”。

## 9. 验收标准

- 所有案例能从真实漏洞标签追溯到关键代码位置与每阶段工件。
- `located_only`、`inspected`、`analyzed` 的判定符合统一标准，不能以“某文件在报告中出现”代替已分析。
- 至少 3 个真实漏检案例归因完毕；如果现有运行日志不足，明确列出“缺失哪条证据、建议添加哪个观察日志”，不可用猜测填充。
- 明确回答三个问题：**最大流失阶段是什么？原有工具有无实际增量？下一步应优先改善分析覆盖、路径关联、知识判断还是验证机制？**
- 不要求本轮提交新的扫描算法、知识库或 Workflow 改造。

## 10. 同事实施顺序

**先从现有运行工件开始，不急于重复跑扫描。** 优先完成第 1–4 节，拿到第一张逐漏洞漏检表后再决定是否需要增加日志或补做 A/B。若已发现主要问题是某一阶段输出/交接损失，可以直接细查该阶段，不必机械地做完整实验。

---

### 关联仓库位置（参考）

- [Shannon Pipeline 文档](https://github.com/GinRawin/Shannon/blob/main/SHANNON_PIPELINE.md)
- [子 Agent 创建与工具注入](https://github.com/GinRawin/Shannon/blob/main/apps/worker/src/ai/pi/task-tool.ts)

本清单为调查规格，结论必须由运行证据产生，不预设某一 Agent 或新工具存在缺陷。
