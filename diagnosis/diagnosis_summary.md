# Shannon 漏检归因诊断 — 2026-11-25 批次（3 个 Java 目标）

> 任务性质：诊断（只读）。未改动 Prompt / 模型 / Workflow / 安全分析策略。
> 结论仅由运行工件产生，证据路径均可在仓库内追溯；无法从工件判定的字段一律标 `unknown`。

## 1. 实验条件与样本

批次队列：`/home/hjr/pentest20261104/pentest20261104.jsonl`
批次状态：`/home/hjr/pentest20261104/pentest20261104.jsonl.shannon-batch-state.json`

昨日（2026-11-25）批次共 4 个目标，其中 **3 个完成、1 个在认证阶段失败**（`qiongchi-dev.ap` → `AUTH_LOGIN_FAILED`，仅 1 个 agent 日志、无 deliverables，排除）：

| 目标 | run_id | 源码仓库 | 状态 |
|---|---|---|---|
| ai-media-fusion-platform-uat | `…shannon-1795599033612` | `/repos/ai-media-fusion-platform-uat-volc` | completed |
| cp-dev-office-ap | `…shannon-1795606717356` | `/repos/zjsystem-cloud-dev` | completed |
| imwl-uat-app | `…shannon-1795616687586` | `/repos/imwl-武器库` | completed |
| (qiongchi-dev-ap) | `…shannon-1795616643707` | `/repos/dmz-fmp-dev-260617` | failed(AUTH_LOGIN_FAILED)，不计入 |

模型：`ep-20260921205410-m6s4d`（3 run 一致）。工件根：`workspaces/<run_id>/.shannon/`。

## 2. 统一状态口径

- `queued`：该漏洞类 `*_exploitation_queue.json` 中的候选数（分析阶段产物，进入 Exploit 的输入）。
- `exploited`：`*_exploit_collector.json` 中 `status=exploited`（拿到运行时影响证据）。
- `blocked`：`status=blocked`（Exploit 实际尝试但未取得运行时证据）。
- `unprocessed`：队列中存在、但 `*_exploitation_evidence.md` 的 **“Unprocessed Vulnerabilities”** 段列出的候选。**2026-11-26 复核更正**：本批 32 项 `unprocessed` 并非真的无裁决——Exploit agent 已逐条测试并把假阳性结论写入每类的 `*_false_positives.md` 跟踪文件，但 `apps/worker/src` 中没有任何代码读取该文件；渲染器按 `Unprocessed = 队列 ID − add_exploit ID` 计算，因此这些 FP 裁决被错误计入 `unprocessed`（详见“发现 1（更正）”）。
- `record-verified`：`record_verified_finding_ids.json`。
- `reported`：`report.json::findings`。
- `record-excluded`：`record_report_exclusions.json`（已 exploited 但因重放/证据缺陷被剔除出报告）。

## 3. 逐阶段漏斗（以“进入队列的候选”为单位）

| run | queued | exploited | blocked | unprocessed | record-verified | reported | record-excluded |
|---|---:|---:|---:|---:|---:|---:|---:|
| ai-media | 49 | 21 | 22 | 6 | 20 | 19 | 3 |
| cp-dev | 60 | 11 | 29 | 20 | 11 | 11 | 3 |
| imwl | 63 | 37 | 20 | 6 | 36 | 34 | 1 |
| **合计** | **172** | **69** | **71** | **32** | **67** | **64** | **7** |

口径核验：`exploited + blocked + unprocessed = 172 = queued`（逐 run 一致）。

阶段耗时（`session.json::metrics.phases`）：三个 run 的耗时集中在 **exploitation 阶段**（ai-media 8995s/63.5%、cp-dev 9476s、imwl 10936s），vulnerability-analysis 次之（2953s / 4730s / 5339s）。

## 4. 关键发现（按影响排序）

### 发现 1（最大流失，已更正）32 项 `unprocessed` 实为**已裁决的假阳性**，未被流水线读取（**非预算/调度问题**）
> 2026-11-26 复核更正：上一版本将此归为 `budget_or_context`（“队列未跑完，agent 在写回裁决前结束”）。逐条复核后确认该归因**错误**。

Exploit agent 在每个 `*_exploitation_evidence.md` 末尾维护一份 **“Unprocessed Vulnerabilities”** 列表。逐条核对后确认：**这 32 项候选中 32/32 都在对应类别的 `*_false_positives.md` 跟踪文件中留有明确的假阳性（FP）裁决**——它们不是“连尝试都没尝试”，也**不是预算/调度耗尽**；agent **已逐条测试并判定为 false positive**。问题在于该裁决没有机器可读出口：

- Exploit agent 的结构化出口 `add_exploit` 的 `status` 仅有 `exploited`/`blocked`，**没有 `false_positive`**（`apps/worker/src/collectors/exploit-collector.ts`）。
- 假阳性被 Prompt 要求写入 `workspace/<class>_false_positives.md`（`apps/worker/prompts/exploit-*.txt`），但 `apps/worker/src` 中**没有任何代码读取该文件**——它是 write-only 的。
- 渲染器按 `Unprocessed = 队列 ID − add_exploit ID` 计算（`apps/worker/src/services/exploit-renderer.ts`），因此从未进入 `add_exploit` 的 FP 裁决必然落入 `unprocessed`。

`unprocessed` 清单（不变）：ai-media 6（`AUTH-10/11/12`、`AUTHZ-17`、`XSS-01/02`）；cp-dev 20（`AUTH-11`、`AUTHZ-07..13/16..22`、`XSS-08/09`、`SSRF-04`、`INJ-05/06/07`）；imwl 6（`AUTHZ-01/20`、`INJ-01/02/03`、`XSS-05`）。

证据：
- `workspaces/<run>/.shannon/deliverables/*_exploitation_evidence.md`（“## Unprocessed Vulnerabilities” 段）；
- `workspaces/<run>/.shannon/scratchpad/<class>_false_positives.md`（逐条 FP 裁决；例如 cp-dev `authz_false_positives.md` 明确列出 AUTHZ-07..13/16..22 为 FP）；
- 逐条命中核对：32/32 全部在 FP 文件中出现，0 项缺失。

命中类型：`pipeline_gap`（裁决无法进入结构化出口），**不是** `budget_or_context`。修复见 `next_actions.md` 建议 A。

### 发现 2 Record/重放阶段因“计划格式缺陷”丢弃已成功利用的真实漏洞（7 项）
`record-verification-failures.jsonl` 的 `review_verdict=retry` 且 `review_reason` 明确“not a false positive”，但最终被 `record_report_exclusions.json` 剔除：

| run | finding | 失败原因（原文摘要） |
|---|---|---|
| ai-media | AUTH-02 | `Extracted variables must have uppercase names distinct from operator variables`（重放计划变量命名规则）；另有 setup 用了 `POST` 但接口实为 `GET` |
| ai-media | AUTHZ-13 | 雪花 ID 精度丢失（`…630000` vs 真实 `…629890`）+ 绝对计数断言 `{"data":9}` 不稳定 |
| ai-media | AUTHZ-26 | `Replay plan contains literal authentication material`（断言内联了操作者账号 literal） |
| cp-dev | AUTH-01 | 同上，变量命名规则 |
| cp-dev | AUTH-02 | 同上，变量命名规则 |
| cp-dev | XSS-01 | 浏览器重放失败，`No trusted JavaScript execution receipt was produced` |
| imwl | XSS-03 | 同上（sink 在 URL hash，仅有 `browser_replay`，`verify_http_replay` 报 `no_http_replay_plan`，缺 `complete_http_packet`） |

剔除理由（`record_report_exclusions.json`）：`missing verified Record verdict` / `missing complete associated HTTP packet` / `missing JavaScript execution evidence`。
命中类型：`record_failed`。这是纯工程缺陷，**不是漏洞不存在**。

### 发现 3 报告的“覆盖完整性”声明与实际工件不一致
三个 run 的 `report.json::report_meta` 均写 `coverage.status=complete`、`limitations: []`，执行摘要还写明“**本次评估不含仅由源码确认、因外部约束而无法在线验证的发现**”。
但同一 run 内存在 71 项 `blocked` 候选（含 Injection/XSS 整类 0 报告）——另有 32 项 `unprocessed` 经复核实为假阳性（见“发现 1（更正）”，不应计入未验证）。**这些真正未取得运行时证据（blocked）的候选没有被作为 residual unknown 暴露**，外部视角因此表现为“该类无问题”，与 `toBeCheck.md` 所指的“漏检”观感一致。
命中类型：`reasoning_incomplete` → 报告/覆盖语义缺陷（把“未验证”当作“无问题”）。

### 发现 4 Source/Sink 候选工具（`find_security_candidates`）调用不一致
`docs/java-security-candidates.md`：该工具仅注册给 `pre-recon`/`recon`，返回候选位置并写入 `scratchpad/security-candidates/*.txt`。
实测调用（`grep` agent 日志 + scratchpad 目录）：
- ai-media：**0 次调用**、无候选文件（该 run 完全未使用工具）。
- cp-dev：6 次，仅生成 `injection.txt/authz.txt/ssrf.txt`（无 auth/xss）。
- imwl：3 次，仅生成 `injection.txt/ssrf.txt`（无 auth/authz/xss）。

因此**无法从本批次得出工具增量结论**（既非受控 A/B，覆盖类型也不一致）；`index_found`（底层全量索引是否命中真值）在工件中不可见 → 标记 `unknown`。

### 发现 5（结构性）可达性受“采样账户 URL 授权白名单”约束
Exploit 阶段以某一低权限账户（cp-dev 为 `ROLE_wxUser`）的 gateway 白名单为准，白名单外一律 `HTTP 200 {"code":500,"msg":"没有权限"}`（`AuthFilter` 默认拒绝）。多项 `blocked` 的直接原因即“该接口不在采样账户授权范围内”，例如 `INJ-13`（FastJson2 反序列化：写入原语接口 `…/vehicle/module/config/signal` 不在白名单）。
影响：**验证召回率依赖采样账户的权限覆盖**；这也解释了 cp-dev 中大量“管理端/纵向越权”类候选被留白。

## 5. 主要瓶颈排序

1. **验证阶段（Exploit/Record）** —— 172 个入队候选中 103 个（60%）没有拿到运行时证据（71 blocked + 32 unprocessed）；但这 32 个 `unprocessed` **不是未尝试**，而是**已判定为假阳性**的候选因缺少结构化出口被误计入（见“发现 1（更正）”）。
2. **Record/重放工程缺陷** —— 7 个已 exploited 的真实漏洞被计划格式缺陷剔除（约占 exploited 的 10%）。
3. **覆盖语义** —— 未验证候选未作为 residual unknown 暴露，报告宣称 complete，掩盖了上述流失。
4. **检测/分析阶段** —— 本批次 3 个 run 在 5 类均产出了成规模候选队列（49/60/63 项），**未见“定位不到”的系统性证据**；本批次的主要流失不在“发现/定位”。

## 6. 三个必答问题

- **最大流失阶段是什么？** Exploit 验证阶段（`unprocessed` 32 项 = **已裁决的假阳性**因缺少 FP 出口而被误计，属流程缺陷而非预算流失；叠加 `blocked` 71 项则为最大且覆盖全部 3 个 run 的瓶颈）。
- **原有工具有无实际增量？** 无法判定。工具在 1/3 run 完全未调用、且覆盖漏洞类型不一致；缺 `index_found`/`agent_consumed` 记录与受控 A/B → 结论为 `unknown`，不填造数值（见 `tool_ablation.md`）。
- **下一步应优先改善哪一环？** **验证机制（verification）** 优先，其次 **Record 重放工程**。分析/定位覆盖在本批次已足够产出候选，不是当前首要矛盾。

## 7. 数据缺口（无法从现有工件判定，需补证据）

- 真值标签未随工件提供：`case_diagnosis.json` 的“漏检”归因建立在**阶段流失**（found/queued → verified）之上；若要与“已知漏洞真值”逐条对齐，需离线提供 Truth 列表（不得注入 Agent 上下文）。
- `find_security_candidates` 的 `index_found`（全量索引命中）不可见：需工具侧记录返回前是否命中真值位置。
- ~~Exploit agent 结束原因：日志中无显式 budget/turn/timeout 记录，`unprocessed` 的触发条件为 `unknown`。~~ 已更正：`unprocessed` 的成因已定位为 FP 裁决缺少结构化出口（见“发现 1（更正）”），无需再依赖 budget/timeout 推断。
- Explore(AST 克隆) 扩展产物（`explore_expansion_*`）已按规范**未计入**主流程漏检归因。

## 8. 证据索引

见 `diagnosis/evidence/index.md`；结构化逐 run 数据见 `diagnosis/case_diagnosis.json` / `.csv`；工具对照见 `diagnosis/tool_ablation.md`；下一步建议见 `diagnosis/next_actions.md`。
