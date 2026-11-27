# 证据索引 — 2026-11-25 批次（3 run）

所有路径相对仓库根。`<run>` ∈
`ai-media-fusion-platform-uat-immotors-com_shannon-1795599033612` /
`cp-dev-office-ap-immotors-com_shannon-1795606717356` /
`imwl-uat-app-immotors-com_shannon-1795616687586`。

## 批次与运行元数据
- 批次队列/状态：`/home/hjr/pentest20261104/pentest20261104.jsonl`、`…jsonl.shannon-batch-state.json`
- 运行元数据/阶段耗时/agent 状态：`workspaces/<run>/.shannon/session.json`
- 顶层扫描日志：`workspaces/<run>/.shannon/workflow.log`

## 各阶段工件（`workspaces/<run>/.shannon/`）
- Pre-Recon / Recon：`deliverables/pre_recon_deliverable.md`、`deliverables/recon_deliverable.md`
- 分析：`deliverables/{class}_analysis_deliverable.md`（class ∈ auth/authz/xss/ssrf/injection）
- 队列（分析→验证输入）：`deliverables/{class}_exploitation_queue.json`
- Exploit 取证与逐条裁决：`deliverables/{class}_exploitation_evidence.md`、`deliverables/{class}_exploit_collector.json`
- Exploit 复核：`deliverables/exploit_review_{class}.json`
- 归并/血缘：`deliverables/{class}_reconciliation_manifest.json`、`deliverables/{class}_renumber_map.json`
- Record：
  - 通过集合：`deliverables/record_verified_finding_ids.json`
  - 失败明细：`deliverables/record-failures.json`
  - 失败原因流：`deliverables/record-verification-failures.jsonl`
  - 剔出报告：`deliverables/record_report_exclusions.json`
  - 校验文本：`deliverables/record_verification.md`、`deliverables/record_verification.json`
- 报告：`deliverables/report.json`、`deliverables/report.sarif`、`deliverables/comprehensive_security_assessment_report.md`
- Agent 日志：`agents/*.log`（含 `{class}-exploit.log`、`record.log`、`record-retry.log`、`record-failure-review.log`）
- 工具候选文件：`scratchpad/security-candidates/*.txt`
- FP 记录（由 agent 写出）：`scratchpad/*_false_positives.md`

## 关键证据点（可复现命令）
- **发现 1（unprocessed 32 项）**：每个 `deliverables/{class}_exploitation_evidence.md` 的 “## Unprocessed Vulnerabilities” 段。
  `grep -rn "Unprocessed Vulnerabilities" workspaces/<run>/.shannon/deliverables/`
- **发现 2（record 剔除 7 项）**：`deliverables/record-verification-failures.jsonl` 的 `review_reason`（含 “not a false positive”）与 `deliverables/record_report_exclusions.json` 的 `reasons`。
- **发现 3（覆盖声明不一致）**：`deliverables/report.json::report_meta.coverage`（`status=complete`,`limitations=[]`）对比同 run 的 `unprocessed`(32)/`blocked`(71)。
- **发现 4（工具调用不一致）**：
  `grep -rc find_security_candidates workspaces/<run>/.shannon/agents/` 与
  `ls workspaces/<run>/.shannon/scratchpad/security-candidates/`
  （ai-media 无目录/0 命中；cp-dev、imwl 仅部分类型）。
- **发现 5（白名单可达性）**：`agents/*-exploit.log` 中 `{"code":500,"msg":"没有权限"}` 与 “not in the allow-list” 措辞；`deliverables/*_exploitation_evidence.md` 的 “current_blocker/How This Would Be Exploited”。

## 结构化汇总
- `diagnosis/case_diagnosis.json`（逐 run / 逐 class 漏斗 + unprocessed/excluded 列表）
- `diagnosis/case_diagnosis.csv`（同上，表格化）
