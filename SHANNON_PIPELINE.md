# Shannon Pipeline 简介

Shannon 是一个面向 Web 应用的自动化安全测试系统。它结合源码分析、应用侦察和动态验证，将一次扫描拆分为多个职责明确的 Agent 阶段。

## Pipeline 总览

```text
认证预检（可选）
        ↓
Pre-Recon 源码预侦察
        ↓
Recon 应用侦察
        ↓
漏洞分析（5 个并行 Agent）
        ↓
结果归并与利用任务形成
        ↓
漏洞利用（按类别并行执行）
        ↓
Report 最终报告
```

## 1. 认证预检

如果扫描提供了登录配置，Shannon 会先完成一次登录并保存浏览器认证状态。后续需要认证的 Agent 可以加载这个状态，避免重复登录。

主要输出：

- 可复用的浏览器认证状态
- 登录是否成功的验证结果

## 2. Pre-Recon：源码预侦察

Pre-Recon Agent 从源码中建立应用的基础安全地图，包括：

- 技术栈和目录结构
- 路由、控制器和 API 入口
- 数据库、命令执行、文件操作等敏感位置
- XSS、SSRF 等潜在 sink
- 认证、授权和 Session 相关实现

主要输出：`.shannon/deliverables/pre_recon_deliverable.md`

该阶段主要收集情报，不负责确认漏洞。

## 3. Recon：应用侦察

Recon Agent 综合源码情报和运行中的 Web 应用，整理：

- 可访问页面和 API
- 请求方法、参数和输入向量
- 登录后功能和用户工作流
- 应用架构及已有安全控制
- 后续漏洞分析需要优先检查的目标

主要输出：`.shannon/deliverables/recon_deliverable.md`

## 4. Vulnerability Analysis：漏洞分析

Shannon 并行运行五个专项 Agent：

| Agent | 主要检查内容 |
|---|---|
| Injection | SQL 注入、命令注入、路径遍历、文件包含、SSTI、反序列化 |
| XSS | Reflected、Stored 和 DOM XSS |
| Auth | 登录、Session、Token、密码恢复、OAuth 和爆破防护 |
| Authz | 水平越权、垂直越权、跨租户及工作流越权 |
| SSRF | 用户输入到服务端网络请求的数据流和网络边界控制 |

分析 Agent 通常执行以下工作：

1. 从 Recon 和 Pre-Recon 获取待检查的输入点或敏感 sink。
2. 追踪 `source → transformation/sanitizer → sink` 数据流。
3. 判断安全控制是否适合最终使用上下文。
4. 必要时使用最小 PoC 对运行中的应用进行验证。
5. 记录确认安全的路径、分析盲区和候选漏洞。

每类 Agent 会生成：

- 分析报告，例如 `injection_analysis_deliverable.md`
- 结构化利用队列，例如 `injection_exploitation_queue.json`

只有外部攻击者能够通过目标 Web 应用触发的候选漏洞才进入利用队列。

## 5. Reconciliation：结果归并

Shannon 会将漏洞分析结果与其他安全发现进行整理和归并，主要处理：

- 重复或高度相关的发现
- 不同来源提供的补充证据
- 漏洞类别和字段规范化
- 后续 Exploit Agent 所需的任务形成

这一步的目的是形成清晰、可执行的利用任务，避免重复测试同一个问题。

## 6. Exploitation：漏洞利用

Exploit Agent 读取对应类别的 exploitation queue，对候选漏洞进行真实目标验证。

它不仅确认“漏洞机制是否存在”，还要证明实际影响。例如对于 SQL 注入：

```text
分析阶段：证明输入可以改变 SQL 查询结构
利用阶段：识别数据库、枚举结构，并证明可以读取非授权数据
```

每个候选项最终会得到类似结论：

- `exploited`：已获得可重复的实际影响证据
- `blocked`：漏洞存在迹象，但受外部条件限制，无法完成影响验证
- `false positive`：经过系统测试后确认不可利用

主要输出示例：`.shannon/deliverables/injection_exploitation_evidence.md`

## 7. Record：重放验证与数据包登记

Record Agent 在 Exploit Agent 完成后读取已发现漏洞及其利用命令，重放能够安全复现的 HTTP 请求，并保存真实请求/响应数据包。它还会检查是否存在对应的前端入口；找到时会记录页面 URL、按钮或输入框位置和触发步骤，无法确认时会明确标注。只有重放成功且响应再次证明影响的漏洞会进入最终报告；失败、无法安全重放或结果不确定的项目会写入 `.shannon/deliverables/pending_manual_verification.md`，等待人工复核。

主要输出包括 `record_verification.json`、`pending_manual_verification.md` 和各类别的 `*_recorded_exploitation_evidence.md`。采集到的 HTTP 数据包保存在 `.shannon/deliverables/http-exchanges/`。

## 8. Explore：模板扩展

Explore Agent 只根据 record 通过的漏洞及其 sink 代码位置提炼少量搜索模板（例如 SQL 执行调用的正则），不负责扫描源码。随后由确定性程序用 ripgrep 搜索源码，校验模板确实匹配原 sink，并把命中位置交给对应类别的漏洞分析 Agent 做一次定向复核。

扩展分析只确认这些位置是否属于已验证漏洞的同一模式；不新增漏洞 ID，也不再次运行 exploit 或 record。确认的代码位置会补充到原漏洞报告。整个扩展只执行一轮，不递归回到 Explore。

主要输出：`explore_templates.json`、`explore_search_results.json` 和各类别的 `explore_expansion_*.md`。

## 9. Report：最终报告

Report Agent 汇总经过验证的结果，生成面向用户的安全评估报告，通常包括：

- 执行摘要
- 漏洞描述和严重性
- 受影响端点与代码位置
- 可复现步骤和利用证据
- 实际安全影响
- 修复建议
- 测试范围和限制

最终报告会输出为 Markdown 和 PDF。

## Analysis 与 Exploit 的区别

| 阶段 | 核心问题 |
|---|---|
| Analysis | 这里是否存在一条可信的漏洞路径？ |
| Exploit | 这条路径在真实目标上能够造成什么实际影响？ |

Analysis 强调覆盖面、数据流和安全控制是否匹配；Exploit 强调真实验证、影响证明和证据可复现。两者可能都会运行 PoC，但目的和完成标准不同。

## 主要交付物流转

```text
pre_recon_deliverable.md → recon_deliverable.md → 漏洞分析 Agent
                                                       │
                                                       ↓
                                                   exploit
                                                       ↓
                                                    record
                                                       ↓
                                      Explore 模板提取 → 确定性源码搜索
                                                       │
                 命中位置 + 已验证漏洞模板           │
                 ┌─────────────────────────────────────┘
                 ↓
         同类别漏洞分析 Agent（仅定向复核一轮）
                 │ 补充原漏洞的代码位置
                 ↓
       Security-Assessment-Report.md / PDF
```

