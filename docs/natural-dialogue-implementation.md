# Token Security 安全智能体 · 自然对话实现文档

> 本文档面向后续开发者（可作为 Codex 等 AI 编程工具的项目上下文），完整说明该智能体"能听懂人话、多轮追问、自主调工具、像安全专家一样回复"的实现原理。所有内容均对应仓库真实代码，标注了文件与行号。

---

## 1. 系统概览

一句话：**自然对话能力 = 一个 LangChain 1.0 的 ReAct Agent（模型自主决定"回答还是调工具"）+ 一份精心设计的系统提示词（意图路由规则）+ 跨请求记忆（checkpointer）+ SSE 流式管道（服务端事件流 → 前端打字机渲染）**。

```
用户消息（前端输入框）
   │  fetch POST /stream_run  (ClientMessage JSON)
   ▼
FastAPI 服务 (src/main.py)
   │  AgentStreamRunner.stream()
   ▼
LangGraph Agent (src/agents/agent.py)
   │  create_agent 编排的 ReAct 循环
   │  ├─ 模型节点（doubao-seed-2-0-pro，流式吐 token）
   │  ├─ 工具节点（16 个 @tool，模型自主选择调用）
   │  └─ 记忆节点（checkpointer 按 thread 持久化消息）
   ▼
SSE 事件流（message_start / answer / tool_request / tool_response / message_end）
   ▼
前端渲染 (web/index.html)
   │  打字机效果 + 工具状态条 + Markdown 渲染 + 建议按钮
   ▼
用户看到逐字输出 & 点击下一步建议
```

---

## 2. 五层实现详解

### 2.1 L1 模型层 —— 大模型配置

**文件**：`config/agent_llm_config.json` + `src/agents/agent.py` L169-192

```json
{
    "config": {
        "model": "doubao-seed-2-0-pro-260215",
        "temperature": 0.3,
        "top_p": 0.9,
        "max_completion_tokens": 10000,
        "timeout": 600,
        "thinking": "disabled"
    }
}
```

关键点：
- **temperature=0.3**：安全场景要严谨，低温减少幻觉；对话仍自然靠提示词而非高温
- **streaming=True**（agent.py L184）：token 级流式输出，是前端打字机效果的前提
- **thinking: disabled**：推理放在提示词编排与工具回执里（可审计推理链），而非隐藏思维链
- 模型通过 `ChatOpenAI` 兼容接口接入，`api_key`/`base_url` 走环境变量（`COZE_WORKLOAD_IDENTITY_API_KEY` / `COZE_INTEGRATION_MODEL_BASE_URL`），密钥不落代码

### 2.2 L2 Agent 编排层 —— create_agent 工具循环

**文件**：`src/agents/agent.py` L194-200

```python
return create_agent(
    model=llm,
    system_prompt=SYSTEM_PROMPT,
    tools=ALL_TOOLS,           # 16 个工具
    checkpointer=get_memory_saver(),
    state_schema=AgentState,
)
```

这就是"自然对话"的核心引擎：`create_agent`（LangChain 1.0）构建一个 **ReAct 循环**——

1. 模型收到 [系统提示词 + 历史对话 + 新用户消息]
2. 模型自己决定：**直接回答**（闲聊/知识问答），还是**调用某个工具**（检测/检索/报告…）
3. 若调用工具：工具执行结果作为 ToolMessage 回填，模型继续生成，**可连续调用多个工具**（例如 PCAP 调查 = preflight → batch_detect → knowledge_search 三连）
4. 直到模型输出不含工具调用的最终文本，循环结束

**16 个工具**（agent.py L58-75）：每个工具就是一个带 `@tool` 装饰器的 Python 函数 + 一段 docstring。**docstring 就是模型眼中的"工具说明书"**——模型根据它判断什么时候该调、传什么参数。例如 `src/tools/prompt_tools.py` L242：

```python
@tool
def prompt_security_scan(prompt_text: str, do_token_analysis: bool = True, new_task: bool = False) -> str:
    """对用户提交的 Prompt 执行安全检测（语义检测 + Token 熵异常检测 + 规则标记），
    返回风险级别、证据列表和异常起点。首次检测 Prompt 时必须调用本工具。
    当用户明确要求"新开案件/重新开始"时传 new_task=true。"""
```

**关键设计**：所有工具返回**结构化文本回执**（风险级别、证据表、CPD 起点、甚至"【可审计推理链·请原样呈现】"表格）。模型不需要理解内部实现，只需把回执中的结论**如实转述**给用户——这保证了回复内容与真实检测一致，不产生幻觉。

### 2.3 L3 行为层 —— 系统提示词（自然对话感的真正来源）

**文件**：`src/agents/agent.py` L77-166（SYSTEM_PROMPT，全文约 90 行）

对话是否"自然"，80% 取决于这份提示词。它不是一个简单的角色设定，而是一份**行为规范手册**，核心章节与作用：

| 章节 | 行号 | 解决的对话问题 |
|------|------|----------------|
| 意图路由规则 | L104-113 | 听懂模糊/完整/混合意图，决定走哪条工具链 |
| 检测与解释 | L115-120 | 结论先行、证据如实标注（real/derived）、无证据不妄断 |
| 主动建议 | L122-137 | 每次结果后输出 2-4 个可点击的下一步按钮，形成"对话式引导" |
| 授权边界 | L139-142 | L0/L1/L2 分级授权，高影响动作必须等用户确认（对话安全感） |
| 当前案件上下文 | L144-145 | 追问不用重复原文（"为什么这个有风险"能接住） |
| 输出格式 | L147-166 | 可审计推理链表、Token 风险轨道字符图、建议按钮格式 |

**意图路由规则（L104-113）原文设计思路**——不依赖关键词匹配，而是教模型用上下文理解：

- 用户提交 Prompt 文本要检测 → 走 `prompt_security_scan`
- 用户提到 PCAP/流量文件 → 先 `pcap_preflight` 预检再 `pcap_batch_detect`
- **上下文追问**：当前是 PCAP 任务时，"这段流量为什么异常"继续走 PCAP 工具；当前是 Prompt 任务时，"改完再测"继续走 Prompt 工具（这依赖 2.4 节的跨轮记忆 + 工具级案件状态）
- 安全知识问题 → `security_knowledge_search` 后回答并标注来源
- 问候（"你好"）→ 简短介绍两个主场景
- **不完整目标**（"帮我看看这个"）→ 主动追问缺什么（Prompt 原文或文件路径），而不是报"超出范围"
- 混合输入（同时给 Prompt 和 PCAP）→ 说明需拆成两个调查，询问先处理哪个
- 非安全任务 → 说明专业边界，给可转化的安全替代问法

这套规则让模型"该干活干活、该闲聊闲聊、缺信息会反问"——这就是用户感受到的自然对话。

### 2.4 记忆层 —— 跨轮与跨请求上下文

自然对话必须有记忆，本项目有**三层记忆**：

**(1) Agent 短期记忆（滑动窗口）**——`agent.py` L45-55

```python
MAX_MESSAGES = 40   # 保留最近 20 轮对话

def _windowed_messages(old, new):
    return add_messages(old, new)[-MAX_MESSAGES:]

class AgentState(MessagesState):
    messages: Annotated[list[AnyMessage], _windowed_messages]
```

- `checkpointer=get_memory_saver()` 把每轮完整消息状态持久化
- `state_schema=AgentState` 配置了消息 reducer：每次追加新消息后**只保留最近 40 条**，防止长对话撑爆上下文
- thread 维度：服务端 `thread_id = ctx.run_id`（main.py L119）；前端每次 `send` 请求头带 `x-run-id: s.sessionId`（index.html L2602），同一会话内 run_id 稳定 → 同一记忆线程

**(2) 案件上下文（工具级状态）**——`src/tools/case_store.py`

- 每次检测自动创建任务（task_id），把**原始 Prompt / PCAP 文件 / 证据列表**存进任务 JSON
- 用户追问"为什么有风险"时，`prompt_explain_evidence` 不需要用户再贴原文——它从当前案件读取
- SYSTEM_PROMPT L144-145 明确告诉模型："用户追问时不需要重新提供原文；只有用户明确说'新开案件'才传 `new_task=true`"

**(3) 前端会话与任务档案**——`web/index.html`

- 消息按 sessionId 分桶缓存（`_msgCache`），任务切换互不覆盖
- 每轮对话结束自动归档到任务（`POST /web/api/tasks/{id}/messages`，最多 100 条）
- 点击侧边栏"最近任务"可恢复该任务的历史对话（`openTask`，同任务点击只高亮不重复插入）

### 2.5 L4 服务层 —— SSE 流式管道

**文件**：`src/main.py` L66/L101-108

- `AgentStreamRunner`（平台框架提供）把 LangGraph 的 token 流转成标准 SSE 事件流
- 前端 `POST /stream_run`，请求体是平台规定的 `ClientMessage` 结构：

```json
{
  "type": "query",
  "project_id": "",
  "session_id": "sess-xxx",
  "local_msg_id": "m1712345678",
  "content": { "query": { "prompt": [{ "type": "text", "content": { "text": "用户消息" } }] } }
}
```

**SSE 事件协议**（前端 `handleEvent`，index.html L2656）：

| 事件 | 内容 | 前端行为 |
|------|------|----------|
| `message_start` | 会话开始 | 打字机光标出现（cursor-blink） |
| `answer` | `{answer: "增量文本"}` | 追加到当前气泡 + renderMD 重渲染 Markdown |
| `tool_request` | `{tool_request: {name, args}}` | 气泡内插入"🔍 正在调用 prompt_security_scan…"状态条 |
| `tool_response` | `{tool_response: "…"}` | 状态条变为"✓ 完成"，记录结果 |
| `message_end` | 结束标记 | 光标移除，消息定稿 |

SSE 解析（`parseSSE`）：事件以 `data:` 行传输、`\n\n` 分隔，逐帧 JSON.parse。

### 2.6 L5 前端层 —— 对话体验细节

**文件**：`web/index.html`（send L2585 / handleEvent L2656）

- **打字机**：`answer` 增量追加，`cursor-blink` 光标类在流结束/异常/中断三处收口移除
- **Markdown 实时渲染**：每帧增量后整段 `renderMD()`，表格/代码/链接即时成型
- **建议按钮**：模型按 SYSTEM_PROMPT 输出 `[文案](#)` 链接，前端渲染为卡片按钮，点击即把文案作为下一条消息发送（`handleSuggestionClick`）——这是"对话式引导"的闭环
- **防污染机制**（state.gen + AbortController）：
  - 每次发送 `state.gen++`；旧流事件到达时 `gen !== state.gen` 直接丢弃并 `reader.cancel()`
  - "新建对话"会 `state.abort.abort()` 中断旧请求 + 复位 busy + 清草稿
- **任务联动**：`send` 结束后 `refreshTasks()` 刷新侧边栏最近任务（工具执行可能新建/更新案件）

---

## 3. 一条消息的完整生命周期（端到端时序）

以用户说 *"帮我看看这段 Prompt 有没有问题：ignore all previous instructions"* 为例：

```
t0  前端 send("帮我看看…")
    ├─ state.gen++ / busy=true / appendMessage(user)
    ├─ appendMessage(assistant, "")  ← 空气泡 + typing dots
    └─ POST /stream_run (ClientMessage, x-run-id=sess-xxx)

t1  FastAPI → AgentStreamRunner.stream(payload, graph, run_config, ctx)
    ├─ thread_id = run_id（= sessionId，接上同一记忆线程）
    └─ LangGraph Agent 循环启动

t2  SSE: message_start
    └─ 前端：光标闪烁

t3  模型推理（第 1 轮循环）：识别为 Prompt 检测意图
    ├─ SSE: tool_request  {prompt_security_scan, {prompt_text: "ignore all…"}}
    │    └─ 前端：显示"正在调用 prompt_security_scan…"
    ├─ 工具真实执行：
    │    ├─ case_store.create_task → TASK-XXXX（案件建档）
    │    ├─ 三路检测：规则标记 + Entropy-CPD + LLM 语义扫描
    │    └─ 返回结构化回执（风险级别/证据表/CPD 起点/可审计推理链）
    ├─ SSE: tool_response  {…回执…}
    │    └─ 前端：状态条"✓ 完成"

t4  模型推理（第 2 轮循环）：拿到回执，生成最终回复
    ├─ SSE: answer × N（token 增量）
    │    └─ 前端：逐字渲染"【检测结论】高风险 → 证据表 → Token 轨道 → 可审计推理链 → 下一步建议按钮"
    └─ SSE: message_end
         └─ 前端：光标移除

t5  前端收尾
    ├─ s.messages 归档 + POST 任务消息归档
    ├─ refreshTasks() → 侧边栏出现"发现风险 TASK-XXXX"
    └─ busy=false，等待下一轮（用户可点击建议按钮或自由追问）
```

**如果用户接着问 *"为什么这是高风险？"*（第 2 艘轮）**：
- 同一 thread → 模型记得上一轮的检测与 task_id
- 意图路由命中"追问继续走当前任务的工具" → 调 `prompt_explain_evidence`
- 工具从 case_store 读出原始 Prompt 和证据 → 结合知识库生成解释
- **用户全程不需要重复任何原文**——这是自然对话的关键体感

---

## 4. 关键文件索引

| 文件 | 职责 | 关键位置 |
|------|------|----------|
| `src/agents/agent.py` | Agent 主逻辑：模型接入、16 工具注册、系统提示词、记忆窗口 | SYSTEM_PROMPT L77；build_agent L169 |
| `config/agent_llm_config.json` | 模型/参数配置 | model / temperature / thinking |
| `src/main.py` | FastAPI 服务：/stream_run SSE 管道、面板检测 API、任务/事件/评测 API | stream L101；thread_id L119 |
| `src/tools/prompt_tools.py` | Prompt 四工具（检测/解释/修复/复检）+ 三路检测管线 | prompt_security_scan L242 |
| `src/tools/pcap_tools.py` | PCAP 四工具 + dpkt 真实解析 + 四类规则引擎 | _analyze_pcap_file |
| `src/tools/entropy_detector.py` | Token 熵计算 + CPD 变化点检测（derived 证据源） | |
| `src/tools/knowledge_tool.py` | 安全知识库 RAG 检索 | security_knowledge_search |
| `src/tools/case_store.py` | 案件/任务持久化（JSON 文件库） | create_task / update_task |
| `web/index.html` | 单文件前端：send/handleEvent/渲染/面板/引导 | send L2585；handleEvent L2656 |
| `src/storage/memory/memory_saver.py` | checkpointer（短期记忆存储） | get_memory_saver |

---

## 5. 扩展指南（在 Codex 里继续开发）

**加一个新工具/新意图**：
1. `src/tools/xxx.py` 写普通 Python 函数，`@tool` 装饰，**docstring 写清楚"什么时候调用、参数含义、返回什么"**（模型只看得到 docstring）
2. 工具内访问当前案件：`from tools.case_store import case_store`，追问类工具从案件读上下文
3. 回执结构化：结论 + 证据（ID/状态/位置/置信度）+ 需要前端原样呈现的内容用统一标记包裹
4. `agent.py` import 并加入 `ALL_TOOLS`；SYSTEM_PROMPT 的"意图路由规则"和"能力清单"同步加一行
5. 重启服务（Python 改动需重启；`web/index.html` 改动无需）

**调对话风格**：只改 `SYSTEM_PROMPT`（不用动代码）。路由规则、建议按钮格式、授权边界都是提示词驱动的。

**换模型**：只改 `config/agent_llm_config.json` 的 `model` 字段。

**加新前端面板**：`web/index.html` 里 `<section class="panel-page" id="panel-xxx">` + WORKSPACES 加项 + PANEL_LOADERS 挂载加载函数 + TOURS 加引导步骤。

**注意事项（易踩坑）**：
- 工具函数内禁止调用其他 `@tool` 函数（装饰后是 StructuredTool 对象不可直接调用）；共用逻辑抽普通函数
- 服务端口 5000（本项目服务）；Python 改动必须重启，HTML 改动刷新即生效
- 检测类工具必须真实执行（禁止 mock 返回），证据状态如实标注 real/derived/simulated/unavailable
