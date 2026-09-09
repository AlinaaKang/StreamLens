# StreamLens 明鉴 平台 · 部署运行说明

## 0 一键启动（推荐，免命令行）

- **Windows**：双击 `run_windows.bat`（自动装依赖 → 后台起服务 → 自动打开浏览器）
- **Linux / macOS**：`bash start.sh`

前置条件仅一个：安装 Python 3.12+（Windows 安装时勾选 "Add Python to PATH"）。
大模型凭据已内置在 `config/credentials.env`（DeepSeek），解压即全功能；如需更换模型（通义/Kimi/OpenAI/本地 Ollama），编辑该文件三个变量即可。

## 1 环境要求

- Python 3.12+（无 GPU 要求，分布层检测纯 CPU 毫秒级）
- 依赖管理：uv（`pyproject.toml` + `uv.lock` 已锁定版本）；无 uv 时自动回落 `pip install -r requirements.txt`

## 2 安装与启动

```bash
# 安装依赖
uv sync

# 启动服务（默认端口 5000）
cd src
python main.py -m http -p 5000
```

浏览器访问：`http://127.0.0.1:5000/web`

## 3 功能入口（Web 工作台）

| 工作区 | 功能 |
|---|---|
| 对话式检测 | 粘贴 Prompt 即触发完整检测链路，流式回显结论与证据 |
| Prompt 安全分析 | 三路检测面板 + Token 风险轨道可视化 + 报告生成 |
| 红蓝攻防演练 | 红队 payload 过真实引擎 / 蓝队样本研判计分 |
| 曲线侦探挑战 | CPD 曲线关卡教学（8 大样本族） |
| 审计中心 | 检测事件流水与证据链回溯 |

## 4 目录结构

```
├── config/          # 模型配置 (agent_llm_config.json)
├── src/
│   ├── main.py      # 服务入口（FastAPI 路由）
│   ├── agents/      # 对话 Agent（流式检测链路）
│   ├── tools/       # 检测引擎：prompt_tools / entropy_detector / lab_run_service / adversary_service / pcap_tools / challenge_tools / case_store
│   ├── storage/     # 会话记忆
│   └── utils/       # 文件等通用封装
├── web/             # 单页前端（index.html）
├── assets/          # 样本库 (challenge/samples.json) / 知识库 / 测试数据
├── docs/            # 设计文档 / 测试文档 / 总结报告 / 合规声明（Markdown 源）
├── scripts/         # 构建与启动脚手架
└── cases/           # 运行时任务数据（服务自动创建，已从源码包排除）
```

## 5 大模型配置（本地自部署）

项目凭据自动适配，两级回落：

1. **托管环境**：检测到 `COZE_API_TOKEN` / `COZE_WORKLOAD_IDENTITY_API_KEY` → 使用平台内置模型（qwen-3-5-plus），无需配置；
2. **本地自部署**：配置任意 **OpenAI 兼容**服务商的 Key，DeepSeek / 通义 / Kimi / OpenAI / 本地 Ollama 均可：

```bash
# Linux / macOS
export OPENAI_API_KEY=sk-你的Key
export OPENAI_BASE_URL=https://api.deepseek.com/v1   # DeepSeek 官方
export OPENAI_MODEL=deepseek-chat

# Windows PowerShell
$env:OPENAI_API_KEY="sk-你的Key"
$env:OPENAI_BASE_URL="https://api.deepseek.com/v1"
$env:OPENAI_MODEL="deepseek-chat"
```

- 未配置任何 Key：规则标记层、Entropy-CPD 分布层、Token 轨道可视化、曲线侦探、审计等**全部可用**；语义三档判定与对话 Agent 将提示"语义服务不可用"并走降级路径（不拦截、转人工复核）
- 语义层 JSON 判定自动启用 `response_format=json_object`（DeepSeek/OpenAI 支持），端点不支持时自动降级重试

## 6 说明

- 分布层（Entropy-CPD）纯本地计算，无外部调用；
- 运行时产生的任务/证据/审计数据位于 `cases/ts_cases/`，首次启动自动创建。
