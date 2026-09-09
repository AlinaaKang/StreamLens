# StreamLens 明鉴 部署运行手册

本文用于比赛评审机或本地演示环境部署，不包含真实凭据。

## 环境要求

- Python 3.12 或更高版本
- CPU 即可运行本地规则和 Entropy-CPD
- Prompt 自然语言对话需要 OpenAI 兼容模型服务
- PCAP 解析依赖项目锁定的 Python 依赖

## 本地启动

Windows：

```text
复制 config/credentials.env.example 为 config/credentials.env
填写 OPENAI_API_KEY、OPENAI_BASE_URL、OPENAI_MODEL
双击 run_windows.bat
```

手动启动：

```text
uv sync
set COZE_PROJECT_TYPE=agent
set COZE_PROJECT_ENV=DEV
set COZE_WORKSPACE_PATH=项目绝对路径
set PYTHONPATH=项目绝对路径\src
python -m uvicorn main:app --app-dir src --host 127.0.0.1 --port 5000 --lifespan off
```

浏览器访问：`http://127.0.0.1:5000/web`

Linux/macOS：

```text
bash start.sh
```

## 模型配置

项目兼容 DeepSeek、OpenAI、通义、Kimi 和其他 OpenAI 兼容服务。模型 Key 只放在服务端；没有 Key 时，本地检测函数仍可运行，但自然语言 Agent 无法生成回复。

## 比赛演示建议

演示前检查 `/health`，打开 Prompt 检测和 PCAP 教学样本各运行一次。优先使用 `assets/challenge` 和 `assets/test_data` 中的脱敏或合成样本。不要把真实生产 PCAP、Token、账号或凭据上传到演示环境。

## 已知限制

本地预览模式使用内存会话存储，服务重启后历史对话不保证保留；完整 PostgreSQL 持久化需要配置 Coze 或自有数据库环境。未接入真实防火墙、EDR 时，不执行高影响处置。
