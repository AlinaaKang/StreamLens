"""LLM 客户端兼容层：让项目在"托管环境"与"本地自部署"都能全功能运行。

- 托管/沙箱环境：优先使用平台内置 LLMClient（凭据 COZE_API_TOKEN 或
  COZE_WORKLOAD_IDENTITY_API_KEY 由运行平台注入）。
- 本地自部署：凭据缺失时回落标准 OpenAI 兼容接口——
  OPENAI_API_KEY（必填）+ OPENAI_BASE_URL（可选，DeepSeek/通义/Kimi/Ollama 等）
  + OPENAI_MODEL（可选，覆盖默认模型名）。

两类客户端对外签名一致：
    invoke(messages, model=..., temperature=..., max_completion_tokens=...) -> resp.content
"""
import logging
import os
from types import SimpleNamespace

log = logging.getLogger(__name__)


class OpenAICompatClient:
    """OpenAI 兼容接口客户端，invoke 签名与平台 LLMClient 对齐。"""

    def __init__(self, ctx=None):
        self._api_key = os.getenv("OPENAI_API_KEY")
        self._base_url = os.getenv("OPENAI_BASE_URL") or None
        self._model_override = os.getenv("OPENAI_MODEL") or None
        self._ctx = ctx

    def invoke(self, messages, model=None, temperature=0.2,
               max_completion_tokens=4000, json_mode=False, **kwargs):
        from langchain_openai import ChatOpenAI
        mdl = self._model_override or model or "gpt-4o-mini"

        def _call(with_json_format: bool):
            llm = ChatOpenAI(
                model=mdl,
                api_key=self._api_key,
                base_url=self._base_url,
                temperature=temperature,
                max_tokens=max_completion_tokens,
                timeout=120,
                **({"model_kwargs": {"response_format": {"type": "json_object"}}} if with_json_format else {}),
            )
            resp = llm.invoke(messages)
            return SimpleNamespace(content=resp.content)

        if json_mode:
            try:  # DeepSeek/OpenAI 等支持 json_object 模式，显著提升 JSON 遵循率
                return _call(True)
            except Exception as e:
                log.warning("json_object mode rejected by endpoint, retry plain: %s", str(e)[:120])
        return _call(False)


_CRED_LOADED = False

def load_credentials_file() -> bool:
    """加载项目根 config/credentials.env（KEY=VALUE）。
    已存在的环境变量不被覆盖（真实环境优先于文件）。"""
    global _CRED_LOADED
    if _CRED_LOADED:
        return True
    path = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "..", "config", "credentials.env"))
    if not os.path.exists(path):
        return False
    try:
        from dotenv import dotenv_values
        for k, v in dotenv_values(path).items():
            if v and not os.environ.get(k):
                os.environ[k] = v
        _CRED_LOADED = True
        log.info("credentials loaded from %s", path)
        return True
    except Exception as e:
        log.warning("load credentials.env failed: %s", e)
        return False

def has_platform_credentials() -> bool:
    """是否具备可用模型凭据（平台内置 或 credentials.env/环境变量中的 OpenAI 兼容配置）。"""
    load_credentials_file()
    return bool(os.getenv("COZE_API_TOKEN") or
                os.getenv("COZE_WORKLOAD_IDENTITY_API_KEY") or
                (os.getenv("OPENAI_API_KEY") and (os.getenv("OPENAI_BASE_URL") or True)))


def get_llm_client(ctx=None):
    """获取可用的 LLM 客户端：平台内置优先，缺失时回落 OpenAI 兼容。"""
    if os.getenv("COZE_API_TOKEN") or os.getenv("COZE_WORKLOAD_IDENTITY_API_KEY"):
        try:
            from coze_coding_dev_sdk import LLMClient
            return LLMClient(ctx=ctx)
        except Exception as e:  # 平台 SDK 异常时仍可回落本地配置
            log.warning("LLMClient init failed, fallback to OpenAI-compatible: %s", e)
    load_credentials_file()
    if not os.getenv("OPENAI_API_KEY"):
        raise RuntimeError(
            "未检测到可用的大模型凭据：请在环境变量中设置 OPENAI_API_KEY"
            "（可选 OPENAI_BASE_URL、OPENAI_MODEL），"
            "或在托管环境中提供 COZE_API_TOKEN / COZE_WORKLOAD_IDENTITY_API_KEY")
    return OpenAICompatClient(ctx=ctx)
