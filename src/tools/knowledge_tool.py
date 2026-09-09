"""安全知识库检索工具（RAG）：基于向量化知识库的语义搜索"""
import logging
from typing import Optional

from langchain.tools import tool
from coze_coding_utils.log.write_log import request_context
from coze_coding_utils.runtime_ctx.context import new_context

logger = logging.getLogger(__name__)


def search_knowledge_struct(query: str, top_k: int = 5, min_score: float = 0.3) -> list:
    """结构化版知识检索（供 Web 面板），返回 [{score, content}]"""
    from coze_coding_dev_sdk import KnowledgeClient, Config

    ctx = request_context.get() or new_context(method="knowledge_search")
    client = KnowledgeClient(config=Config(), ctx=ctx)
    resp = client.search(query=query, top_k=top_k, min_score=min_score)
    if resp.code != 0 or not resp.chunks:
        return []
    return [{"score": round(float(c.score), 3), "content": c.content} for c in resp.chunks]


def search_knowledge(query: str, top_k: int = 3, min_score: float = 0.3) -> str:
    """普通函数版知识检索（供其他工具内部复用），返回拼接的知识文本"""
    chunks = search_knowledge_struct(query, top_k, min_score)
    if not chunks:
        return ""
    return "\n\n".join(
        f"[知识{i}] (相关度 {c['score']:.2f})\n{c['content']}"
        for i, c in enumerate(chunks, 1)
    )


@tool
def security_knowledge_search(query: str) -> str:
    """在安全知识库（Prompt风险模式/Token模型安全/网络PCAP/ATT&CK技战术/合规处置 五类）中执行语义检索，返回最相关的知识片段及来源。回答安全术语、攻击原理、合规要求等问题时调用。"""
    try:
        result = search_knowledge(query, top_k=5, min_score=0.3)
        if not result:
            return "未找到匹配知识。当前知识库覆盖：Prompt 风险模式、Token/模型安全、网络与 PCAP 分析、MITRE ATT&CK 技战术、合规与处置。你可以换个说法再试，或提出以上范围内的安全知识问题。"
        return result
    except Exception as e:
        logger.exception("security_knowledge_search failed")
        return f"知识检索失败：{e}。请稍后重试。"
