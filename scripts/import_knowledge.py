"""导入安全知识库文档到 RAG 知识库（一次性脚本）"""
import os
import sys

from coze_coding_dev_sdk import KnowledgeClient, Config, KnowledgeDocument, DataSourceType, ChunkConfig
from coze_coding_utils.runtime_ctx.context import new_context

KNOWLEDGE_DIR = os.path.join(os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects"), "assets", "knowledge")

FILES = [
    "prompt_risk_patterns.md",
    "token_model_security.md",
    "network_pcap.md",
    "attack_tactics.md",
    "compliance.md",
]


def main():
    ctx = new_context(method="knowledge_import")
    client = KnowledgeClient(config=Config(), ctx=ctx)

    documents = []
    for name in FILES:
        path = os.path.join(KNOWLEDGE_DIR, name)
        if not os.path.exists(path):
            print(f"[SKIP] not found: {path}")
            continue
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
        documents.append(KnowledgeDocument(source=DataSourceType.TEXT, raw_data=content))
        print(f"[LOAD] {name} ({len(content)} chars)")

    if not documents:
        print("no documents to import")
        return

    chunk_config = ChunkConfig(separator="\n\n", max_tokens=1000, remove_extra_spaces=False)
    resp = client.add_documents(
        documents=documents,
        table_name="coze_doc_knowledge",
        chunk_config=chunk_config,
    )
    print(f"code={resp.code} msg={resp.msg} doc_ids={resp.doc_ids}")


if __name__ == "__main__":
    main()
