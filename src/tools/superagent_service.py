"""PCAP 数据调查工作区：批次匿名导入 → 两次确认授权（一次性 token）→ 批量检测 → 匿名展示 → 失败重试。

流程：
1. prepare(limit)      选择批次规模（≤20），生成匿名文件映射（PCAP-001...）与一次性授权码
2. authorize_and_run   校验并消费授权码（一次性），后台线程逐文件真实检测
3. get_batch           轮询进度与匿名结果（只展示匿名 ID，不暴露原始文件名）
4. retry               对失败文件单独重试
状态持久化 /tmp/ts_superagent.json，线程安全。
"""
import json
import os
import threading
import time
import uuid

from tools.pcap_tools import _analyze_pcap_file
from tools.pcap_profile import load_ground_truth, DATASET_DIR

STATE_PATH = os.path.join("/tmp", "ts_superagent.json")
MAX_BATCH = 20
MAX_BATCHES = 20  # 状态文件最多保留批次数

_lock = threading.Lock()


def _load() -> dict:
    if os.path.isfile(STATE_PATH):
        try:
            with open(STATE_PATH, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"pending": None, "batches": {}}


def _save(state: dict):
    with open(STATE_PATH, "w", encoding="utf-8") as f:
        json.dump(state, f, ensure_ascii=False)


def _prune(state: dict):
    """只保留最近 MAX_BATCHES 个批次"""
    keys = sorted(state["batches"].keys())
    while len(keys) > MAX_BATCHES:
        state["batches"].pop(keys.pop(0))


def prepare(limit: int) -> dict:
    limit = max(1, min(int(limit or 10), MAX_BATCH))
    items = load_ground_truth()
    if not items:
        return {"ok": False, "message": "数据集未生成，请先运行 python src/tools/pcap_dataset.py"}

    files = []
    for i, it in enumerate(items[:limit], 1):
        files.append({
            "anon_id": f"PCAP-{i:03d}",
            "file": it["file"],          # 内部真实路径标识，结果页不展示
            "kind": it["kind"],          # ground truth 仅用于结果核验，不提前暴露
            "gt": it.get("attack_types", []),
        })

    token = uuid.uuid4().hex[:8].upper()
    batch_id = f"batch_{time.strftime('%m%d%H%M%S')}"
    with _lock:
        state = _load()
        state["pending"] = {
            "batch_id": batch_id,
            "confirm_token": token,
            "files": files,
            "created_at": time.time(),
        }
        _save(state)
    return {
        "ok": True,
        "batch_id": batch_id,
        "count": len(files),
        "files": [{"anon_id": f["anon_id"], "size_hint": "数据集样本"} for f in files],
        "confirm_token": token,
        "max_batch": MAX_BATCH,
        "notice": f"已生成批次 {batch_id}（{len(files)} 个文件，匿名编号 PCAP-001 起）。"
                  f"批量检测将读取文件内容并运行四类规则引擎，请确认授权。",
    }


def authorize_and_run(batch_id: str, confirm_token: str) -> dict:
    with _lock:
        state = _load()
        pending = state.get("pending")
        if not pending or pending.get("batch_id") != batch_id:
            return {"ok": False, "message": "没有待授权的批次，请先生成批次"}
        if pending.get("confirm_token") != (confirm_token or "").strip().upper():
            return {"ok": False, "message": "授权码不正确，请核对后重试"}

        # 一次性消费授权码
        state["pending"] = None
        files = []
        for f in pending["files"]:
            files.append({**f, "status": "pending", "result": None, "error": None, "latency_ms": None})
        state["batches"][batch_id] = {
            "batch_id": batch_id,
            "status": "running",
            "progress": 0,
            "total": len(files),
            "authorized_at": time.time(),
            "files": files,
        }
        _prune(state)
        _save(state)

    threading.Thread(target=_execute, args=(batch_id,), daemon=True).start()
    return {"ok": True, "message": "授权通过，批量检测已启动", "batch_id": batch_id}


def _execute(batch_id: str):
    # 顺序执行；每个文件独立读-改-写，保证状态持久化
    while True:
        with _lock:
            state = _load()
            batch = state["batches"].get(batch_id)
            if not batch:
                return
            nxt = next((f for f in batch["files"] if f["status"] == "pending"), None)
            if nxt is None:
                batch["status"] = "completed"
                batch["progress"] = batch["total"]
                _save(state)
                return
            nxt["status"] = "running"
            _save(state)
            anon_id = nxt["anon_id"]
            path = os.path.join(DATASET_DIR, nxt["file"])

        t0 = time.time()
        result, error = None, None
        try:
            result = _analyze_pcap_file(path)
        except Exception as e:
            error = str(e)[:160]

        with _lock:
            state = _load()
            batch = state["batches"].get(batch_id)
            if not batch:
                return
            target = next((f for f in batch["files"] if f["anon_id"] == anon_id), None)
            if target is not None:
                target["latency_ms"] = round((time.time() - t0) * 1000, 1)
                if error is not None:
                    target["status"] = "failed"
                    target["error"] = error
                elif result is not None and "error" in result:
                    target["status"] = "failed"
                    target["error"] = result["error"]
                else:
                    findings = result.get("findings", [])
                    target["status"] = "done"
                    target["result"] = {
                        "packets": result.get("total_packets", 0),
                        "anomaly_count": len(findings),
                        "findings": [{
                            "type": fd.get("type"),
                            "confidence": fd.get("confidence"),
                        } for fd in findings],
                        "parse_errors": result.get("parse_errors", 0),
                    }
            batch["progress"] = sum(1 for x in batch["files"] if x["status"] in ("done", "failed"))
            batch["status"] = "completed" if batch["progress"] >= batch["total"] else "running"
            _save(state)


def retry(batch_id: str, anon_id: str) -> dict:
    with _lock:
        state = _load()
        batch = state["batches"].get(batch_id)
        if not batch:
            return {"ok": False, "message": "批次不存在"}
        target = [f for f in batch["files"] if f["anon_id"] == anon_id]
        if not target:
            return {"ok": False, "message": f"未找到 {anon_id}"}
        if target[0]["status"] != "failed":
            return {"ok": False, "message": f"{anon_id} 无需重试（当前状态 {target[0]['status']}）"}
        target[0].update(status="pending", result=None, error=None)
        batch["status"] = "running"
        _save(state)
    threading.Thread(target=_execute, args=(batch_id,), daemon=True).start()
    return {"ok": True, "message": f"{anon_id} 重试已启动"}


def get_batch(batch_id: str) -> dict:
    with _lock:
        state = _load()
    batch = state["batches"].get(batch_id)
    if not batch:
        return {"ok": False, "message": "批次不存在"}
    files_view = []
    for f in batch["files"]:
        view = {
            "anon_id": f["anon_id"],
            "status": f["status"],
            "latency_ms": f["latency_ms"],
        }
        if f["status"] == "done" and f["result"]:
            view["packets"] = f["result"]["packets"]
            view["anomaly_count"] = f["result"]["anomaly_count"]
            view["findings"] = f["result"]["findings"]
        if f["status"] == "failed":
            view["error"] = f["error"]
        files_view.append(view)
    return {
        "ok": True,
        **{k: batch[k] for k in ("batch_id", "status", "progress", "total")},
        "files": files_view,
    }


def list_batches() -> dict:
    with _lock:
        state = _load()
    out = []
    for bid, b in sorted(state["batches"].items(), reverse=True):
        out.append({
            "batch_id": bid, "status": b["status"],
            "progress": b["progress"], "total": b["total"],
            "authorized_at": b.get("authorized_at"),
        })
    pending = state.get("pending")
    return {"ok": True, "batches": out,
            "pending": {"batch_id": pending["batch_id"], "created_at": pending["created_at"]} if pending else None}
