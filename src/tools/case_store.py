"""案件状态存储：跨工具、跨轮次持久化调查任务状态（Prompt 案件 / PCAP 案件 / 证据链）"""
import json
import logging
import os
import re
import threading
import time
import uuid
from typing import Any, Optional

logger = logging.getLogger(__name__)

# 案件存储放在项目持久目录：工作区同步会周期性清理 assets/ 下未跟踪的运行时文件，
# 而 /tmp 会随沙箱/环境重置被清空（曾导致案件丢失、最近任务无法回到现场）。
# 因此落盘到 $COZE_WORKSPACE_PATH/cases/ts_cases，启动时自动迁移旧 /tmp 数据。
_WORKSPACE = os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects")
CASES_DIR = os.path.join(_WORKSPACE, "cases", "ts_cases")
_LEGACY_DIRS = ("/tmp/ts_cases",)

_lock = threading.Lock()


def _migrate_legacy_dirs() -> None:
    """把旧 /tmp 案件文件迁移到持久目录（幂等，跨文件系统安全）"""
    import shutil
    for legacy in _LEGACY_DIRS:
        try:
            if not os.path.isdir(legacy):
                continue
            os.makedirs(CASES_DIR, exist_ok=True)
            for name in os.listdir(legacy):
                src = os.path.join(legacy, name)
                dst = os.path.join(CASES_DIR, name)
                if name.endswith(".json") and not os.path.exists(dst):
                    shutil.move(src, dst)
                    logger.info("case_store migrated %s -> %s", src, dst)
        except Exception:
            logger.warning("case_store legacy migration failed for %s", legacy, exc_info=True)


# ---- 会话→任务绑定（同一会话内 prompt/pcap 检测共用同一案件，除非新建会话） ----
_SESSION_STATE = {"session_key": "", "pinned_task_id": ""}
_SESSION_MAP_PATH = os.path.join(CASES_DIR, "session_map.json")


def bind_session(session_key=None, task_id=None):
    """前端会话绑定：传 session_id（web-xxx / task-XXX）或直接钉住 task_id。"""
    if task_id:
        _SESSION_STATE["pinned_task_id"] = task_id
        return True
    if session_key:
        if _SESSION_STATE["session_key"] != session_key:
            _SESSION_STATE["session_key"] = session_key
            _SESSION_STATE["pinned_task_id"] = ""
    return True


def get_session_key():
    return _SESSION_STATE["session_key"]


def _load_session_map() -> dict:
    try:
        with open(_SESSION_MAP_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_session_map(m: dict) -> None:
    try:
        with open(_SESSION_MAP_PATH, "w", encoding="utf-8") as f:
            json.dump(m, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def resolve_task_for_session(case_store, mode: str, title: str):
    """同一会话复用同一案件；无会话上下文返回 None（调用方走原逻辑）。

    session_key 形态：
    - "task-TASK-XXXX"：最近任务恢复的会话，直接钉住该案件
    - "web-YYYY"：自由会话，查 session_map 映射，未命中则新建并记录
    """
    sk = _SESSION_STATE["session_key"]
    pinned = _SESSION_STATE["pinned_task_id"]
    if pinned:
        d = case_store.get_task(pinned)
        if d:
            case_store.set_current(pinned)
            return pinned
        _SESSION_STATE["pinned_task_id"] = ""
    if not sk:
        return None
    if sk.startswith("task-"):
        tid = sk[5:]
        if case_store.get_task(tid):
            case_store.set_current(tid)
            return tid
        return None
    m = _load_session_map()
    tid = m.get(sk)
    if tid:
        if case_store.get_task(tid):
            case_store.set_current(tid)
            return tid
        m.pop(sk, None)
        _save_session_map(m)
    tid = case_store.create_task(mode=mode, title=title, origin="chat")
    m[sk] = tid
    _save_session_map(m)
    case_store.set_current(tid)
    return tid


class CaseStore:
    """基于 JSON 文件的案件存储，保证 Agent 多轮对话与工具间状态一致"""

    def __init__(self):
        self._current_task_id: Optional[str] = None
        _migrate_legacy_dirs()
        os.makedirs(CASES_DIR, exist_ok=True)

    # ---------- task 生命周期 ----------
    def create_task(self, mode: str, title: str = "", origin: str = "chat",
                    description: str = "") -> str:
        """origin: chat=安全对话产生 | workspace=专业学习区面板产生 | challenge/其他=挑战实验"""
        task_id = f"TASK-{uuid.uuid4().hex[:8].upper()}"
        data = {
            "task_id": task_id,
            "mode": mode,  # prompt | pcap | challenge | lab | evaluation
            "origin": origin,
            "title": title or ("Prompt 安全调查" if mode == "prompt" else "PCAP 数据调查"),
            "description": description,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%S+08:00"),
            "original_prompt": "",
            "pcap_files": [],       # [{name, sha256, size, packet_count}]
            "evidence": [],         # 统一证据格式
            "hypotheses": [],       # [{stage, supports:[evidence_id], missing:[], confidence}]
            "plan": [],
            "repair": None,         # 修复版本 {repaired_prompt, changes[], note}
            "recheck": None,        # 复检结果
            "report_url": None,
            "authorization": {},    # {action: {granted_at, scope}}
            "connector_state": {
                "semantic_scan": "real",
                "entropy_cpd": "derived",
                "pcap_parser": "real",
                "edr_isolation": "unavailable",
                "firewall_block": "unavailable",
                "identity_lookup": "unavailable",
            },
        }
        self._save(task_id, data)
        self._current_task_id = task_id
        return task_id

    def get_task(self, task_id: str) -> Optional[dict]:
        path = self._path(task_id)
        if not os.path.exists(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"case store read failed task={task_id}: {e}")
            return None

    def update_task(self, task_id: str, **fields: Any) -> Optional[dict]:
        data = self.get_task(task_id)
        if data is None:
            return None
        data.update(fields)
        data["updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%S+08:00")
        self._save(task_id, data)
        return data

    def set_current(self, *args) -> None:
        """兼容两种调用：set_current(task_id) 与 set_current(mode, task_id)"""
        if len(args) >= 2:
            task_id = args[1]
        elif len(args) == 1:
            task_id = args[0]
        else:
            return
        with _lock:
            self._current_task_id = task_id

    def get_current(self, mode: Optional[str] = None) -> Optional[dict]:
        """获取当前活跃案件；mode 指定时要求模式匹配。
        对话链路只复用 origin=chat 的案件，避免续接学习区面板任务"""
        task_id = self._current_task_id
        if task_id:
            data = self.get_task(task_id)
            if data and data.get("origin", "chat") != "workspace" \
                    and (mode is None or data.get("mode") == mode):
                return data
        # 兜底：返回该模式最近更新的对话案件
        latest = self._latest_task(mode)
        if latest:
            self._current_task_id = latest["task_id"]
        return latest

    def _latest_task(self, mode: Optional[str]) -> Optional[dict]:
        best = None
        try:
            for name in os.listdir(CASES_DIR):
                if not name.endswith(".json"):
                    continue
                data = self.get_task(name[:-5])
                if not data:
                    continue
                if data.get("origin", "chat") == "workspace":
                    continue  # 学习区面板任务不参与对话复用
                if mode and data.get("mode") != mode:
                    continue
                if best is None or data.get("updated_at", "") > best.get("updated_at", ""):
                    best = data
        except FileNotFoundError:
            pass
        return best

    # ---------- 证据 ----------
    def add_evidence(self, task_id: str, evidence: dict) -> str:
        data = self.get_task(task_id)
        if data is None:
            raise ValueError(f"task {task_id} not found")
        prefix = "P" if data["mode"] == "prompt" else "N"
        seq = len(data.get("evidence", [])) + 1
        evidence_id = f"{prefix}-{seq:03d}"
        evidence["evidence_id"] = evidence_id
        evidence.setdefault("created_at", time.strftime("%Y-%m-%dT%H:%M:%S+08:00"))
        data.setdefault("evidence", []).append(evidence)
        self._save(task_id, data)
        return evidence_id

    def get_evidence(self, task_id: str, evidence_id: str) -> Optional[dict]:
        data = self.get_task(task_id)
        if data is None:
            return None
        for ev in data.get("evidence", []):
            if ev.get("evidence_id") == evidence_id:
                return ev
        return None

    # ---------- 内部 ----------
    @staticmethod
    def _path(task_id: str) -> str:
        return os.path.join(CASES_DIR, f"{task_id}.json")

    def _save(self, task_id: str, data: dict) -> None:
        os.makedirs(CASES_DIR, exist_ok=True)
        tmp = self._path(task_id) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self._path(task_id))


# ---- 可审计推理链（借鉴 Token Sentinel 的 AuditableReasoningChain）----
    def get_or_create_task(self, mode: str) -> str:
        """按类型复用当前任务；无则新建（challenge/evaluation/lab 等轻任务场景）"""
        cur = self.get_current(mode=mode)
        if cur:
            return cur["task_id"]
        return self.create_task(mode)

    def reset_actions(self, task_id: str) -> None:
        """入口型工具（scan/preflight）在新一轮调查开始时清空动作记录"""
        self.update_task(task_id, actions=[])

    def log_action(self, task_id: str, tool: str, summary: str) -> None:
        """记录本轮已执行的工具动作（真实执行记录，非模型生成）"""
        data = self.get_task(task_id) or {}
        actions = data.get("actions") or []
        actions.append({"tool": tool, "summary": summary})
        self.update_task(task_id, actions=actions)

    def build_chain(self, task_id: str, observe: str, plan: str,
                    replan: str = "未触发补充检测", close: str = "") -> str:
        """生成可审计推理链 Markdown 表格（数据来自真实工具执行记录）"""
        data = self.get_task(task_id) or {}
        actions = data.get("actions") or []
        act_rows = "\n".join(
            f"| 行动 | ✅ | {i + 1}. {a['tool']} → {a['summary']} |"
            for i, a in enumerate(actions)
        ) or "| 行动 | ⚠️ | （本轮暂无工具回执） |"
        replan_state = "⏭" if ("未触发" in replan or "跳过" in replan) else "✅"
        return (
            "\n【可审计推理链 · 请在最终回复中原样呈现下表】\n"
            "| 阶段 | 状态 | 内容 |\n|------|------|------|\n"
            f"| 观察 | ✅ | {observe} |\n"
            f"| 计划 | ✅ | {plan} |\n"
            f"{act_rows}\n"
            f"| 重规划 | {replan_state} | {replan} |\n"
            f"| 收口 | ✅ | {close} |\n"
        )

    def list_tasks(self, limit: int = 12) -> list:
        """列出最近任务（按更新时间倒序），供 Web 侧边栏展示"""
        import glob as _glob
        items = []
        for p in sorted(_glob.glob(os.path.join(CASES_DIR, "*.json")), key=os.path.getmtime, reverse=True)[:limit]:
            try:
                with open(p, encoding="utf-8") as f:
                    d = json.loads(f.read())
                items.append({
                    "task_id": d.get("task_id"),
                    "mode": d.get("mode"),
                    "origin": d.get("origin", "chat"),
                    "title": d.get("title", ""),
                    "status": self._derive_status(d),
                    "evidence_count": len(d.get("evidence", [])),
                    "file_count": len(d.get("pcap_files", [])),
                    "updated_at": d.get("updated_at", ""),
                })
            except Exception:
                continue
        return items

    @staticmethod
    def _top_risk(d: dict) -> str:
        """取最新一条带风险等级的证据等级"""
        for ev in reversed(d.get("evidence", [])):
            r = str(ev.get("risk_level") or "").lower()
            if r and r != "none":
                return r
        # 兜底：真实执行记录（actions）里的判级，如"面板三路检测完成，判级 high"
        for a in reversed(d.get("actions") or []):
            m = re.search(r"判级\s*(high|medium|low)", str(a.get("summary") or ""))
            if m:
                return m.group(1)
        return str(d.get("last_risk_level") or "").lower() or ""

    @classmethod
    def _derive_status(cls, d: dict) -> str:
        """从案件数据推导展示状态（对齐平台侧边栏标签风格）"""
        if d.get("report_url"):
            return "已出报告"
        if d.get("recheck"):
            return "已复检"
        if d.get("repair"):
            return "已修复"
        risk = cls._top_risk(d)
        if risk == "high":
            return "发现风险"
        if risk == "medium":
            return "需关注"
        if d.get("authorization"):
            return "已授权"
        if d.get("evidence") or d.get("actions"):
            return "已收口"
        return "进行中"

    def delete_task(self, task_id: str) -> bool:
        """删除任务文件；若是当前任务则重置指针"""
        path = self._path(task_id)
        if not os.path.exists(path):
            return False
        try:
            os.remove(path)
        except Exception as e:
            logger.error(f"case store delete failed task={task_id}: {e}")
            return False
        if self._current_task_id == task_id:
            self._current_task_id = None
        return True


# 全局单例
case_store = CaseStore()

