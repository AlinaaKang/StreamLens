# -*- coding: utf-8 -*-
"""PCAP 侦探挑战 · 内置脱敏关卡库（纯静态数据，不含真实用户文件）。

设计对齐 Demo：
- 每关 3 行 Packet 分组（正常基线 / 待研判异常 / 结果证据）
- 玩家提交：异常 Packet 组 + 攻击类型 + 攻击目的
- 答案与解析仅在提交后展露
"""
from typing import Any, Dict, List

ATK_SQLI = {"v": "sqli", "label": "SQL 注入"}
ATK_CMD = {"v": "cmd_injection", "label": "命令注入"}
ATK_PATH = {"v": "path_traversal", "label": "路径穿越"}
ATK_C2 = {"v": "c2_beacon", "label": "C2 心跳"}
ATK_SCAN = {"v": "port_scan", "label": "端口扫描"}
ATK_TUNNEL = {"v": "dns_tunnel", "label": "DNS 隧道"}
ATK_BRUTE = {"v": "bruteforce", "label": "口令暴破"}

GOAL_BYPASS = {"v": "auth_bypass", "label": "认证绕过"}
GOAL_EXEC = {"v": "script_exec", "label": "脚本执行"}
GOAL_INTERNAL = {"v": "internal_access", "label": "内部地址访问"}
GOAL_EXFIL = {"v": "data_exfil", "label": "数据外传"}
GOAL_CTRL = {"v": "remote_ctrl", "label": "远程控制"}
GOAL_PERSIST = {"v": "persistence", "label": "持久化驻留"}
GOAL_CRED = {"v": "credential", "label": "窃取凭证"}

LEVELS: List[Dict[str, Any]] = [
    {
        "id": "pc-level-01",
        "title": "登录接口异常请求",
        "description": "一段经过脱敏的 HTTP 会话中出现了短促但集中的异常请求，请综合小队公开线索完成研判。",
        "proto_summary": "HTTP · 9 个 Packet · 明文请求均可见",
        "packets": [
            {
                "group": "Packet 1-3",
                "time": "00:00.000-00:00.083",
                "proto_dir": "HTTP　10.0.8.21 -> auth.demo.local",
                "payload": "GET /login HTTP/1.1\nGET /assets/login.css HTTP/1.1",
                "hint": "正常基线：登录页与静态资源请求，未出现额外参数。",
            },
            {
                "group": "Packet 4-4",
                "time": "00:00.084",
                "proto_dir": "HTTP POST　10.0.8.21 -> auth.demo.local",
                "payload": "POST /login HTTP/1.1\nusername=admin%27+OR+%271%27%3D%271&password=x",
                "hint": "待研判：账号字段出现编码后的引号、OR 与布尔条件组合，与正常请求明显不同。",
            },
            {
                "group": "Packet 5-7",
                "time": "00:00.101-00:00.164",
                "proto_dir": "HTTP　auth.demo.local -> 10.0.8.21",
                "payload": "HTTP/1.1 401 Unauthorized\nContent-Length: 96",
                "hint": "结果证据：服务端拒绝请求，不能据此证明异常尝试成功。",
            },
        ],
        "attack_types": [ATK_SQLI, ATK_CMD, ATK_PATH],
        "attack_goals": [GOAL_BYPASS, GOAL_EXEC, GOAL_INTERNAL],
        "answer": {"packet_group": "Packet 4-4", "attack_type": "sqli", "attack_goal": "auth_bypass"},
        "explain": "POST /login 的账号字段出现 URL 编码后的引号与 OR '1'='1 恒真条件，属于典型 SQL 注入探测载荷，"
                   "目的是绕过登录认证读取账号数据；401 响应说明服务端拦截成功，攻击未实际得手。",
    },
    {
        "id": "pc-level-02",
        "title": "整点后的规律性外联",
        "description": "一台办公终端在夜间出现了机器节拍般的规律性外联，请结合元数据判断会话性质。",
        "proto_summary": "HTTPS/DNS · 32 个 Packet · 载荷已加密仅元数据可见",
        "packets": [
            {
                "group": "Packet 1-2",
                "time": "17:59:41",
                "proto_dir": "DNS　10.0.8.21 -> 8.8.8.8",
                "payload": "A? cdn-corp-edge.com -> 172.16.4.19 (TTL 300)",
                "hint": "正常基线：办公时段首次解析新域名，无历史记录但符合下班前缓存刷新习惯。",
            },
            {
                "group": "Packet 8-20",
                "time": "18:00:00-19:00:00",
                "proto_dir": "HTTPS　10.0.8.21 -> 172.16.4.19",
                "payload": "TLS AppData\n上行 512B @ 每 60.0s ±0.3s（间隔方差 <0.2）",
                "hint": "待研判：整点后每 60 秒固定小包上行，间隔方差极小，像机器节拍而非人工操作。",
            },
            {
                "group": "Packet 21-32",
                "time": "01:00:00-05:00:00",
                "proto_dir": "HTTPS　10.0.8.21 -> 172.16.4.19",
                "payload": "TLS AppData\n会话持续 4 小时不间断，无任何用户交互关联",
                "hint": "结果证据：夜间时段仍持续外联，终端处于无人使用状态。",
            },
        ],
        "attack_types": [ATK_C2, ATK_SCAN, ATK_TUNNEL],
        "attack_goals": [GOAL_EXFIL, GOAL_CTRL, GOAL_PERSIST],
        "answer": {"packet_group": "Packet 8-20", "attack_type": "c2_beacon", "attack_goal": "data_exfil"},
        "explain": "固定 60s 间隔、固定小包上行且间隔方差极小（CV<0.2），夜间无人时段仍持续——符合 C2 心跳 beacon 特征；"
                   "持续的规律性上行通道通常用于维持远程控制并回传数据，研判为 C2 心跳 / 数据外传。",
    },
    {
        "id": "pc-level-03",
        "title": "短促密集的认证失败",
        "description": "SSH 服务的认证日志在 30 秒内出现了高频失败，请判断来源会话的性质。",
        "proto_summary": "SSH · 48 个 Packet · 认证日志明文可见",
        "packets": [
            {
                "group": "Packet 1-3",
                "time": "09:00:11-09:00:19",
                "proto_dir": "SSH　10.0.8.30 -> 10.0.8.5",
                "payload": "User auth: admin (Accepted publickey)",
                "hint": "正常基线：管理员单次公钥成功登录，来源固定。",
            },
            {
                "group": "Packet 10-40",
                "time": "23:41:02-23:41:31",
                "proto_dir": "SSH　10.0.8.99 -> 10.0.8.5",
                "payload": "User auth: root (Failed)\n×27 attempts / 30s，用户名按 root/admin/test 轮换",
                "hint": "待研判：夜间单一来源 30 秒 27 次失败，用户名字典轮换，节奏密集。",
            },
            {
                "group": "Packet 41-48",
                "time": "23:41:32",
                "proto_dir": "SSH　10.0.8.5 -> 10.0.8.99",
                "payload": "Disconnect: Too many authentication failures",
                "hint": "结果证据：服务端触发封禁断开，暴破未成功。",
            },
        ],
        "attack_types": [ATK_BRUTE, ATK_SQLI, ATK_CMD],
        "attack_goals": [GOAL_CRED, GOAL_BYPASS, GOAL_INTERNAL],
        "answer": {"packet_group": "Packet 10-40", "attack_type": "bruteforce", "attack_goal": "credential"},
        "explain": "夜间单一来源 30 秒 27 次认证失败且用户名按字典轮换，是典型 SSH 口令暴破；"
                   "目的是穷举获取有效凭证。服务端封禁及时，未成功。",
    },
]


def get_level(level_id: str = "", exclude: str = "") -> Dict[str, Any]:
    """默认第一关；exclude 用于“换一关”（按顺序推进到下一关，末关循环回首关）。返回给前端时剥离答案。"""
    lv = None
    if level_id:
        matched = [l for l in LEVELS if l["id"] == level_id]
        if matched:
            lv = matched[0]
    if lv is None:
        if exclude:
            idx = next((i for i, l in enumerate(LEVELS) if l["id"] == exclude), -1)
            lv = LEVELS[(idx + 1) % len(LEVELS)] if idx >= 0 else LEVELS[0]
        else:
            lv = LEVELS[0]  # 默认从第一关开始
    out = {k: lv[k] for k in ("id", "title", "description", "proto_summary", "packets", "attack_types", "attack_goals")}
    out["index"] = LEVELS.index(lv) + 1
    out["total"] = len(LEVELS)
    return out


def get_answer(level_id: str) -> Dict[str, Any]:
    for l in LEVELS:
        if l["id"] == level_id:
            return {"answer": l["answer"], "explain": l["explain"]}
    return {}


def judge(level_id: str, packet_group: str, attack_type: str, attack_goal: str) -> Dict[str, Any]:
    """判分：位置 40 + 类型 30 + 目的 30 = 100。"""
    info = get_answer(level_id)
    if not info:
        return {"error": "level not found"}
    ans = info["answer"]
    items = []
    ok1 = packet_group == ans["packet_group"]
    items.append({
        "label": "异常 Packet 组",
        "ok": ok1,
        "text": f"你标记了 {packet_group}，正确答案是 {ans['packet_group']}" if not ok1
                else f"{packet_group} 标记正确",
        "gain": 40 if ok1 else 0,
    })
    ok2 = attack_type == ans["attack_type"]
    type_label = next((t["label"] for t in get_level(level_id)["attack_types"] if t["v"] == ans["attack_type"]), ans["attack_type"])
    items.append({
        "label": "攻击类型",
        "ok": ok2,
        "text": f"你选择了 {attack_type}，正确答案是 {type_label}" if not ok2
                else f"{type_label} 判断正确",
        "gain": 30 if ok2 else 0,
    })
    ok3 = attack_goal == ans["attack_goal"]
    goal_label = next((g["label"] for g in get_level(level_id)["attack_goals"] if g["v"] == ans["attack_goal"]), ans["attack_goal"])
    items.append({
        "label": "攻击目的",
        "ok": ok3,
        "text": f"你选择了 {attack_goal}，正确答案是 {goal_label}" if not ok3
                else f"{goal_label} 判断正确",
        "gain": 30 if ok3 else 0,
    })
    return {"score": sum(i["gain"] for i in items), "items": items, "explain": info["explain"]}
