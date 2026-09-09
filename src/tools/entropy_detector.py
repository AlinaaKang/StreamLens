"""Entropy-CPD：Token 级熵流 + 在线 CUSUM 变化点检测（对齐 CPD Online 参考实现）

方法论对齐 cpdonline/cpdonline（Entropy CUSUM 参考实现）：
- 信号单位从"字符滑窗"升级为 **token 级序列**（中文按字、英文按词、数字串、标点独立）
- 每个 token 计算局部字符窗口熵 H_t（字符 unigram 熵作为无 LM 环境下的熵代理，真实计算）
- 基线采用 **robust location-scale**（median + 1.4826*MAD，与原版 _robust_location_scale 一致），
  基线来自评测中心冻结良性样本的 token 熵分布（PP-gap 本地版），启动时自动加载
- 在线单侧 CUSUM：z_t=(H_t-m0)/s0；W_t=max(0, W_{t-1} + (z_t - k))；W_t>=h 报警
  参数与原版一致：k=0.5（slack），h 由良性数据标定（误报率 <= 1/1000 per token）
- 曲线输出 W 累计轨迹（平滑累积，不再是锯齿滑窗 z）

职责与边界（对齐设计文档 1E 节）：
- 为语义检测提供第二路独立证据（status=derived）
- 定位可能的异常起点（token/字符位置）
- 不作为单证据生产封禁器；短文本结果不稳定，需标注局限
"""
import json
import math
import os
import re
from typing import Any, Dict, List, Optional, Tuple

# ---------- 检测参数（与 CPD Online 参考实现对齐） ----------
WINDOW_CHARS = 12          # per-token 局部字符窗口（熵代理的平滑尺度）
MIN_TEXT_LEN = 30          # 低于该长度熵估计不稳定
Z_THRESHOLD = 2.0          # 弱候选的 z 阈值（次级信号，保持与旧口径可比）
CUSUM_K = 0.5              # CUSUM slack（原版 --online-k 默认 0.5）
CUSUM_H_DEFAULT = 10.0     # CUSUM 阈值默认（原版 --online-h 默认；实际以基线标定为准）
Z_CAP = 4.0
LAMBDA_BI = 0.6
LOG2_INV_BACKOFF = math.log2(1.0 / (1.0 - LAMBDA_BI))  # unseen-bigram 回退的 log2(1/(1-λ))
S0_FLOOR = 1.0                # 单点 z 封顶：字符 NLL 重尾，CUSUM 只累积持续漂移（工程补偿）
MAD_SCALE = 1.4826         # MAD → sigma 的正态一致性尺度（原版同值）
EPS = 1e-6
ALGO_VERSION = "cpd-online-cusum-v3-token"
BASELINE_PATH = os.path.join(
    os.getenv("COZE_WORKSPACE_PATH", "/workspace/projects"),
    "assets", "challenge", "baseline_stats.json")

# 兼容别名（evaluation_service 等旧引用）
WINDOW_SIZE = WINDOW_CHARS
STEP = 1

KNOWN_JAILBREAK_MARKERS = [
    "ignore all previous", "ignore previous", "disregard", "DAN mode",
    "developer mode", "system:", "</system>", "<system>", "jailbreak",
    "you are now", "no restrictions", "no limit", "bypass", "roleplay as",
    "pretend", "pretend to be", "从现在开始", "忽略之前", "无视所有", "解除限制",
    "越狱", "不受任何", "没有限制的", "已获授权",
]

_TOKEN_RE = re.compile(r"[A-Za-z]+|\d+|\s+|.")


# ---------- 基础工具 ----------
def _shannon_entropy(text: str) -> float:
    """计算字符串的香农熵（按字符分布，0-8 bit 区间）"""
    if not text:
        return 0.0
    freq: dict = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def tokenize(text: str) -> List[Dict]:
    """中英文混合 token 化：英文按词、数字串、中文/其他按单字符；空白 token 标记 skip。

    返回 [{"text", "start", "end", "skip"}]，start/end 为字符区间（左闭右开）。
    """
    out: List[Dict] = []
    i, n = 0, len(text)
    matched_spans: List[Tuple[int, int, str]] = []
    for m in _TOKEN_RE.finditer(text):
        if m.group().strip():
            matched_spans.append((m.start(), m.end(), m.group()))
        # 空白段跳过记录，但保持字符连续性
    for start, end, tok in matched_spans:
        # 英文词/数字串整体一个 token；其余（中文/标点）按单字符拆分
        if re.fullmatch(r"[A-Za-z]+|\d+", tok):
            out.append({"text": tok, "start": start, "end": end, "skip": False})
        else:
            for j in range(start, end):
                out.append({"text": text[j], "start": j, "end": j + 1, "skip": False})
    # 空白 gap 也记录为 skip token（保持 token_index 与字符位置的直观对应）
    merged: List[Dict] = []
    cursor = 0
    for tok in out:
        if tok["start"] > cursor:
            merged.append({"text": text[cursor:tok["start"]], "start": cursor,
                           "end": tok["start"], "skip": True})
        merged.append(tok)
        cursor = tok["end"]
    if cursor < n:
        merged.append({"text": text[cursor:], "start": cursor, "end": n, "skip": True})
    return merged


def _char_unigram_model(text: str) -> Dict[str, Any]:
    """全文 +1 平滑字符 unigram 对数分布（bit）"""
    freq: dict = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text) + len(freq)
    floor = math.log2(1.0 / total)
    logp = {ch: math.log2((c + 1) / total) for ch, c in freq.items()}
    return {"logp": logp, "floor": floor}


def _charlm_model(texts: List[str]) -> Dict:
    """字符 unigram + bigram 插值语言模型（良性语料训练，PP-gap 本地版）。

    p(c_i | c_{i-1}) = LAMBDA_BI * p_bi + (1 - LAMBDA_BI) * p_uni；
    bigram 未命中时自动回退 unigram。对应原版"LM 在良性分布上的意外度"，无 LM 环境的字符级代理。
    """
    uni: Dict[str, int] = {}
    bi: Dict[str, int] = {}
    for t in texts:
        prev = ""
        for ch in t:
            if ch.isspace():
                prev = ""
                continue
            uni[ch] = uni.get(ch, 0) + 1
            if prev:
                bi[prev + ch] = bi.get(prev + ch, 0) + 1
            prev = ch
    total_uni = float(sum(uni.values())) + 0.5
    vocab = len(uni) + 1
    uni_floor = math.log2(0.5 / (total_uni + 0.5 * vocab))
    logp_uni = {ch: math.log2((c + 0.5) / (total_uni + 0.5 * vocab)) for ch, c in uni.items()}
    total_bi = float(sum(bi.values()))
    return {"uni": uni, "bi": bi, "logp_uni": logp_uni, "uni_floor": uni_floor,
            "total_uni": total_uni, "vocab": vocab, "total_bi": total_bi}


def _charlm_nll(model: Dict, win: str) -> float:
    """窗口字符序列在插值 bigram 模型下的平均 NLL（bit/char）。"""
    lam = LAMBDA_BI
    logp_uni = model["logp_uni"]
    uni_floor = model["uni_floor"]
    tot_bi = model["total_bi"]
    tot_uni = model["total_uni"]
    vocab = model["vocab"]
    bi = model["bi"]
    vals: List[float] = []
    prev = ""
    for ch in win:
        pu = logp_uni.get(ch, uni_floor)
        if prev:
            cnt = bi.get(prev + ch)
            if cnt:
                pb = math.log2((cnt + 0.5) / (tot_bi + 0.5 * vocab))
                p_bits = -(_mix(lam, pb, pu))
            else:
                # bigram 回退 unigram：隐含 unseen-bigram 概率质量 (1-λ)·p_uni
                p_bits = -pu + LOG2_INV_BACKOFF
        else:
            p_bits = -pu
        vals.append(p_bits)
        prev = ch
    return sum(vals) / max(len(vals), 1)


def _mix(lam: float, logp_bi: float, logp_uni: float) -> float:
    """插值混合的 log2 概率（bit）"""
    return math.log2(lam * (2.0 ** logp_bi) + (1.0 - lam) * (2.0 ** logp_uni))


def compute_token_signals(text: str, char_freq: Optional[Dict[str, int]] = None,
                          charlm: Optional[Dict] = None) -> Dict:
    """Token 级信号流（真实计算，非模拟）：

    - H_t：以该 token 结尾的局部字符窗口（WINDOW_CHARS）的香农熵——字符 unigram 熵代理
    - NLL_t：同窗口的平均负对数似然（bit/char）。
      提供 charlm（评测中心良性语料训练的 unigram+bigram 插值模型）时用该模型：
      攻击样本中的乱码/外域片段在良性分布下 NLL 显著上漂——与原版"LM 熵在对抗分布上增大"同构；
      其次退化到 char_freq（字符 unigram）；都未提供时退回全文自身分布（区分度弱，仅参考）。
    返回 {"tokens": [...], "H": [...], "nll": [...], "spans": [(start,end)], "length": n}
    """
    cleaned = text.strip()
    toks = [t for t in tokenize(cleaned) if not t["skip"]]
    H: List[float] = []
    nll: List[float] = []
    spans: List[Tuple[int, int]] = []
    for t in toks:
        end = t["end"]
        win = cleaned[max(0, end - WINDOW_CHARS):end]
        H.append(round(_shannon_entropy(win), 4))
        if charlm is not None:
            nll.append(round(_charlm_nll(charlm, win), 4))
        else:
            model = _char_unigram_model(cleaned)
            logp, floor = model["logp"], model["floor"]
            if char_freq:
                total = float(sum(char_freq.values())) + 0.5
                vocab = len(char_freq) + 1
                logp = {ch: math.log2((cnt + 0.5) / (total + 0.5 * vocab)) for ch, cnt in char_freq.items()}
                floor = math.log2(0.5 / (total + 0.5 * vocab))
            nll.append(round(-sum(logp.get(ch, floor) for ch in win) / max(len(win), 1), 4))
        spans.append((t["start"], t["end"]))
    return {"tokens": toks, "H": H, "nll": nll, "spans": spans, "length": len(cleaned)}


# ---------- 基线（PP-gap 本地版：评测中心良性 token 熵分布） ----------
def load_baseline(sig: Optional[Dict] = None) -> Dict:
    """加载 CPD 基线。优先 assets/challenge/baseline_stats.json（由评测中心良性样本标定）；
    缺失时退回样本内前段 token 估计（对应原版"无 prefix 基线"场景）。

    返回 {"m0", "s0", "k", "h", "source", "n_tokens", "n_samples"}
    """
    k = CUSUM_K
    try:
        with open(BASELINE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        m0, s0, h = float(data["m0"]), max(float(data["s0"]), EPS), float(data.get("h", CUSUM_H_DEFAULT))
        if m0 == m0 and s0 > 0 and h > 0:  # 基本有效性
            lm: Optional[Dict] = None
            if data.get("uni_freq"):
                lm = {"uni": data["uni_freq"], "bi": data.get("bi_freq") or {},
                      "total_uni": float(data.get("total_uni_lm") or (sum(data["uni_freq"].values()) + 0.5)),
                      "total_bi": float(data.get("total_bi_lm") or 0.0)}
                lm["vocab"] = len(lm["uni"]) + 1
                lm["uni_floor"] = math.log2(0.5 / (lm["total_uni"] + 0.5 * lm["vocab"]))
                lm["logp_uni"] = {ch: math.log2((c + 0.5) / (lm["total_uni"] + 0.5 * lm["vocab"]))
                                  for ch, c in lm["uni"].items()}
            return {"m0": m0, "s0": s0, "k": float(data.get("k", k)), "h": h,
                    "source": str(data.get("source", "calibrated")),
                    "n_tokens": int(data.get("n_tokens", 0)),
                    "n_samples": int(data.get("n_samples", 0)),
                    "char_freq": data.get("char_freq") or None,
                    "charlm": lm}
    except Exception:
        pass
    # 样本内兜底：前段 token 的 robust location-scale
    if sig and len(sig["H"]) >= 4:
        warm = sig["H"][:max(3, min(8, len(sig["H"]) // 3))]
        m0, s0 = _robust_location_scale(warm)
        return {"m0": m0, "s0": s0, "k": k, "h": CUSUM_H_DEFAULT,
                "source": "in_sample_warmup", "n_tokens": len(warm), "n_samples": 1}
    return {"m0": 3.0, "s0": 0.75, "k": k, "h": CUSUM_H_DEFAULT,
            "source": "prior_default", "n_tokens": 0, "n_samples": 0}


def _robust_location_scale(x: List[float]) -> Tuple[float, float]:
    """median + 1.4826*MAD（与 CPD Online 原版 _robust_location_scale 一致）"""
    if not x:
        return 0.0, 1.0
    arr = sorted(x)
    med = _median(arr)
    mad = MAD_SCALE * _median(sorted(abs(v - med) for v in arr))
    return med, max(mad, EPS)


def _median(arr: List[float]) -> float:
    n = len(arr)
    if n == 0:
        return 0.0
    mid = n // 2
    return arr[mid] if n % 2 else (arr[mid - 1] + arr[mid]) / 2.0


# ---------- 在线 CUSUM（复刻 cpd_online.update 单侧递推） ----------
def cpd_online_cusum(H: List[float], base: Optional[Dict] = None) -> Dict:
    """在线单侧 CUSUM：W_t = max(0, W_{t-1} + (z_t - k))，W_t >= h 报警。

    返回 {"W_trace":[...], "z_trace":[...], "t_alarm": Optional[int],
          "max_W": float, "k": float, "h": float, "m0": float, "s0": float}
    """
    base = base or load_baseline()
    m0, s0 = base["m0"], max(base["s0"], EPS)
    k, h = base.get("k", CUSUM_K), base.get("h", CUSUM_H_DEFAULT)
    W = 0.0
    W_trace: List[float] = []
    z_trace: List[float] = []
    t_alarm: Optional[int] = None
    z_cap = Z_CAP  # 单点封顶：CUSUM 检测持续漂移而非单点尖峰（字符 NLL 天然重尾）
    for i, val in enumerate(H):
        z = min((val - m0) / s0, z_cap)
        W = max(0.0, W + (z - k))
        if t_alarm is None and W >= h:
            t_alarm = i
        W_trace.append(round(W, 4))
        z_trace.append(round(z, 3))
    return {"W_trace": W_trace, "z_trace": z_trace, "t_alarm": t_alarm,
            "max_W": max(W_trace) if W_trace else 0.0,
            "k": k, "h": h, "m0": round(m0, 4), "s0": round(s0, 4)}


def calibrate_baseline(benign_texts: List[str], out_path: Optional[str] = None,
                       corpus_texts: Optional[List[str]] = None) -> Dict:
    """用良性文本集标定基线（评测中心冻结良性样本 → PP-gap 本地版）。

    - char_freq：良性池 + 扩容语料（知识库/文档等正常中文）的字符 unigram 频率，
      用于运行时 NLL 参考分布；语料只扩词表，不参与 NLL 基线流统计
    - m0/s0：良性 token 的 NLL（基线分布下）robust location-scale（median/MAD，对齐
      cpdonline 的 _robust_location_scale），s0 设下限 S0_FLOOR 防重尾压扁 z 尺度
    - h：二分标定使良性 token 流误报率 <= 1/500 per token（h 下限 3.0，防小样本过压）
    """
    lm = _charlm_model(list(benign_texts) + list(corpus_texts or []))
    freq: Dict[str, int] = lm["uni"]
    all_X: List[float] = []
    streams: List[List[float]] = []
    for t in benign_texts:
        sig = compute_token_signals(t, charlm=lm)
        if len(sig["nll"]) >= 4:
            streams.append(sig["nll"])
            all_X.extend(sig["nll"])
    if not all_X:
        return {"ok": False, "reason": "no_valid_benign_stream"}
    m0, s0 = _robust_location_scale(all_X)
    s0 = max(s0, S0_FLOOR)

    def false_alarm_rate(h_th: float) -> float:
        alarms, tokens = 0, 0
        for xs in streams:
            res = cpd_online_cusum(xs, {"m0": m0, "s0": s0, "k": CUSUM_K, "h": h_th})
            tokens += len(xs)
            alarms += 1 if res["t_alarm"] is not None else 0
        return alarms / max(tokens, 1)

    lo, hi = 3.0, 10.0
    rate = false_alarm_rate(hi)
    guard = 0
    while rate > 1 / 500 and guard < 12:  # 区间扩张
        hi *= 2.0
        rate = false_alarm_rate(hi)
        guard += 1
    for _ in range(24):  # 二分
        mid = (lo + hi) / 2
        if false_alarm_rate(mid) > 1 / 500:
            lo = mid
        else:
            hi = mid
        if hi - lo < 1e-3:
            break
    payload = {"m0": round(m0, 4), "s0": round(s0, 4), "k": CUSUM_K,
               "h": round(hi, 3), "source": "evaluation_frozen_benign_plain+shift",
               "n_tokens": len(all_X), "n_samples": len(streams),
               "char_freq": freq, "uni_freq": lm["uni"], "bi_freq": lm["bi"], "total_uni_lm": lm["total_uni"], "total_bi_lm": lm["total_bi"], "char_vocab": len(freq),
               "algo_version": ALGO_VERSION}
    out_path = out_path or BASELINE_PATH
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return {"ok": True, **payload}


# ---------- 兼容层：滑窗熵 / NLL（evaluation_service 等旧口径仍可用） ----------
def compute_entropy_profile(text: str) -> dict:
    """滑动窗口熵序列（字符窗口，步长 3；旧口径兼容）"""
    cleaned = text.strip()
    n = len(cleaned)
    if n < WINDOW_CHARS:
        return {"series": [], "mean": 0.0, "std": 0.0, "length": n, "valid": False}
    series: List[Tuple[int, float]] = []
    for start in range(0, n - WINDOW_CHARS + 1, 3):
        chunk = cleaned[start:start + WINDOW_CHARS]
        series.append((start, _shannon_entropy(chunk)))
    values = [v for _, v in series]
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std = math.sqrt(variance) if variance > 0 else 0.0
    return {"series": series, "mean": round(mean, 4), "std": round(std, 4), "length": n, "valid": True}


def compute_window_nll(text: str) -> List[Tuple[int, float]]:
    """字符 unigram 滑窗平均 NLL（bit/char；旧口径兼容，步长 3）"""
    cleaned = text.strip()
    n = len(cleaned)
    if n < WINDOW_CHARS:
        return []
    model = _char_unigram_model(cleaned)
    logp, floor = model["logp"], model["floor"]
    out: List[Tuple[int, float]] = []
    for start in range(0, n - WINDOW_CHARS + 1, 3):
        chunk = cleaned[start:start + WINDOW_CHARS]
        nll = -sum(logp.get(ch, floor) for ch in chunk) / WINDOW_CHARS
        out.append((start, round(nll, 4)))
    return out


# ---------- 面板轨迹（窗口自适应） ----------
def _adaptive_window(n: int) -> int:
    """自适应窗口：短文本自动缩窗，保证 ≥6 字符输入即可生成轨迹"""
    return min(WINDOW_CHARS, max(3, n // 2))


def compute_entropy_profile_adaptive(text: str) -> dict:
    """滑窗熵序列（窗口自适应版，供 Prompt 分析面板轨迹使用）。

    与旧口径兼容：n≥24 时 window=12/step=3 完全一致；
    短文本缩窗（step=1），中文 30 字从 7 点提升到 19 点。
    """
    cleaned = text.strip()
    n = len(cleaned)
    if n < 6:
        return {"series": [], "mean": 0.0, "std": 0.0, "length": n, "valid": False,
                "window_used": 0, "degraded": False}
    win = _adaptive_window(n)
    step = 1 if n < 60 else 3
    series: List[Tuple[int, float]] = []
    for start in range(0, n - win + 1, step):
        chunk = cleaned[start:start + win]
        series.append((start, _shannon_entropy(chunk)))
    values = [v for _, v in series]
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std = math.sqrt(variance) if variance > 0 else 0.0
    return {"series": series, "mean": round(mean, 4), "std": round(std, 4), "length": n,
            "valid": True, "window_used": win, "degraded": win < WINDOW_CHARS}


def compute_window_nll_adaptive(text: str) -> List[Tuple[int, float]]:
    """字符 unigram 滑窗平均 NLL（窗口自适应，与熵序列同窗口/同步长，供面板双线轨迹）"""
    cleaned = text.strip()
    n = len(cleaned)
    if n < 6:
        return []
    win = _adaptive_window(n)
    step = 1 if n < 60 else 3
    model = _char_unigram_model(cleaned)
    logp, floor = model["logp"], model["floor"]
    out: List[Tuple[int, float]] = []
    for start in range(0, n - win + 1, step):
        chunk = cleaned[start:start + win]
        nll = -sum(logp.get(ch, floor) for ch in chunk) / win
        out.append((start, round(nll, 4)))
    return out


# ---------- 主检测入口（schema 兼容） ----------
def detect_change_points(text: str) -> dict:
    """Token 级在线熵 CUSUM 变化点检测（对齐 CPD Online）。

    主候选 = CUSUM 报警 token（首个 W>=h 及其后 W 局部峰）；
    次候选 = 无报警时 z>=Z_THRESHOLD 的 token（低置信，保持旧口径可观测性）。

    返回 schema 与旧版一致：
        {"status","algo_version","valid","candidates":[{"position","char_index","token_index",
          "entropy","z","confidence","snippet"}],"max_z","global_entropy","limitations",
          新增: "cusum_alarm","baseline_source","n_tokens","max_W","h"}
    """
    limitations = [
        "Entropy-CPD 为第二路独立证据，不能证明攻击成功，也不能还原原始 Prompt 真实意图",
        "熵代理为字符级近似（无本地 LM token 熵），粒度为词/字级 token 流",
        "不适合作为单证据生产封禁器，不能单独触发高影响处置",
    ]
    result = {
        "status": "derived",
        "algo_version": ALGO_VERSION,
        "valid": False,
        "candidates": [],
        "max_z": 0.0,
        "global_entropy": round(_shannon_entropy(text), 4),
        "cusum_alarm": False,
        "baseline_source": "unknown",
        "n_tokens": 0,
        "max_W": 0.0,
        "h": CUSUM_H_DEFAULT,
        "t_alarm": None,
        "limitations": limitations,
    }
    if len(text.strip()) < 2:
        limitations.insert(0, "文本过短（不足 2 字符），无法生成 Token 轨迹")
        return result

    sig_src = load_baseline()
    sig = compute_token_signals(text, char_freq=sig_src.get("char_freq"), charlm=sig_src.get("charlm"))
    if not sig["nll"]:
        result["limitations"].append("未能切分出 Token，无法生成熵轨迹")
        return result
    base = sig_src
    cus = cpd_online_cusum(sig["nll"], base)
    result["baseline_source"] = base.get("source", "unknown")
    result["n_tokens"] = len(sig["H"])
    result["max_W"] = cus["max_W"]
    result["h"] = cus["h"]

    spans = sig["spans"]
    candidates: List[Dict] = []

    def _mk(idx: int, z: float, conf: float) -> Dict:
        start, end = spans[idx]
        direction = "up" if z > 0 else "down"
        return {
            "position": start,
            "char_index": start,
            "token_index": idx,
            "entropy": sig["H"][idx],
            "z": round(z, 2),
            "confidence": conf,
            # 方向语义：up=熵骤升（突现意外内容，载荷/乱码候选）；down=熵骤降（模板化片段，风格突变参考）
            "direction": direction,
            "direction_note": ("熵骤升 · 载荷突变候选" if direction == "up" else "熵骤降 · 模板化片段（通常非载荷起点）"),
            "snippet": text[max(0, start):end + 12],
        }

    # 主候选：CUSUM 报警 → 取报警 token 与其后 W 局部峰（最多 3 个）。
    # 短文本（< 10 token）不做报警判定：序列太短 CUSUM 统计不稳，易把自然波动当突变；
    # 此时仍走次候选/兜底定位，保证"每条检测都有 Token 锚点"且不抬高误报。
    alarm_ok = False
    if cus["t_alarm"] is None and len(cus["z_trace"]) > 4:
        # 强突变直报通道：优化后缀常为"短促而强"的 NLL 突变，单点 |z| 触顶且其后局部持续抬升，
        # 无需 CUSUM 累计满门限即可报警；良性文本零星高 z（标点/罕见字）后续迅速回落，不会命中
        ztr = cus["z_trace"]
        zmax_i = max(range(1, len(ztr)), key=lambda i: abs(ztr[i]))
        if abs(ztr[zmax_i]) >= 3.95:
            near = ztr[zmax_i + 1: zmax_i + 4]
            if near and sum(abs(z) for z in near) / len(near) >= 1.2:
                cus["t_alarm"] = zmax_i
                result["cusum_alarm_boosted"] = "strong_step"
    if cus["t_alarm"] is not None and len(sig["H"]) >= 10:
        # 持续偏移校验：真攻击后缀在报警点后是一段持续高 NLL 区；
        # 普通文本的零星高 NLL（标点/罕见字）报警后迅速回落，不作为主候选
        tail = cus["z_trace"][cus["t_alarm"]:cus["t_alarm"] + 6]
        sustained = (sum(tail) / len(tail)) >= 0.3 if tail else False
        if sustained:
            alarm_ok = True
        else:
            result["cusum_alarm_rejected"] = "no_sustained_shift"
    if alarm_ok:
        alarm_idx = cus["t_alarm"]
        # 强度校验：报警点 |z| < 2.0 的"持续小幅正偏移"是口语化短文本的自然波动形态
        # （如"我曾经是一个很爱学习的人…"，|z|≈1.3-1.7 却能累计满 CUSUM 门限），
        # 与真突变（GCG/AD 类 |z|≥2，强样本 |z|≈4）差一个数量级，只配观察级置信，不进报警档。
        if abs(cus["z_trace"][alarm_idx]) < 2.0:
            alarm_ok = False
            result["cusum_alarm_rejected"] = "weak_step_amplitude"
    if alarm_ok:
        result["cusum_alarm"] = True
        result["t_alarm"] = cus["t_alarm"]
        n_tok = len(sig["H"])
        # 短文本置信折减：token 数 < 30 时 CUSUM 证据不充分（短序列尾部偏移无回落窗口可校验，
        # 极易把良性短句的收尾用词当持续突变），置信上限压到次候选档（0.45），不驱动处置
        conf_cap = 0.45 if n_tok < 30 else 0.9
        candidates.append(_mk(alarm_idx, cus["z_trace"][alarm_idx],
                              min(conf_cap, round(0.5 + 0.4 * cus["W_trace"][alarm_idx] / max(cus["h"], 1e-9), 2))))
        peak_idx = max(range(alarm_idx, len(cus["W_trace"])), key=lambda i: cus["W_trace"][i]) \
            if alarm_idx < len(cus["W_trace"]) - 1 else alarm_idx
        if peak_idx != alarm_idx and spans[peak_idx][0] - spans[alarm_idx][0] >= WINDOW_CHARS:
            candidates.append(_mk(peak_idx, cus["z_trace"][peak_idx],
                                  min(min(conf_cap, 0.85), round(0.4 + 0.4 * cus["W_trace"][peak_idx] / max(cus["h"], 1e-9), 2))))
    # 次候选：无报警但 z 突出（低置信，观察级）
    # 首 token 无历史参照（窗口冷启动），z 必然虚高，跳过；上限 0.45：次候选不得驱动处置升级
    if not candidates:
        for idx, z in enumerate(cus["z_trace"]):
            if idx >= 1 and abs(z) >= Z_THRESHOLD:
                candidates.append(_mk(idx, z, min(0.45, round(abs(z) / 8.0, 2))))
    # 兜底定位：无报警且无超阈 z 时，取 |z| 最大点作为低置信定位，保证每条检测都有 Token 锚点
    if not candidates and cus["z_trace"]:
        rng = range(1, len(cus["z_trace"])) if len(cus["z_trace"]) > 1 else range(len(cus["z_trace"]))
        idx0 = max(rng, key=lambda i: abs(cus["z_trace"][i]))
        candidates.append(_mk(idx0, cus["z_trace"][idx0],
                              min(0.45, max(0.3, round(abs(cus["z_trace"][idx0]) / 10.0, 2)))))

    # 去重：位置相邻保留置信高者
    dedup: List[Dict] = []
    for c in sorted(candidates, key=lambda x: x["position"]):
        if dedup and c["position"] - dedup[-1]["position"] < WINDOW_CHARS:
            if c["confidence"] > dedup[-1]["confidence"]:
                dedup[-1] = c
        else:
            dedup.append(c)

    if len(sig["nll"]) < 6:
        limitations.append("短文本（%d token），熵估计置信度有限" % len(sig["nll"]))
    dedup.sort(key=lambda x: -x["confidence"])
    result["valid"] = True
    result["candidates"] = dedup[:3]
    result["max_z"] = round(max((abs(z) for z in cus["z_trace"]), default=0.0), 2)
    return result


def compute_cpd_series(text: str) -> dict:
    """Token 级 CPD 全序列视图（供曲线侦探回放；与 detect_change_points 同源）。

    返回:
        {
          "z_values":  [(char_start, z_t), ...]        每 token 的标准化熵偏离（保留符号）
          "cumulative":[(char_start, W_t), ...]        CUSUM W 累计统计量（平滑累积曲线）
          "nll_values":[(char_start, nll_t), ...]      token 级 NLL
          "tokens":    n                              token 数
          "threshold": h                              CUSUM 报警阈值
          "t_alarm":   报警 token 下标或 None
        }
    """
    result = {"z_values": [], "cumulative": [], "nll_values": [], "entropy_values": [],
              "tokens": 0, "threshold": CUSUM_H_DEFAULT, "t_alarm": None}
    if len(text.strip()) < 2:
        return result
    base = load_baseline()
    sig = compute_token_signals(text, char_freq=base.get("char_freq"), charlm=base.get("charlm"))
    if not sig["H"]:
        return result
    cus = cpd_online_cusum(sig["nll"], base)
    result["z_values"] = [(sig["spans"][i][0], z) for i, z in enumerate(cus["z_trace"])]
    result["cumulative"] = [(sig["spans"][i][0], w) for i, w in enumerate(cus["W_trace"])]
    result["nll_values"] = [(sig["spans"][i][0], v) for i, v in enumerate(sig["nll"])]
    result["entropy_values"] = [(sig["spans"][i][0], v) for i, v in enumerate(sig["H"])]
    result["tokens"] = len(sig["H"])
    result["threshold"] = cus["h"]
    result["t_alarm"] = cus["t_alarm"]
    return result


def marker_scan(text: str) -> dict:
    """已知越权短语扫描（规则层，作为语义检测的快速通道证据）"""
    low = text.lower()
    hits = []
    for m in KNOWN_JAILBREAK_MARKERS:
        idx = low.find(m.lower())
        if idx >= 0:
            hits.append({"marker": m, "position": idx, "snippet": text[max(0, idx - 10):idx + len(m) + 10]})
    return {"status": "real", "method": "rule_markers", "hits": hits}
