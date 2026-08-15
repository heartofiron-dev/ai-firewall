from __future__ import annotations

import hashlib
import html
import json
import re
import secrets
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit


MAX_SOURCE_BYTES = 100 * 1024 * 1024
MAX_FEEDBACK_BYTES = 10 * 1024 * 1024
MAX_REQUEST_BYTES = 16 * 1024
ALERT_ID_PATTERN = re.compile(r"^[0-9a-f]{16}$")
ALLOWED_SEVERITIES = {"", "critical", "high", "medium", "info"}


_INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="api-token" content="{token}">
  <title>AI Firewall 本地仪表盘</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <header>
    <div>
      <p class="eyebrow">LOCAL-ONLY DETECTION</p>
      <h1>AI Firewall</h1>
      <p class="subtitle">连接与告警仪表盘 · 仅分析，不自动拦截</p>
    </div>
    <div class="live"><span></span><strong id="status">正在连接</strong></div>
  </header>
  <main>
    <section class="metrics" aria-label="概览">
      <article><span>当前记录</span><strong id="total">0</strong></article>
      <article><span>严重告警</span><strong id="critical">0</strong></article>
      <article><span>已标误报</span><strong id="feedback">0</strong></article>
      <article><span>跳过坏行</span><strong id="skipped">0</strong></article>
    </section>
    <section class="panel controls" aria-label="筛选">
      <label>严重级别
        <select id="severity">
          <option value="">全部</option><option value="critical">Critical</option>
          <option value="high">High</option><option value="medium">Medium</option>
          <option value="info">Info</option>
        </select>
      </label>
      <label class="search">搜索连接、进程或原因
        <input id="query" maxlength="100" placeholder="例如 3389、browser、PORT_SCAN">
      </label>
      <button id="refresh" type="button">立即刷新</button>
    </section>
    <section class="panel">
      <div class="table-title"><h2>连接与告警</h2><small id="updated">尚未刷新</small></div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>时间 / 级别</th><th>连接</th><th>进程 / 方向</th><th>风险与证据</th><th>人工标记</th></tr></thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
      <p id="empty" class="empty">暂无匹配记录。可以先运行 analyze，或让 monitor 写入同一个 JSONL。</p>
    </section>
  </main>
  <footer>数据只从本机 JSONL 读取；误报标记进入独立审核队列，不会自动训练或修改防火墙。</footer>
  <script src="/app.js" defer></script>
</body>
</html>
"""


_STYLE_CSS = """
:root{color-scheme:dark;--bg:#08111f;--panel:#111d2e;--line:#26364d;--text:#e7eef8;--muted:#91a4bd;--accent:#3dd9b4;--danger:#ff6577;--warn:#ffba5c}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top right,#15304a 0,var(--bg) 42%);color:var(--text);font:14px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;min-height:100vh}
header,main,footer{max-width:1280px;margin:auto}header{display:flex;justify-content:space-between;align-items:center;padding:36px 24px 20px}h1{font-size:36px;letter-spacing:-1px;margin:0}.eyebrow{color:var(--accent);font-size:11px;font-weight:800;letter-spacing:2px;margin:0}.subtitle,small,footer{color:var(--muted)}.subtitle{margin:4px 0}.live{display:flex;align-items:center;gap:9px;background:#10273a;border:1px solid #27506b;border-radius:999px;padding:9px 14px}.live span{width:9px;height:9px;border-radius:50%;background:var(--accent);box-shadow:0 0 12px var(--accent)}main{padding:0 24px 32px}.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}.metrics article,.panel{background:rgba(17,29,46,.94);border:1px solid var(--line);border-radius:14px;box-shadow:0 18px 44px rgba(0,0,0,.18)}.metrics article{padding:18px}.metrics span{display:block;color:var(--muted)}.metrics strong{font-size:28px}.panel{margin-top:14px;padding:18px}.controls{display:flex;align-items:end;gap:14px}.controls label{color:var(--muted);font-weight:650}.search{flex:1}select,input,button{margin-top:6px;height:40px;border-radius:9px;border:1px solid #334760;background:#0a1524;color:var(--text);padding:0 12px;font:inherit}input{width:100%}button{background:#153f4a;border-color:#277c79;color:#dffcf4;font-weight:750;cursor:pointer}button:hover{background:#1b535d}.table-title{display:flex;justify-content:space-between;align-items:center}.table-title h2{margin:0 0 10px}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:900px}th,td{text-align:left;padding:12px 10px;border-top:1px solid var(--line);vertical-align:top;white-space:pre-line}th{color:var(--muted);font-size:12px}.badge{display:inline-block;border-radius:999px;padding:2px 8px;font-size:11px;text-transform:uppercase;font-weight:800;background:#24364b}.critical{color:#ffd8de;background:#602b38}.high{color:#ffe4bd;background:#604226}.medium{color:#fff1bd;background:#584d22}.risk{font:700 16px ui-monospace,monospace}.muted{color:var(--muted)}.evidence{max-width:420px}.feedback-done{color:var(--accent);font-weight:750}.empty{text-align:center;color:var(--muted);padding:28px 0;margin:0;display:none}footer{text-align:center;padding:0 24px 28px;font-size:12px}
@media(max-width:760px){header{align-items:flex-start;gap:16px}.metrics{grid-template-columns:repeat(2,1fr)}.controls{align-items:stretch;flex-direction:column}.controls button{width:100%}}
"""


_APP_JS = """
const $=id=>document.getElementById(id);const token=document.querySelector('meta[name="api-token"]').content;
function cell(text,cls=''){const el=document.createElement('td');el.textContent=text??'';if(cls)el.className=cls;return el}
function render(data){$('total').textContent=data.count;$('critical').textContent=data.alerts.filter(x=>x.severity==='critical').length;$('feedback').textContent=data.feedback_count;$('skipped').textContent=data.skipped_lines;$('updated').textContent='更新于 '+new Date(data.updated_at).toLocaleTimeString();$('status').textContent=data.source_exists?'实时刷新中':'等待数据文件';const body=$('rows');body.replaceChildren();$('empty').style.display=data.alerts.length?'none':'block';for(const alert of data.alerts){const tr=document.createElement('tr');const first=cell(alert.timestamp||'未知时间');const badge=document.createElement('span');badge.className='badge '+(alert.severity||'info');badge.textContent=alert.severity||'info';first.append(document.createElement('br'),badge);tr.append(first);tr.append(cell(`${alert.src_ip||'?'} → ${alert.dst_ip||'?'}:${alert.dst_port??'?'} / ${alert.protocol||'?'}`));tr.append(cell(`${alert.process_name||'—'}${alert.process_id?` (${alert.process_id})`:''}\n${alert.direction||alert.connection_state||'—'}`,'muted'));const reasons=Array.isArray(alert.reasons)?alert.reasons.join('；'):'无解释';tr.append(cell(`${Number(alert.risk_score||0).toFixed(4)}\n${reasons}`,'evidence risk'));const action=document.createElement('td');if(alert._feedback){const done=document.createElement('span');done.className='feedback-done';done.textContent='✓ 已标记误报';action.append(done)}else{const button=document.createElement('button');button.type='button';button.textContent='标记误报';button.addEventListener('click',()=>markFalsePositive(alert._id,button));action.append(button)}tr.append(action);body.append(tr)}}
async function load(){const params=new URLSearchParams({severity:$('severity').value,q:$('query').value.trim()});try{const response=await fetch('/api/alerts?'+params,{cache:'no-store'});if(!response.ok)throw new Error('HTTP '+response.status);render(await response.json())}catch(error){$('status').textContent='读取失败';console.error(error)}}
async function markFalsePositive(id,button){button.disabled=true;try{const response=await fetch('/api/feedback',{method:'POST',headers:{'Content-Type':'application/json','X-AI-Firewall-Token':token},body:JSON.stringify({alert_id:id})});if(!response.ok)throw new Error('HTTP '+response.status);await load()}catch(error){button.disabled=false;$('status').textContent='标记失败';console.error(error)}}
$('refresh').addEventListener('click',load);$('severity').addEventListener('change',load);let timer;$('query').addEventListener('input',()=>{clearTimeout(timer);timer=setTimeout(load,250)});load();setInterval(load,2000);
"""


def _alert_id(alert: dict[str, Any]) -> str:
    payload = json.dumps(alert, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _search_text(alert: dict[str, Any]) -> str:
    fields = (
        "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "severity", "process_id", "process_name", "direction", "connection_state",
        "model_algorithm", "model_version",
    )
    values = [str(alert.get(name, "")) for name in fields]
    for name in ("reasons", "rule_ids"):
        value = alert.get(name, [])
        if isinstance(value, list):
            values.extend(str(item) for item in value)
        else:
            values.append(str(value))
    return " ".join(values).casefold()


def load_feedback_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    if path.stat().st_size > MAX_FEEDBACK_BYTES:
        raise ValueError("误报队列超过 10 MiB 安全上限，请先审核或归档")
    ids: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            alert_id = item.get("alert_id") if isinstance(item, dict) else None
            if isinstance(alert_id, str) and ALERT_ID_PATTERN.fullmatch(alert_id):
                ids.add(alert_id)
    return ids


def load_alerts(
    path: Path, feedback_path: Path, *, limit: int = 500,
    severity: str = "", query: str = "",
) -> tuple[list[dict[str, Any]], int, int]:
    if limit < 1 or limit > 5000:
        raise ValueError("limit 必须在 1 到 5000 之间")
    if severity not in ALLOWED_SEVERITIES:
        raise ValueError("不支持的严重级别")
    if len(query) > 100:
        raise ValueError("搜索词不能超过 100 个字符")
    if not path.exists():
        return [], 0, len(load_feedback_ids(feedback_path))
    if path.stat().st_size > MAX_SOURCE_BYTES:
        raise ValueError("告警文件超过 100 MiB 安全上限，请先轮换或归档")

    feedback_ids = load_feedback_ids(feedback_path)
    records: deque[dict[str, Any]] = deque(maxlen=limit)
    skipped = 0
    normalized_query = query.casefold().strip()
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            if not isinstance(item, dict):
                skipped += 1
                continue
            if severity and str(item.get("severity", "")).casefold() != severity:
                continue
            if normalized_query and normalized_query not in _search_text(item):
                continue
            record = dict(item)
            record["_id"] = _alert_id(item)
            record["_feedback"] = record["_id"] in feedback_ids
            records.append(record)
    return list(reversed(records)), skipped, len(feedback_ids)


@dataclass(frozen=True)
class DashboardState:
    alerts_path: Path
    feedback_path: Path
    max_alerts: int = 500

    def __post_init__(self) -> None:
        if self.alerts_path.resolve() == self.feedback_path.resolve():
            raise ValueError("告警输入与误报队列不能是同一个文件")
        if self.alerts_path.suffix.casefold() != ".jsonl" or self.feedback_path.suffix.casefold() != ".jsonl":
            raise ValueError("告警输入与误报队列都必须使用 .jsonl 扩展名")
        if self.alerts_path.is_symlink() or self.feedback_path.is_symlink():
            raise ValueError("仪表盘拒绝符号链接文件")
        if not 1 <= self.max_alerts <= 5000:
            raise ValueError("max_alerts 必须在 1 到 5000 之间")

    def record_false_positive(self, alert_id: str, note: str = "") -> bool:
        if not ALERT_ID_PATTERN.fullmatch(alert_id):
            raise ValueError("alert_id 格式无效")
        if len(note) > 240:
            raise ValueError("备注不能超过 240 个字符")
        alerts, _, _ = load_alerts(
            self.alerts_path, self.feedback_path, limit=self.max_alerts,
        )
        if alert_id not in {item["_id"] for item in alerts}:
            raise ValueError("告警不存在或已超出当前审核窗口")
        if alert_id in load_feedback_ids(self.feedback_path):
            return False
        self.feedback_path.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "alert_id": alert_id,
            "label": "false_positive",
            "note": note,
            "review_status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        with self.feedback_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
            handle.flush()
        return True


class DashboardServer(HTTPServer):
    # On Windows SO_REUSEADDR can let two processes accept the same port,
    # making the UI origin ambiguous. Fail closed when the port is occupied.
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], state: DashboardState, token: str | None = None):
        self.state = state
        self.api_token = token or secrets.token_urlsafe(32)
        super().__init__(address, DashboardHandler)


class DashboardHandler(BaseHTTPRequestHandler):
    server: DashboardServer

    def log_message(self, format: str, *args: object) -> None:
        return

    def _host_allowed(self) -> bool:
        host = self.headers.get("Host", "")
        try:
            hostname = urlsplit(f"//{host}").hostname
        except ValueError:
            return False
        return hostname in {"127.0.0.1", "localhost", "::1"}

    def _headers(self, status: int, content_type: str, length: int) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(length))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
        )
        self.end_headers()

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self._headers(status, content_type, len(body))
        self.wfile.write(body)

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send(status, body, "application/json; charset=utf-8")

    def _reject_bad_host(self) -> bool:
        if self._host_allowed():
            return False
        self._json(403, {"error": "只接受本机 Host"})
        return True

    def do_GET(self) -> None:
        if self._reject_bad_host():
            return
        parsed = urlsplit(self.path)
        if parsed.path == "/":
            body = _INDEX_HTML.format(token=html.escape(self.server.api_token, quote=True)).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return
        if parsed.path == "/style.css":
            self._send(200, _STYLE_CSS.encode("utf-8"), "text/css; charset=utf-8")
            return
        if parsed.path == "/app.js":
            self._send(200, _APP_JS.encode("utf-8"), "text/javascript; charset=utf-8")
            return
        if parsed.path == "/api/alerts":
            params = parse_qs(parsed.query, keep_blank_values=True)
            severity = params.get("severity", [""])[0].casefold()
            query = params.get("q", [""])[0]
            try:
                alerts, skipped, feedback_count = load_alerts(
                    self.server.state.alerts_path,
                    self.server.state.feedback_path,
                    limit=self.server.state.max_alerts,
                    severity=severity,
                    query=query,
                )
            except (OSError, ValueError) as exc:
                self._json(400, {"error": str(exc)})
                return
            self._json(200, {
                "alerts": alerts,
                "count": len(alerts),
                "feedback_count": feedback_count,
                "skipped_lines": skipped,
                "source_exists": self.server.state.alerts_path.exists(),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self._reject_bad_host():
            return
        if urlsplit(self.path).path != "/api/feedback":
            self._json(404, {"error": "not found"})
            return
        if not secrets.compare_digest(
            self.headers.get("X-AI-Firewall-Token", ""), self.server.api_token,
        ):
            self._json(403, {"error": "invalid token"})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "Content-Type 必须为 application/json"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_REQUEST_BYTES:
            self._json(413, {"error": "请求体大小无效"})
            return
        try:
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("请求体必须是对象")
            created = self.server.state.record_false_positive(
                str(payload.get("alert_id", "")), str(payload.get("note", "")),
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, OSError) as exc:
            self._json(400, {"error": str(exc)})
            return
        self._json(201 if created else 200, {"created": created})


def serve_dashboard(
    alerts_path: str | Path, feedback_path: str | Path,
    *, port: int = 8765, max_alerts: int = 500,
) -> None:
    if not 1 <= port <= 65535:
        raise ValueError("port 必须在 1 到 65535 之间")
    state = DashboardState(Path(alerts_path), Path(feedback_path), max_alerts)
    server = DashboardServer(("127.0.0.1", port), state)
    print(f"本地仪表盘: http://127.0.0.1:{port}")
    print(f"读取: {state.alerts_path}；误报审核队列: {state.feedback_path}")
    print("仅绑定回环地址，不会启动采集、上传数据、自动训练或修改防火墙。按 Ctrl+C 停止。")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        print("\n本地仪表盘已停止。")
    finally:
        server.server_close()
