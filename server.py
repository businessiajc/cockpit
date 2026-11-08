"""Cockpit : suivi local d'un agent Claude Code (lecture de fichiers uniquement).

Serveur http.server sur 127.0.0.1. Aucune dependance externe, aucun appel reseau sortant.
"""
import argparse
import ast
import json
import os
import re
import sys
import threading
import time
import unicodedata
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
FROZEN = bool(getattr(sys, "frozen", False))
RES_DIR = getattr(sys, "_MEIPASS", HERE)       # ressources embarquees (index.html, descriptions.json)
APP_DIR = os.path.dirname(os.path.abspath(sys.executable)) if FROZEN else HERE   # a cote de l'exe : config.json
CONFIG_PATH = os.path.join(APP_DIR, "config.json")
DEFAULT_PORT = 8780
HOST = "127.0.0.1"

IGNORED = {".git", "node_modules", "__pycache__", "dist", "build", "venv", ".venv", "_secrets", "secrets",
           ".env", "chromium_headless_shell", "extensions_crx_cache", "component_crx_cache", ".cache",
           ".pytest_cache", ".idea", ".vscode", "logs", "tmp"}   # comparaison sans casse
BASE_IGNORED = frozenset(IGNORED)
PROFILE_MARKERS = ("Local State", "Preferences")   # un dossier qui les contient = profil de navigateur
TREE_EXT = {".md", ".py", ".json", ".html", ".js", ".bat", ".sh", ".txt", ".toml", ".yml", ".yaml"}
TREE_NAMES = {"license", "licence", ".gitignore"}   # fichiers sans extension reconnus
CODE_MAX = 400 * 1024          # taille maximale d'un fichier affiche en entier
REFUSED_EXT = {".pem", ".key", ".pfx", ".p12", ".crt", ".kdbx"}
MAX_NODES = 1500
MAX_DEPTH = 6
INITIAL_WINDOW = 3_000_000   # octets lus a la fin d'un gros fichier au premier chargement
MAX_EVENTS = 3000
PREVIEW_LINES = 60
PREVIEW_BYTES = 200_000

# ----------------------------------------------------------------- masquage
_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/=]{8,}", re.I),
    re.compile(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9_\-]{10,}"),
    re.compile(r"\bAIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{12,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
]
_KV_PATTERN = re.compile(
    r"(?i)\b((?:api[_-]?key|secret|token|passw(?:or)?d|mot_de_passe)[\"']?\s*[:=]\s*[\"']?)([^\s\"',;]{6,})")


def mask(text):
    """Remplace toute chaine ressemblant a une cle ou un jeton par [MASQUE]."""
    if not isinstance(text, str):
        return text
    for pat in _SECRET_PATTERNS:
        text = pat.sub("[MASQUE]", text)
    return _KV_PATTERN.sub(lambda m: m.group(1) + "[MASQUE]", text)


def fix_mojibake(s):
    if isinstance(s, str) and ("\u00c3" in s or "\u00e2\u20ac" in s):
        try:
            return s.encode("cp1252").decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            return s
    return s


def clean(s, n=200):
    s = mask(fix_mojibake(s if isinstance(s, str) else str(s)))
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n - 1] + "\u2026"


# ------------------------------------------------------------ lecteur JSONL
def summarize_tool(name, inp):
    if not isinstance(inp, dict):
        return ""
    for k in ("command", "file_path", "path", "pattern", "url", "query", "description", "prompt"):
        v = inp.get(k)
        if isinstance(v, str) and v:
            return clean(v, 160)
    for v in inp.values():
        if isinstance(v, str) and v:
            return clean(v, 160)
    return ""


def _ts(s):
    """Horodatage ISO -> secondes (float), ou None."""
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


PLAN_TOOL = "mcp__ccd_turn__update_plan"
TEST_RE = re.compile(r"(?:\btest_|\bunittest\b|\bpytest\b|\bnpm (?:run )?test\b)")
NOTIF_RE = re.compile(r"<task-notification>(.*?)</task-notification>", re.S)


def short_name(path):
    return re.split(r"[\\/]", (path or "").rstrip("\\/"))[-1] or (path or "")


def first_sentence(text, n=160):
    text = " ".join((text or "").split())
    m = re.search(r"(?<=[.!?])\s", text)
    if m:
        text = text[:m.start()]
    return text if len(text) <= n else text[:n - 1] + "…"


def extract_commit(cmd):
    """Message d'un `git commit` (option -m ou heredoc), ou None."""
    if not isinstance(cmd, str) or "git commit" not in cmd:
        return None
    m = re.search(r"<<-?\s*['\"]?(\w+)['\"]?[ \t]*\r?\n(.*?)(?:\r?\n[ \t]*\1\b|$)", cmd, re.S)
    if m:
        for ln in m.group(2).splitlines():
            if ln.strip():
                return clean(ln.strip(), 120)
    m = re.search(r"""(?:-m|--message)[ =]+(?:"((?:[^"\\]|\\.)*)"|'([^']*)')""", cmd)
    if m:
        txt = (m.group(1) or m.group(2) or "").strip()
        return clean(txt.splitlines()[0], 120) if txt else None
    return None


def apply_plan(plan, inp):
    """Applique un appel update_plan (items complets, ou advance/done/start) a la liste courante."""
    if not isinstance(inp, dict):
        return plan
    items = inp.get("items")
    if isinstance(items, list) and items:
        out = []
        for it in items:
            if isinstance(it, dict) and it.get("content"):
                st = it.get("status") if it.get("status") in ("pending", "in_progress", "completed") else "pending"
                out.append({"content": clean(it["content"], 140), "status": st})
        return out
    plan = [dict(p) for p in plan]
    if inp.get("advance"):
        cur = next((i for i, p in enumerate(plan) if p["status"] == "in_progress"), None)
        if cur is not None:
            plan[cur]["status"] = "completed"
        nxt = next((i for i, p in enumerate(plan) if p["status"] == "pending"), None)
        if nxt is not None:
            plan[nxt]["status"] = "in_progress"
    for n in inp.get("done") or []:
        if isinstance(n, int) and 1 <= n <= len(plan):
            plan[n - 1]["status"] = "completed"
    st = inp.get("start")
    if isinstance(st, int) and 1 <= st <= len(plan):
        plan[st - 1]["status"] = "in_progress"
    return plan


def phrase_for(ev):
    """Evenement brut -> {'kind','text','key'} en francais simple (ou None si a ignorer)."""
    k = ev.get("kind")
    if k == "text":
        return {"kind": "say", "key": None, "text": "A dit : " + clean(re.sub(r"[*`#]+", "", ev.get("text", "")), 140)}
    if k == "user":
        return {"kind": "user", "key": None, "text": "Vous avez écrit : " + clean(ev.get("text", ""), 140)}
    if k == "error":
        return {"kind": "error", "key": None, "text": "Un problème est survenu : " + clean(ev.get("text", ""), 140)}
    if k != "tool":
        return None
    name = ev.get("name", "")
    summ = ev.get("summary", "")
    if name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        return {"kind": "write", "key": None,
                "text": "A écrit ou modifié " + short_name(ev.get("file") or summ)}
    if name == "Read":
        return {"kind": "read", "key": "read", "text": "A lu " + short_name(summ)}
    if name in ("Grep", "Glob"):
        return {"kind": "find", "key": "find", "text": "A cherché dans les fichiers"}
    if name == "Bash":
        cmd = summ
        if "git commit" in cmd:
            msg = ev.get("commit")
            return {"kind": "git", "key": None,
                    "text": "A enregistré une version" + (" : " + msg if msg else "")}
        if "git push" in cmd:
            return {"kind": "git", "key": None, "text": "A publié sur GitHub"}
        if re.search(r"\bcurl\b", cmd):
            return {"kind": "web", "key": None, "text": "A vérifié qu'un site répond"}
        if TEST_RE.search(cmd):
            return {"kind": "test", "key": None, "text": "A lancé un test"}
        return {"kind": "cmd", "key": None, "text": "A exécuté une commande"}
    if name in ("WebSearch", "WebFetch"):
        return {"kind": "web", "key": None, "text": "A cherché sur le web : " + clean(summ, 100)}
    if name == "Agent":
        return {"kind": "agent", "key": None, "text": "A lancé un agent : " + clean(summ, 100)}
    if name == PLAN_TOOL:
        return {"kind": "plan", "key": None, "text": "A mis à jour son plan"}
    return {"kind": "other", "key": None, "text": "A utilisé un outil (" + clean(name, 40) + ")"}


def details_for(ev):
    k = ev.get("kind")
    if k in ("text", "user", "error"):
        return [clean(ev.get("text", ""), 600)]
    out = ["Outil : " + ev.get("name", "?")]
    if ev.get("summary"):
        out.append("Résumé : " + ev["summary"])
    if ev.get("file"):
        out.append("Fichier : " + ev["file"])
    if ev.get("dur") is not None:
        out.append("Durée : %s s" % ev["dur"])
    if ev.get("error"):
        out.append("Résultat : échec")
    return out


def build_timeline(events, limit=50):
    """Regroupe les evenements en phrases simples. Plus recent en premier."""
    items = []
    for ev in events:
        p = phrase_for(ev)
        if not p:
            continue
        last = items[-1] if items else None
        if p["key"] and last and last["_key"] == p["key"]:
            last["n"] += 1
            last["names"].append(p["text"][5:] if p["key"] == "read" else "")
            last["details"].extend(details_for(ev))
            last["ts_end"] = ev.get("ts")
            continue
        items.append({"seq": ev["seq"], "ts": ev.get("ts"), "ts_end": ev.get("ts"), "kind": p["kind"],
                      "text": p["text"], "_key": p["key"], "n": 1, "names": [p["text"][5:]],
                      "details": details_for(ev)})
    out = []
    for it in items[-limit:]:
        if it["_key"] == "read" and it["n"] > 1:
            it["text"] = "A lu %d fichiers" % it["n"]
        elif it["_key"] == "find" and it["n"] > 1:
            it["text"] = "A cherché dans les fichiers (%d recherches)" % it["n"]
        it.pop("_key")
        it.pop("names")
        out.append(it)
    out.reverse()
    return out


def norm_name(s):
    s = unicodedata.normalize("NFKD", str(s or "")).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def next_run(horaires, now):
    """Prochaine execution parmi des 'HH:MM' -> (datetime, libelle) ou (None, None)."""
    times = []
    for h in horaires or []:
        m = re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*", str(h))
        if m and int(m.group(1)) < 24 and int(m.group(2)) < 60:
            times.append((int(m.group(1)), int(m.group(2))))
    if not times:
        return None, None
    times.sort()
    for day in (0, 1):
        base = (now + timedelta(days=day)).replace(hour=0, minute=0, second=0, microsecond=0)
        for hh, mm in times:
            c = base + timedelta(hours=hh, minutes=mm)
            if c > now:
                return c, ("aujourd'hui" if day == 0 else "demain") + " à %02d:%02d" % (hh, mm)
    return None, None


STATUS_LABELS = {"running": "En cours", "done": "Terminé", "planned": "Planifié",
                 "failed": "Échec", "paused": "En pause", "unknown": "État inconnu"}


def load_agents_file(path):
    res = {"found": False, "agents": [], "error": None, "path": path}
    if not os.path.isfile(path):
        return res
    res["found"] = True
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        res["error"] = "Fichier illisible : " + clean(str(e), 100)
        return res
    lst = data.get("agents") if isinstance(data, dict) else data
    for a in lst if isinstance(lst, list) else []:
        if not isinstance(a, dict):
            continue
        nom = a.get("nom") or a.get("name") or a.get("id")
        if not nom:
            continue
        hor = a.get("horaires") if isinstance(a.get("horaires"), list) else []
        res["agents"].append({
            "id": clean(a.get("id") or nom, 80), "nom": clean(nom, 120), "role": clean(a.get("role", ""), 300),
            "type": clean(a.get("type", ""), 40), "horaires": [clean(h, 10) for h in hor],
            "fichier": clean(a.get("fichier", ""), 200), "etat": clean(a.get("etat", ""), 30).lower()})
    return res


def _reg_status(a):
    e = a["etat"]
    if e in ("termine", "terminé", "fini", "done"):
        return "done"
    if e in ("echec", "échec", "erreur", "failed"):
        return "failed"
    if e in ("en_cours", "encours", "running"):
        return "running"
    if e in ("inactif", "pause", "paused", "desactive", "désactivé"):
        return "paused"
    if a["type"] in ("planifie", "planifié") or a["horaires"]:
        return "planned"
    return "running" if e == "actif" else "unknown"


def merge_agents(registered, detected, now):
    """Fiches d'agents : le registre d'abord, puis les sous-agents detectes absents du registre."""
    cards, used = [], set()
    dets = [(norm_name(d["name"]), i, d) for i, d in enumerate(detected)]
    for a in registered:
        key = norm_name(a["nom"])
        det = None
        for dk, i, d in dets:
            if i not in used and dk and key and (dk == key or (min(len(dk), len(key)) >= 10 and (dk in key or key in dk))):
                det = d
                used.add(i)
                break
        st = _reg_status(a)
        card = dict(a, source="registre", detail="", started=None, ended=None, duree_s=None)
        if det and st not in ("planned", "paused"):
            st = det["status"]
        if det:
            card.update(detail=det.get("result", ""), started=det.get("started"), ended=det.get("ended"),
                        duree_s=det.get("duree_s"))
        nd, label = next_run(a["horaires"], now) if st == "planned" else (None, None)
        card.update(status=st, status_label=STATUS_LABELS[st], next_run=label,
                    last_activity=card["ended"] or card["started"])
        cards.append(card)
    for i, (_, _, d) in enumerate(dets):
        if i in used:
            continue
        st = d["status"]
        cards.append({"id": d["id"], "nom": d["name"], "role": d.get("result") or "Agent lancé pendant la session.",
                      "type": "sous-agent", "horaires": [], "fichier": "", "etat": st, "source": "détecté",
                      "detail": d.get("result", ""), "started": d.get("started"), "ended": d.get("ended"),
                      "duree_s": d.get("duree_s"), "status": st, "status_label": STATUS_LABELS[st],
                      "next_run": None, "last_activity": d.get("ended") or d.get("started")})
    return cards


class IncrementalReader:
    """Lit un JSONL de session par morceaux, sans jamais relire ce qui l'a deja ete."""

    def __init__(self, path, initial_window=INITIAL_WINDOW, max_events=MAX_EVENTS):
        self.path = path
        self.offset = 0
        self.seq = 0
        self.events = []
        self.pending = {}        # tool_use_id -> (seq, ts)
        self.calls = 0
        self.errors = 0
        self.files = {}          # chemin -> nb de modifications
        self.searches = 0        # WebSearch + WebFetch
        self.tests = 0
        self.plan = []           # derniere liste de taches (update_plan)
        self.agents = {}         # tool_use_id -> fiche de sous-agent
        self.agent_by_aid = {}   # agentId -> fiche
        self.initial_window = initial_window
        self.max_events = max_events
        self.started = False

    def _emit(self, ev):
        self.seq += 1
        ev["seq"] = self.seq
        self.events.append(ev)
        if len(self.events) > self.max_events:
            del self.events[:len(self.events) - self.max_events]
        return self.seq

    def poll(self):
        """Lit les nouvelles lignes completes. Renvoie le nombre d'evenements ajoutes."""
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return 0
        skip_first = False
        if size < self.offset:           # fichier tronque : on repart
            self.offset = 0
            self.started = False
        if not self.started:
            self.started = True
            if size > self.initial_window:
                self.offset = size - self.initial_window
                skip_first = True
        if size == self.offset:
            return 0
        before = self.seq
        with open(self.path, "rb") as f:
            f.seek(self.offset)
            data = f.read(size - self.offset)
        end = data.rfind(b"\n")
        if end < 0:
            return 0                      # ligne incomplete : on attend la suite
        chunk = data[:end + 1]
        self.offset += len(chunk)
        lines = chunk.split(b"\n")
        if skip_first:
            lines = lines[1:]
        for raw in lines:
            if raw.strip():
                try:
                    self._handle(json.loads(raw.decode("utf-8", "replace")))
                except (ValueError, TypeError):
                    continue
        return self.seq - before

    def _handle(self, o):
        t = o.get("type")
        if t not in ("assistant", "user"):
            return
        msg = o.get("message")
        if not isinstance(msg, dict):
            return
        ts = o.get("timestamp", "")
        content = msg.get("content")
        if isinstance(content, str):
            if t == "user" and content.strip():
                if "<task-notification>" in content:
                    self._notif(content, ts)
                else:
                    self._emit({"kind": "user", "ts": ts, "text": clean(content, 300)})
            return
        if not isinstance(content, list):
            return
        for b in content:
            if not isinstance(b, dict):
                continue
            bt = b.get("type")
            if t == "assistant" and bt == "text" and b.get("text", "").strip():
                self._emit({"kind": "text", "ts": ts, "text": clean(b["text"], 600)})
            elif t == "assistant" and bt == "tool_use":
                name = b.get("name", "?")
                inp = b.get("input") or {}
                self.calls += 1
                fp = None
                if name in ("Edit", "Write", "NotebookEdit", "MultiEdit") and isinstance(inp, dict):
                    fp = inp.get("file_path") or inp.get("notebook_path")
                    if isinstance(fp, str):
                        fp = clean(fp, 260)
                        self.files[fp] = self.files.get(fp, 0) + 1
                    else:
                        fp = None
                ev = {"kind": "tool", "ts": ts, "name": clean(name, 60),
                      "summary": summarize_tool(name, inp), "file": fp, "dur": None, "error": False}
                if name == "Bash" and isinstance(inp, dict):
                    cmd = inp.get("command") if isinstance(inp.get("command"), str) else ""
                    if "git commit" in cmd:
                        ev["commit"] = extract_commit(cmd)
                    if TEST_RE.search(cmd):
                        self.tests += 1
                elif name in ("WebSearch", "WebFetch"):
                    self.searches += 1
                elif name == PLAN_TOOL:
                    self.plan = apply_plan(self.plan, inp)
                elif name == "Agent" and b.get("id") and isinstance(inp, dict):
                    self.agents[b["id"]] = {"id": b["id"], "name": clean(inp.get("description") or "Agent", 120),
                                            "status": "running", "started": ts, "ended": None,
                                            "duree_s": None, "result": "", "aid": None}
                s = self._emit(ev)
                if b.get("id"):
                    self.pending[b["id"]] = (s, _ts(ts), ev)
            elif t == "user" and bt == "tool_result":
                ref = self.pending.pop(b.get("tool_use_id"), None)
                self._agent_result(b, ts)
                dur = None
                if ref and ref[1] is not None and _ts(ts) is not None:
                    dur = max(0.0, round(_ts(ts) - ref[1], 1))
                err = bool(b.get("is_error"))
                if err:
                    self.errors += 1
                if ref:
                    ref[2]["dur"] = dur
                    ref[2]["error"] = err
                    self._emit({"kind": "result", "ts": ts, "ref": ref[0], "dur": dur, "error": err})
                if err:
                    c = b.get("content")
                    if isinstance(c, list):
                        c = " ".join(x.get("text", "") for x in c if isinstance(x, dict))
                    self._emit({"kind": "error", "ts": ts, "text": clean(c or "erreur", 300)})
            elif t == "user" and bt == "text" and b.get("text", "").strip():
                if "<task-notification>" in b["text"]:
                    self._notif(b["text"], ts)
                else:
                    self._emit({"kind": "user", "ts": ts, "text": clean(b["text"], 300)})

    @staticmethod
    def _result_text(b):
        c = b.get("content")
        if isinstance(c, list):
            c = " ".join(x.get("text", "") for x in c if isinstance(x, dict))
        return c if isinstance(c, str) else ""

    def _finish_agent(self, rec, ts, status, text):
        rec["status"] = status
        rec["ended"] = ts
        a, z = _ts(rec["started"]), _ts(ts)
        rec["duree_s"] = round(z - a) if a is not None and z is not None and z >= a else None
        rec["result"] = first_sentence(clean(text, 400))

    def _agent_result(self, b, ts):
        rec = self.agents.get(b.get("tool_use_id"))
        if not rec:
            return
        text = self._result_text(b)
        m = re.search(r"agentId:\s*(\w+)", text)
        if "Async agent launched" in text and m:
            rec["aid"] = m.group(1)
            self.agent_by_aid[m.group(1)] = rec
        else:
            self._finish_agent(rec, ts, "failed" if b.get("is_error") else "done", text)

    def _notif(self, text, ts):
        for body in NOTIF_RE.findall(text):
            def g(tag):
                mm = re.search(r"<%s>(.*?)</%s>" % (tag, tag), body, re.S)
                return mm.group(1).strip() if mm else ""
            rec = self.agent_by_aid.get(g("task-id"))
            if rec:
                st = "done" if g("status") == "completed" else "failed"
                self._finish_agent(rec, ts, st, re.sub(r'^Background agent "[^"]*"\s*', "", g("summary")))

    def since(self, n):
        return [e for e in self.events if e["seq"] > n]

    def stats(self):
        top = sorted(self.files.items(), key=lambda kv: -kv[1])[:12]
        return {"calls": self.calls, "errors": self.errors, "searches": self.searches,
                "tests": self.tests, "files_n": len(self.files),
                "files": [{"path": p, "n": c} for p, c in top]}

    def problems(self, now=None, window=600):
        """Erreurs recentes (par defaut moins de 10 minutes), les 3 dernieres."""
        now = now or time.time()
        out = []
        for e in reversed(self.events):
            if e["kind"] != "error":
                continue
            t = _ts(e.get("ts", ""))
            if t is not None and now - t <= window:
                out.append({"ts": e["ts"], "text": e["text"]})
            if len(out) >= 3:
                break
        return out

    def detected_agents(self):
        return [dict(a) for a in self.agents.values()]


def newest_jsonl(folder):
    if not folder:
        return None
    best, best_m = None, -1
    try:
        with os.scandir(folder) as it:
            for e in it:
                if e.is_file() and e.name.endswith(".jsonl"):
                    m = e.stat().st_mtime
                    if m > best_m:
                        best, best_m = e.path, m
    except OSError:
        return None
    return best


class LiveState:
    def __init__(self, folder, detector=None):
        self.folder = folder
        self.detector = detector     # appelee tant qu'aucun dossier de sessions n'est connu
        self.lock = threading.Lock()
        self.reader = None
        self.session = None
        self.epoch = 0

    def update(self, since, epoch):
        with self.lock:
            if not self.folder and self.detector:
                self.folder = self.detector()
            path = newest_jsonl(self.folder)
            if path is None:
                return {"session": None, "epoch": self.epoch, "events": [], "seq": 0,
                        "stats": {"calls": 0, "errors": 0, "searches": 0, "tests": 0, "files_n": 0, "files": []},
                        "plan": [], "timeline": [], "problems": [], "working": False, "age_s": None}
            if path != self.session:
                self.session = path
                self.reader = IncrementalReader(path)
                self.epoch += 1
            self.reader.poll()
            try:
                age = max(0.0, time.time() - os.path.getmtime(path))
            except OSError:
                age = None
            return {"session": os.path.basename(path), "epoch": self.epoch, "seq": self.reader.seq,
                    "stats": self.reader.stats(), "plan": self.reader.plan,
                    "timeline": build_timeline(self.reader.events[-600:]),
                    "problems": self.reader.problems(), "age_s": age,
                    "working": age is not None and age < 180}

    def detected(self):
        with self.lock:
            return self.reader.detected_agents() if self.reader else []


# ------------------------------------- detection automatique (aucun chemin code en dur)
def claude_projects_dir(env=None):
    """Dossier des sessions Claude Code de l'utilisateur courant : <profil>\\.claude\\projects."""
    env = os.environ if env is None else env
    home = env.get("USERPROFILE") or env.get("HOME") or os.path.expanduser("~")
    return os.path.join(home, ".claude", "projects")


def encode_project_name(path):
    """Nom de sous-dossier de session pour un dossier de travail (tout caractere non alphanumerique -> '-')."""
    return re.sub(r"[^A-Za-z0-9]", "-", path)


def detect_sessions(projects_dir):
    """Sous-dossier de `projects` le plus recemment modifie (date de son dernier .jsonl) ; None s'il n'y en a pas."""
    best, best_m = None, -1.0
    try:
        with os.scandir(projects_dir) as it:
            for d in it:
                if not d.is_dir():
                    continue
                m = -1.0
                try:
                    with os.scandir(d.path) as sub:
                        for f in sub:
                            if f.is_file() and f.name.endswith(".jsonl"):
                                m = max(m, f.stat().st_mtime)
                except OSError:
                    continue
                if m > best_m:
                    best, best_m = d.path, m
    except OSError:
        return None
    return best


def decode_project_name(name, start=None):
    """Retrouve le dossier de travail existant dont le nom encode vaut `name` (ex. 'C--Users-Moi-MonProjet').

    L'encodage perd les separateurs (espace, tiret, point) : on cherche sur le disque le chemin
    qui, une fois encode, redonne exactement `name`. `start` (tests) remplace la lettre de lecteur.
    """
    if start is None:
        m = re.match(r"^([A-Za-z])--(.+)$", name or "")
        if not m:
            return None
        start, rest = m.group(1).upper() + ":\\", m.group(2)
    else:
        rest = name

    def walk(base, rest):
        try:
            names = sorted((e.name for e in os.scandir(base) if e.is_dir()), key=len, reverse=True)
        except OSError:
            return None
        for n in names:
            enc = encode_project_name(n)
            if rest == enc:
                return os.path.join(base, n)
            if rest.startswith(enc + "-"):
                r = walk(os.path.join(base, n), rest[len(enc) + 1:])
                if r:
                    return r
        return None
    return walk(start, rest)


def is_drive_root(path):
    p = os.path.abspath(path)
    return os.path.dirname(p) == p


def root_from_session_file(sessions):
    """Dossier de travail lu dans le champ 'cwd' des premieres lignes de la derniere session, s'il existe."""
    path = newest_jsonl(sessions)
    if not path:
        return None
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for _, line in zip(range(60), f):
                m = re.search(r'"cwd"\s*:\s*("(?:[^"\\]|\\.)*")', line)
                if not m:
                    continue
                try:
                    cwd = json.loads(m.group(1))
                except ValueError:
                    continue
                if os.path.isdir(cwd) and not is_drive_root(cwd):
                    return os.path.abspath(cwd)
    except OSError:
        return None
    return None


def guess_root(sessions):
    """Racine de la vue Cerveau deduite des sessions : champ cwd, sinon nom du sous-dossier. None si inconnue."""
    if not sessions:
        return None
    r = root_from_session_file(sessions) or decode_project_name(os.path.basename(os.path.normpath(sessions)))
    return r if r and not is_drive_root(r) else None


def load_config(path):
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def save_config(path, data):
    """Ecrit config.json ; False si l'emplacement n'est pas inscriptible."""
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except OSError:
        return False


def resolve_settings(sessions_arg, root_arg, config, projects_dir):
    """Priorite : option en ligne de commande > config.json > detection automatique. -> (sessions, root ou None)."""
    sessions = sessions_arg or config.get("sessions") or detect_sessions(projects_dir)
    root = root_arg or config.get("root")
    if root and not os.path.isdir(root):
        root = None
    if not root:
        root = guess_root(sessions)
    return sessions, root


# ------------------------------------------------------------ carte cerveau
def is_ignored_name(name):
    return name.lower() in IGNORED


def safe_resolve(root, rel):
    """Chemin absolu sous root, ou None (../, absolu, dossier ignore, hors racine)."""
    if not isinstance(rel, str) or "\x00" in rel:
        return None
    rel = rel.replace("\\", "/")
    if rel.startswith("/") or re.match(r"^[A-Za-z]:", rel):
        return None
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." or is_ignored_name(p) for p in parts):
        return None
    root_real = os.path.realpath(root)
    full = os.path.realpath(os.path.join(root_real, *parts))
    try:
        if os.path.commonpath([root_real, full]) != root_real:
            return None
    except ValueError:
        return None
    rp = os.path.relpath(full, root_real).replace("\\", "/")
    if rp != "." and any(is_ignored_name(p) for p in rp.split("/")):
        return None
    return full


# ---------------------------------------------- classement : generique, ou profil local optionnel
PALETTE = ["#60a5fa", "#22d3ee", "#4ade80", "#fbbf24", "#a78bfa", "#f472b6", "#fb923c", "#f87171"]
OTHER_COLOR = "#94a3b8"
MAX_ZONES = 8
PROFILE = {"active": False, "folder": None, "zones": {}, "order": [], "colors": {}, "dir_zone": {},
           "dir_prefix": {}, "file_zone": {}, "friendly": {}, "desc": {}, "desc_file": None}

# Descriptions generiques de fichiers courants (cle = nom en minuscules)
GENERIC_DESC = {
    "readme.md": "Le mode d'emploi du projet : à lire en premier.",
    "license": "La licence : ce que chacun a le droit de faire avec ce projet.",
    "licence": "La licence : ce que chacun a le droit de faire avec ce projet.",
    "requirements.txt": "La liste des bibliothèques Python à installer pour que le projet fonctionne.",
    "package.json": "La fiche d'un projet JavaScript : son nom, ses dépendances et ses commandes.",
    "pyproject.toml": "La fiche d'un projet Python : son nom, ses dépendances et ses outils.",
    ".gitignore": "La liste des fichiers que Git doit ignorer.",
    "agents.json": "Le registre des agents : qui fait quoi, et à quelle heure.",
    "claude.md": "La consigne de l'agent : sa mission et ses limites.",
    "changelog.md": "L'historique des changements, version par version.",
    "contributing.md": "Comment participer au projet.",
    "security.md": "Comment signaler un problème de sécurité.",
    "config.json": "Un fichier de réglages.",
    "__init__.py": "Marque ce dossier comme un paquet Python.",
}


def readable_name(name):
    """Nom lisible d'un dossier : underscores et tirets remplaces par des espaces, majuscule initiale."""
    t = re.sub(r"[_\-]+", " ", name or "").strip()
    return (t[:1].upper() + t[1:]) if t else (name or "")


def reset_profile():
    IGNORED.clear()
    IGNORED.update(BASE_IGNORED)
    PROFILE.update(active=False, folder=None, zones={}, order=[], colors={}, dir_zone={}, dir_prefix={},
                   file_zone={}, friendly={}, desc={}, desc_file=None)
    _DCACHE.update(m=None, d={})


def load_profile(folder):
    """Charge un profil local (profil.json + descriptions.json facultatif). Renvoie True si charge."""
    reset_profile()
    if not folder:
        return False
    try:
        with open(os.path.join(folder, "profil.json"), "r", encoding="utf-8-sig") as f:
            d = json.load(f)
    except (OSError, ValueError):
        return False
    if not isinstance(d, dict):
        return False
    low = lambda m: {str(k).lower(): v for k, v in (m or {}).items()}
    zones = d.get("zones") if isinstance(d.get("zones"), dict) else {}
    IGNORED.update(str(x).lower() for x in d.get("ignored_extra") or [])
    PROFILE.update(active=bool(zones), folder=folder, zones=zones,
                   order=[z for z in d.get("zone_order") or list(zones) if z in zones],
                   colors=d.get("colors") or {}, dir_zone=low(d.get("dir_zone")),
                   dir_prefix=low(d.get("dir_zone_prefix")), file_zone=low(d.get("file_zone")),
                   friendly=low(d.get("friendly")), desc=low(d.get("desc")),
                   desc_file=os.path.join(folder, "descriptions.json"))
    return True


_DCACHE = {"m": None, "d": {}}


def load_descriptions():
    """descriptions.json du profil (cle = chemin relatif, valeurs quoi / pourquoi), relu si le fichier change."""
    path = PROFILE["desc_file"]
    if not path:
        return {}
    try:
        m = os.path.getmtime(path)
    except OSError:
        return {}
    if _DCACHE["m"] != m:
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                raw = json.load(f)
            _DCACHE["d"] = {str(k).replace("\\", "/").lower(): v for k, v in raw.items() if isinstance(v, dict)}
        except (OSError, ValueError):
            _DCACHE["d"] = {}
        _DCACHE["m"] = m
    return _DCACHE["d"]


def describe(rel, name):
    """(quoi, pourquoi) : profil d'abord (descriptions.json, puis table par nom), puis descriptions generiques."""
    d = load_descriptions().get(rel.replace("\\", "/").lower())
    if d:
        return mask(str(d.get("quoi", ""))), mask(str(d.get("pourquoi", "")))
    t = PROFILE["desc"].get(name.lower())
    if t:
        return t, ""
    return GENERIC_DESC.get(name.lower(), ""), ""


def zone_of(first_part, is_dir):
    low = first_part.lower()
    if PROFILE["active"]:
        if is_dir:
            if low in PROFILE["dir_zone"]:
                return PROFILE["dir_zone"][low]
            for pre, z in PROFILE["dir_prefix"].items():
                if low.startswith(pre):
                    return z
            return "autres"
        return PROFILE["file_zone"].get(low, "autres")
    return ("z:" + low) if is_dir else "autres"


def finish_zones(nodes):
    """Remappe les zones generiques (8 plus gros dossiers de premier niveau + Autres) ; renvoie la liste des zones."""
    counts = {}
    for n in nodes:
        if n["id"]:
            counts[n["zone"]] = counts.get(n["zone"], 0) + 1
    if PROFILE["active"]:
        out = []
        for i, z in enumerate(PROFILE["order"]):
            if counts.get(z):
                out.append({"id": z, "label": PROFILE["zones"][z], "count": counts[z],
                            "color": PROFILE["colors"].get(z) or PALETTE[i % len(PALETTE)]})
        return out
    labels = {n["zone"]: readable_name(n["name"]) for n in nodes if n["parent"] == "" and n["type"] == "dir" and n["id"]}
    ranked = sorted((z for z in counts if z != "autres"), key=lambda z: (-counts[z], labels.get(z, z)))
    keep = ranked[:MAX_ZONES]
    for n in nodes:
        if n["id"] and n["zone"] != "autres" and n["zone"] not in keep:
            n["zone"] = "autres"
    counts = {}
    for n in nodes:
        if n["id"]:
            counts[n["zone"]] = counts.get(n["zone"], 0) + 1
    out = [{"id": z, "label": labels.get(z, z), "count": counts[z], "color": PALETTE[i % len(PALETTE)]}
           for i, z in enumerate(keep) if counts.get(z)]
    if counts.get("autres"):
        out.append({"id": "autres", "label": "Autres", "count": counts["autres"], "color": OTHER_COLOR})
    return out


def is_profile_dir(path):
    try:
        return any(os.path.exists(os.path.join(path, m)) for m in PROFILE_MARKERS)
    except OSError:
        return False


def build_tree(root):
    root_real = os.path.realpath(root)
    nodes = [{"id": "", "name": os.path.basename(root_real) or root_real, "label": os.path.basename(root_real) or root_real, "type": "dir",
              "parent": None, "size": 0, "mtime": 0, "zone": "root", "desc": ""}]
    stack = [(root_real, "", 0)]
    truncated = False
    while stack:
        d, rid, depth = stack.pop()
        try:
            entries = sorted(os.scandir(d),
                             key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower()))
        except OSError:
            continue
        for e in entries:
            if is_ignored_name(e.name) or e.is_symlink():
                continue
            cid = (rid + "/" + e.name) if rid else e.name
            first = cid.split("/")[0]
            try:
                if e.is_dir(follow_symlinks=False):
                    if depth + 1 > MAX_DEPTH or is_profile_dir(e.path):
                        continue
                    st = e.stat()
                    nodes.append({"id": cid, "name": e.name, "label": PROFILE["friendly"].get(e.name.lower(), e.name) if PROFILE["active"] else readable_name(e.name),
                                  "type": "dir", "parent": rid, "size": 0, "mtime": st.st_mtime,
                                  "zone": zone_of(first, True), "desc": describe(cid, e.name)[0],
                                  "why": describe(cid, e.name)[1]})
                    stack.append((e.path, cid, depth + 1))
                else:
                    ext = os.path.splitext(e.name)[1].lower()
                    if ext not in TREE_EXT and not (not ext and e.name.lower() in TREE_NAMES):
                        continue
                    st = e.stat()
                    nodes.append({"id": cid, "name": e.name, "label": e.name, "type": ext[1:] or "txt", "parent": rid,
                                  "size": st.st_size, "mtime": st.st_mtime,
                                  "zone": zone_of(first, depth > 0),
                                  "desc": describe(cid, e.name)[0], "why": describe(cid, e.name)[1]})
            except OSError:
                continue
            if len(nodes) >= MAX_NODES:
                truncated = True
                stack.clear()
                break
    # Retire les dossiers sans aucun fichier retenu en dessous
    keep = set()
    by_id = {n["id"]: n for n in nodes}
    for n in nodes:
        if n["type"] != "dir":
            p = n["parent"]
            while p is not None and p not in keep:
                keep.add(p)
                p = by_id[p]["parent"]
    nodes = [n for n in nodes if n["type"] != "dir" or n["id"] == "" or n["id"] in keep]
    zones = finish_zones(nodes)
    return {"nodes": nodes, "truncated": truncated, "zones": zones}


def outline_of(text, ext):
    """Titres d'un document (schema de flux) : titres Markdown, definitions Python, cles JSON."""
    out = []
    if ext == ".md":
        for ln in text.splitlines():
            m = re.match(r"^(#{1,3})\s+(.+?)\s*#*$", ln)
            if m:
                out.append(clean(m.group(2), 60))
    elif ext == ".py":
        for ln in text.splitlines():
            m = re.match(r"^(?:def|class)\s+(\w+)", ln)
            if m:
                out.append(m.group(1))
    elif ext == ".json":
        try:
            data = json.loads(text)
        except ValueError:
            return []
        if isinstance(data, dict):
            for k, v in data.items():
                suffix = " (%d)" % len(v) if isinstance(v, (list, dict)) else ""
                out.append(clean(str(k), 40) + suffix)
        elif isinstance(data, list):
            out.append("liste de %d \u00e9l\u00e9ments" % len(data))
    return [mask(o) for o in out[:12]]


def md_levels(text):
    """Niveau (1 a 3) de chaque titre Markdown, dans l'ordre (meme ordre que outline_of)."""
    return [len(m.group(1)) for m in (re.match(r"^(#{1,3})\s+(.+?)\s*#*$", ln) for ln in text.splitlines()) if m][:12]


def summary_of(text, ext):
    """Premiere ligne utile du fichier (ou premiere ligne du docstring pour un .py)."""
    if ext == ".py":
        m = re.match(r'\s*(?:#[^\n]*\n\s*)*(?:"""|\'\'\')(.+?)(?:"""|\'\'\'|\n)', text, re.S)
        if m and m.group(1).strip():
            return clean(m.group(1).strip().splitlines()[0], 160)
    if ext == ".json":
        return ""
    for ln in text.splitlines():
        t = ln.strip().lstrip("#>*-| ").strip()
        if len(t) >= 8 and not t.startswith(("```", "---", "===")):
            return clean(t, 160)
    return ""


def read_preview(root, rel):
    full = safe_resolve(root, rel)
    if full is None or not os.path.isfile(full):
        return None
    st = os.stat(full)
    with open(full, "rb") as f:
        raw = f.read(PREVIEW_BYTES)
    if b"\x00" in raw[:4096]:
        return {"path": rel, "size": st.st_size, "mtime": st.st_mtime, "binary": True, "text": ""}
    text = raw.decode("utf-8", "replace")
    lines = text.splitlines()
    ext = os.path.splitext(full)[1].lower()
    name = os.path.basename(full).lower()
    quoi, pourquoi = describe(rel, name)
    summary = mask(summary_of(text, ext))
    return {"path": rel, "quoi": quoi or summary or "Pas encore de description", "pourquoi": pourquoi,
            "described": bool(quoi), "size": st.st_size, "mtime": st.st_mtime, "binary": False,
            "truncated": len(lines) > PREVIEW_LINES or st.st_size > PREVIEW_BYTES,
            "lines": len(lines), "desc": quoi, "summary": summary,
            "outline": outline_of(text, ext), "levels": md_levels(text) if ext == ".md" else [],
            "text": mask("\n".join(lines[:PREVIEW_LINES]))}


def _readable(root, rel):
    """Chemin d'un fichier lisible (dans la racine, hors dossiers ignores, hors fichiers de secrets) ou None."""
    full = safe_resolve(root, rel)
    if full is None or not os.path.isfile(full):
        return None
    base = os.path.basename(full).lower()
    if base.startswith(".env") or os.path.splitext(base)[1] in REFUSED_EXT:
        return None
    return full


def read_code(root, rel):
    """Fichier texte entier (moins de 400 Ko), secrets masques. None = interdit ou introuvable."""
    full = _readable(root, rel)
    if full is None:
        return None
    size = os.path.getsize(full)
    if size > CODE_MAX:
        return {"ok": False, "path": rel, "size": size,
                "reason": "Ce fichier est trop gros pour s'afficher en entier (%d Ko ; limite %d Ko)." % (size // 1024, CODE_MAX // 1024)}
    with open(full, "rb") as f:
        raw = f.read()
    if b"\x00" in raw[:4096]:
        return {"ok": False, "path": rel, "size": size, "reason": "Ce fichier n'est pas du texte : il ne peut pas s'afficher."}
    text = raw.decode("utf-8", "replace")
    return {"ok": True, "path": rel, "size": size, "lines": text.count("\n") + 1, "text": mask(text)}


def tech_info(root, rel):
    """Fiche technique : fonctions et classes avec leur role (module ast pour .py), imports, titres (.md)."""
    full = _readable(root, rel)
    if full is None:
        return None
    size = os.path.getsize(full)
    if size > CODE_MAX:
        return {"ok": False, "reason": "Fichier trop gros pour l'analyse (limite %d Ko)." % (CODE_MAX // 1024)}
    with open(full, "rb") as f:
        text = f.read().decode("utf-8", "replace")
    ext = os.path.splitext(full)[1].lower()
    out = {"ok": True, "kind": ext[1:], "size": size, "lines": text.count("\n") + 1, "items": [], "imports": [], "error": ""}
    if ext == ".py":
        try:
            tree = ast.parse(text)
        except SyntaxError as e:
            out["error"] = "Le programme n'a pas pu etre analyse : " + clean(str(e), 80)
            return out
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods.update(a.name.split(".")[0] for a in n.names)
            elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
                mods.add(n.module.split(".")[0])
        out["imports"] = sorted(mods)[:40]

        def role(n):
            d = ast.get_docstring(n)
            return mask(clean(d.strip().splitlines()[0], 140)) if d and d.strip() else "Rôle non documenté (nom : " + n.name.replace("_", " ") + ")"

        def item(n, prefix=""):
            kind = "classe" if isinstance(n, ast.ClassDef) else ("methode" if prefix else "fonction")
            return {"name": prefix + n.name, "kind": kind, "line": n.lineno, "end": getattr(n, "end_lineno", n.lineno), "role": role(n)}
        for n in tree.body:
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                out["items"].append(item(n))
                if isinstance(n, ast.ClassDef):
                    for m in n.body:
                        if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            out["items"].append(item(m, n.name + "."))
        out["items"] = out["items"][:80]
    elif ext == ".md":
        for i, ln in enumerate(text.splitlines(), 1):
            m = re.match(r"^(#{1,3})\s+(.+?)\s*#*$", ln)
            if m:
                out["items"].append({"name": mask(clean(m.group(2), 80)), "kind": "titre", "line": i, "level": len(m.group(1)), "role": ""})
        out["items"] = out["items"][:80]
    elif ext == ".json":
        for k in outline_of(text, ext):
            out["items"].append({"name": k, "kind": "rubrique", "line": 0, "role": ""})
    return out


# ------------------------------------------------------------------ serveur
def make_handler(live, ctx, index_path):
    """ctx = {'root': dossier ou None, 'config_path': chemin de config.json ou None}."""
    class Handler(BaseHTTPRequestHandler):
        server_version = "Cockpit/1.1"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json; charset=utf-8"):
            if not isinstance(body, bytes):
                body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy",
                             "default-src 'self' 'unsafe-inline'; connect-src 'self'")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _host_ok(self):
            h = (self.headers.get("Host") or "").split(":")[0].lower()
            return h in ("127.0.0.1", "localhost")

        def do_GET(self):
            if not self._host_ok():
                return self._send(403, {"error": "hote refuse"})
            u = urlparse(self.path)
            q = parse_qs(u.query)
            root = ctx["root"]
            try:
                if u.path in ("/", "/index.html"):
                    with open(index_path, "rb") as f:
                        return self._send(200, f.read(), "text/html; charset=utf-8")
                if u.path == "/api/config":
                    return self._send(200, {"sessions": live.folder, "root": root,
                                            "name": os.path.basename(root) if root else "",
                                            "needs_root": root is None})
                if u.path == "/api/live":
                    since = int(q.get("since", ["0"])[0])
                    epoch = int(q.get("epoch", ["0"])[0])
                    return self._send(200, live.update(since, epoch))
                if root is None and u.path in ("/api/code", "/api/tech", "/api/agents", "/api/tree", "/api/file"):
                    return self._send(409, {"error": "dossier a suivre non choisi", "needs_root": True})
                if u.path in ("/api/code", "/api/tech"):
                    fn = read_code if u.path == "/api/code" else tech_info
                    r = fn(root, q.get("path", [""])[0])
                    if r is None:
                        return self._send(404, {"error": "introuvable ou interdit"})
                    return self._send(200, r)
                if u.path == "/api/agents":
                    reg = load_agents_file(os.path.join(root, "AGENTS.json"))
                    cards = merge_agents(reg["agents"], live.detected(), datetime.now())
                    return self._send(200, {"found": reg["found"], "error": reg["error"],
                                            "path": reg["path"], "cards": cards})
                if u.path == "/api/tree":
                    return self._send(200, build_tree(root))
                if u.path == "/api/file":
                    r = read_preview(root, q.get("path", [""])[0])
                    if r is None:
                        return self._send(404, {"error": "introuvable ou interdit"})
                    return self._send(200, r)
            except (ValueError, OSError) as e:
                return self._send(400, {"error": clean(str(e), 120)})
            return self._send(404, {"error": "inconnu"})

        do_HEAD = do_GET

        def do_POST(self):
            """Seule ecriture du programme : memoriser le dossier choisi dans config.json."""
            if not self._host_ok():
                return self._send(403, {"error": "hote refuse"})
            if urlparse(self.path).path != "/api/setup":
                return self._send(404, {"error": "inconnu"})
            origin = self.headers.get("Origin") or ""
            host = (self.headers.get("Host") or "").lower()
            if origin.lower() != "http://" + host:       # refuse les requetes venues d'une autre page
                return self._send(403, {"error": "origine refusee"})
            if not (self.headers.get("Content-Type") or "").lower().startswith("application/json"):
                return self._send(400, {"error": "format attendu : JSON"})
            try:
                n = int(self.headers.get("Content-Length") or "0")
                if not 0 < n <= 4096:
                    raise ValueError
                data = json.loads(self.rfile.read(n).decode("utf-8"))
                folder = data.get("root") if isinstance(data, dict) else None
            except (ValueError, UnicodeDecodeError):
                return self._send(400, {"error": "demande illisible"})
            if not isinstance(folder, str) or not folder.strip():
                return self._send(400, {"error": "Indiquez un dossier."})
            folder = os.path.abspath(os.path.expandvars(folder.strip().strip('"')))
            if not os.path.isdir(folder):
                return self._send(400, {"error": "Ce dossier n'existe pas : " + clean(folder, 120)})
            if is_drive_root(folder):
                return self._send(400, {"error": "Choisissez un dossier de travail, pas un disque entier."})
            ctx["root"] = folder
            saved = bool(ctx.get("config_path")) and save_config(ctx["config_path"], {"root": folder})
            return self._send(200, {"ok": True, "root": folder, "saved": saved})

    return Handler


def make_server(port, sessions, root, config_path=None, detector=None):
    live = LiveState(sessions, detector)
    ctx = {"root": root, "config_path": config_path}
    handler = make_handler(live, ctx, os.path.join(RES_DIR, "index.html"))
    srv = ThreadingHTTPServer((HOST, port), handler)
    srv.ctx = ctx
    return srv


def open_browser(url):
    try:
        if sys.platform == "win32":
            os.startfile(url)  # navigateur par defaut
        else:
            import webbrowser
            webbrowser.open(url)
    except Exception as e:
        print("Ouverture du navigateur impossible :", e)


def cockpit_answers(port):
    """Vrai si un Cockpit repond deja sur ce port (on rouvre alors simplement la page)."""
    import http.client
    try:
        c = http.client.HTTPConnection(HOST, port, timeout=1)
        c.request("GET", "/api/config")
        r = c.getresponse()
        ok = r.status == 200 and b"needs_root" in r.read(2000)
        c.close()
        return ok
    except (OSError, ValueError):
        return False


def main(argv=None):
    ap = argparse.ArgumentParser(description="Cockpit : suivi local d'un agent Claude Code")
    ap.add_argument("--port", type=int, default=None)
    ap.add_argument("--sessions", default=None, help="dossier des sessions JSONL (defaut : detecte)")
    ap.add_argument("--root", default=None, help="dossier racine de la vue Cerveau (defaut : deduit ou demande)")
    ap.add_argument("--config", default=CONFIG_PATH, help="fichier config.json (defaut : a cote du programme)")
    ap.add_argument("--profil", default=None, help="dossier d'un profil local (profil.json) ; defaut : profil_prive a cote du programme")
    ap.add_argument("--no-open", action="store_true", help="n'ouvre pas le navigateur")
    a = ap.parse_args(argv)
    prof = a.profil or next((d for d in (os.path.join(APP_DIR, "profil_prive"), os.path.join(HERE, "profil_prive"))
                             if os.path.isfile(os.path.join(d, "profil.json"))), None)
    if load_profile(prof):
        print("Profil local charge :", os.path.basename(os.path.normpath(prof)))
    cfg = load_config(a.config)
    projects = claude_projects_dir()
    sessions, root = resolve_settings(a.sessions, a.root, cfg, projects)
    detector = (lambda: detect_sessions(projects)) if not a.sessions and not cfg.get("sessions") else None
    ports = [a.port] if a.port else range(DEFAULT_PORT, DEFAULT_PORT + 10)
    srv = None
    for p in ports:
        try:
            srv = make_server(p, sessions, root, a.config, detector)
            break
        except OSError:
            if p == DEFAULT_PORT and cockpit_answers(p):
                print("Cockpit tourne deja sur http://%s:%d/ : page rouverte." % (HOST, p))
                if not a.no_open:
                    open_browser("http://%s:%d/" % (HOST, p))
                return
    if srv is None:
        print("Impossible de demarrer : aucun port libre.")
        sys.exit(1)
    url = "http://%s:%d/" % (HOST, srv.server_address[1])
    print("Cockpit tourne : fermez cette fenetre pour arreter.")
    print("Adresse :", url, "(Ctrl+C pour arreter)")
    print("Dossier suivi :", root or "(a choisir dans la page)")
    print("Sessions Claude Code :", sessions or "(aucune trouvee pour l'instant)", flush=True)
    if not a.no_open:
        open_browser(url)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
