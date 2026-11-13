"""Tests de Cockpit. Lancer : uv run python -I -m unittest -v test_cockpit  (depuis ce dossier)."""
import http.client
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import server  # noqa: E402


def line(**o):
    return json.dumps(o) + "\n"


def fake_session(path):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(line(type="queue-operation"))
        f.write(line(type="user", timestamp="2026-11-08T10:00:00.000Z",
                     message={"role": "user", "content": "Bonjour"}))
        f.write(line(type="assistant", timestamp="2026-11-08T10:00:01.000Z", message={"content": [
            {"type": "text", "text": "Je lis le fichier."},
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": "D:\\x\\a.md"}},
            {"type": "tool_use", "id": "t2", "name": "Edit", "input": {"file_path": "D:\\x\\b.py"}}]}))
        f.write(line(type="user", timestamp="2026-11-08T10:00:03.500Z", message={"content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "ok"},
            {"type": "tool_result", "tool_use_id": "t2", "content": "boom", "is_error": True}]}))


class TestReader(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.p = os.path.join(self.d, "s.jsonl")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_incremental(self):
        fake_session(self.p)
        r = server.IncrementalReader(self.p)
        self.assertGreater(r.poll(), 0)
        kinds = [e["kind"] for e in r.events]
        self.assertEqual(kinds.count("tool"), 2)
        self.assertIn("error", kinds)
        self.assertEqual(r.calls, 2)
        self.assertEqual(r.errors, 1)
        tool = [e for e in r.events if e["kind"] == "tool"][0]
        res = [e for e in r.events if e["kind"] == "result" and e["ref"] == tool["seq"]][0]
        self.assertEqual(res["dur"], 2.5)
        self.assertEqual(list(r.files), ["D:\\x\\b.py"])
        # rien de nouveau : aucune relecture
        off = r.offset
        self.assertEqual(r.poll(), 0)
        self.assertEqual(r.offset, off)
        # ajout d'une ligne complete puis d'une ligne partielle
        with open(self.p, "a", encoding="utf-8", newline="\n") as f:
            f.write(line(type="assistant", timestamp="2026-11-08T10:01:00.000Z",
                         message={"content": [{"type": "text", "text": "Suite"}]}))
            half = line(type="assistant", timestamp="2026-11-08T10:01:01.000Z",
                        message={"content": [{"type": "text", "text": "Fin"}]})
            f.write(half[:20])
        self.assertEqual(r.poll(), 1)
        self.assertEqual(r.events[-1]["text"], "Suite")
        with open(self.p, "a", encoding="utf-8", newline="\n") as f:
            f.write(half[20:])
        self.assertEqual(r.poll(), 1)
        self.assertEqual(r.events[-1]["text"], "Fin")
        self.assertEqual([e["seq"] for e in r.since(r.seq - 1)], [r.seq])

    def test_window_on_big_file_and_garbage(self):
        with open(self.p, "w", encoding="utf-8", newline="\n") as f:
            for i in range(200):
                f.write(line(type="assistant", timestamp="2026-11-08T10:00:00Z",
                             message={"content": [{"type": "text", "text": "m%d" % i}]}))
            f.write("{pas du json\n")
        r = server.IncrementalReader(self.p, initial_window=2000)
        r.poll()
        self.assertLess(len(r.events), 200)
        self.assertEqual(r.events[-1]["text"], "m199")

    def test_newest_file(self):
        a, b = os.path.join(self.d, "a.jsonl"), os.path.join(self.d, "b.jsonl")
        open(a, "w").close()
        open(b, "w").close()
        os.utime(a, (1000, 1000))
        os.utime(b, (2000, 2000))
        self.assertEqual(server.newest_jsonl(self.d), b)


class TestMask(unittest.TestCase):
    def test_secrets(self):
        samples = ["gho_" + "A" * 36, "ghp_" + "b1" * 18, "sk-ant-api03-" + "x" * 30,
                   "AIza" + "Sy" + "A" * 33, "Bearer abcdef1234567890XYZ",
                   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abcdefghijklmnop",
                   "AKIA" + "ABCDEFGHIJKLMNOP", "xoxb-1234567890-abcdef"]
        for s in samples:
            out = server.mask("avant " + s + " apres")
            self.assertNotIn(s, out, s)
            self.assertIn("[MASQUE]", out)
            self.assertTrue(out.startswith("avant ") and out.endswith(" apres"))
        out = server.mask('password = "hunter2hunter2"')
        self.assertNotIn("hunter2", out)
        out = server.mask('{"api_key": "abcdef123456"}')
        self.assertNotIn("abcdef123456", out)
        pem = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkq\n-----END PRIVATE KEY-----"
        self.assertNotIn("MIIEvQ", server.mask(pem))
        self.assertEqual(server.mask("texte normal sans secret"), "texte normal sans secret")

    def test_masked_in_events(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "s.jsonl")
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(line(type="assistant", timestamp="2026-11-08T10:00:00Z", message={"content": [
                    {"type": "text", "text": "cle gho_" + "Z" * 30},
                    {"type": "tool_use", "id": "q", "name": "Bash",
                     "input": {"command": "curl -H 'Authorization: Bearer abcdefgh12345678' x"}}]}))
            r = server.IncrementalReader(p)
            r.poll()
            blob = json.dumps(r.events)
            self.assertNotIn("gho_ZZZ", blob)
            self.assertNotIn("abcdefgh12345678", blob)
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_mojibake(self):
        self.assertEqual(server.fix_mojibake("r\u00c3\u00a9v\u00c3\u00a8le"), "r\u00e9v\u00e8le")
        self.assertEqual(server.fix_mojibake("normal \u00e9"), "normal \u00e9")


class TestPaths(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.root = os.path.join(self.d, "root")
        os.makedirs(os.path.join(self.root, "_secrets"))
        os.makedirs(os.path.join(self.root, "sub"))
        os.makedirs(os.path.join(self.root, "tmp"))
        for rel, txt in [("a.md", "# a\n" + "l\n" * 100), ("sub/b.py", "x=1"),
                         ("_secrets/k.json", "{}"), ("tmp/t.md", "t"), ("c.dat", "no")]:
            with open(os.path.join(self.root, rel), "w") as f:
                f.write(txt)
        with open(os.path.join(self.d, "outside.md"), "w") as f:
            f.write("dehors")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_resolve(self):
        r = self.root
        self.assertIsNotNone(server.safe_resolve(r, "a.md"))
        self.assertIsNotNone(server.safe_resolve(r, "sub/b.py"))
        for bad in ["../outside.md", "sub/../../outside.md", "..\\outside.md", "/etc/passwd",
                    "C:\\Windows\\win.ini", "_secrets/k.json", "tmp/t.md", "a.md\x00.png"]:
            self.assertIsNone(server.safe_resolve(r, bad), bad)

    def test_preview_and_tree(self):
        p = server.read_preview(self.root, "a.md")
        self.assertEqual(len(p["text"].splitlines()), 60)
        self.assertTrue(p["truncated"])
        self.assertIsNone(server.read_preview(self.root, "../outside.md"))
        ids = {n["id"] for n in server.build_tree(self.root)["nodes"]}
        self.assertIn("a.md", ids)
        self.assertIn("sub/b.py", ids)
        self.assertNotIn("c.txt", ids)
        self.assertFalse(any("_secrets" in i or "tmp" in i for i in ids))


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class TestServer(unittest.TestCase):
    """(c) ecoute sur 127.0.0.1 uniquement, refus de ../ ; (d) demarrage reel + curl."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.root = os.path.join(cls.d, "root")
        cls.sess = os.path.join(cls.d, "sess")
        os.makedirs(os.path.join(cls.root, "sub"))
        os.makedirs(cls.sess)
        with open(os.path.join(cls.root, "a.md"), "w") as f:
            f.write("hello gho_" + "Q" * 30)
        with open(os.path.join(cls.d, "outside.md"), "w") as f:
            f.write("dehors")
        fake_session(os.path.join(cls.sess, "s.jsonl"))
        cls.port = free_port()
        cls.proc = subprocess.Popen(
            [sys.executable, "-I", os.path.join(HERE, "server.py"), "--port", str(cls.port),
             "--sessions", cls.sess, "--root", cls.root, "--no-open"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", cls.port), 0.2).close()
                break
            except OSError:
                time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(5)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
        shutil.rmtree(cls.d, ignore_errors=True)

    def get(self, path, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.putrequest("GET", path, skip_host=bool(host))
        if host:
            c.putheader("Host", host)
        c.endheaders()
        r = c.getresponse()
        body = r.read()
        c.close()
        return r.status, body

    def test_bind_loopback_only(self):
        self.assertEqual(server.HOST, "127.0.0.1")
        srv = server.make_server(0, self.sess, self.root)
        try:
            self.assertEqual(srv.socket.getsockname()[0], "127.0.0.1")
        finally:
            srv.server_close()
        # une connexion via une autre adresse locale non-loopback doit echouer
        try:
            lan = socket.gethostbyname(socket.gethostname())
        except OSError:
            lan = None
        if lan and not lan.startswith("127."):
            with self.assertRaises(OSError):
                socket.create_connection((lan, self.port), 1)

    def test_traversal_refused(self):
        for p in ["/api/file?path=../outside.md", "/api/file?path=..%2Foutside.md",
                  "/api/file?path=..%5Coutside.md", "/api/file?path=%2Fetc%2Fpasswd",
                  "/api/file?path=C%3A%5CWindows%5Cwin.ini"]:
            st, body = self.get(p)
            self.assertEqual(st, 404, p)
            self.assertNotIn(b"dehors", body)
        st, _ = self.get("/../outside.md")
        self.assertEqual(st, 404)

    def test_host_header_rebinding(self):
        st, _ = self.get("/api/tree", host="evil.example.com")
        self.assertEqual(st, 403)

    def test_endpoints(self):
        st, body = self.get("/")
        self.assertEqual(st, 200)
        self.assertIn(b"Cockpit", body)
        st, body = self.get("/api/file?path=a.md")
        j = json.loads(body)
        self.assertEqual(st, 200)
        self.assertNotIn("QQQQ", j["text"])
        self.assertIn("[MASQUE]", j["text"])
        st, body = self.get("/api/tree")
        self.assertIn("a.md", [n["id"] for n in json.loads(body)["nodes"]])
        st, body = self.get("/api/live?since=0&epoch=0")
        j = json.loads(body)
        self.assertEqual(j["stats"]["calls"], 2)
        self.assertEqual(j["stats"]["errors"], 1)

    def test_curl(self):
        curl = shutil.which("curl")
        if not curl:
            self.skipTest("curl absent")
        base = "http://127.0.0.1:%d" % self.port
        out = subprocess.run([curl, "-s", base + "/api/live?since=0&epoch=0"],
                             capture_output=True, text=True, timeout=10).stdout
        self.assertEqual(json.loads(out)["stats"]["calls"], 2)
        code = subprocess.run([curl, "-s", "-o", os.devnull, "-w", "%{http_code}", "--path-as-is",
                               base + "/api/file?path=../outside.md"],
                              capture_output=True, text=True, timeout=10).stdout
        self.assertEqual(code, "404")
        code = subprocess.run([curl, "-s", "-o", os.devnull, "-w", "%{http_code}", "--path-as-is",
                               base + "/../../outside.md"],
                              capture_output=True, text=True, timeout=10).stdout
        self.assertEqual(code, "404")


# ------------------------------------------------------------ refonte : nouveaux tests
def ev(**k):
    d = {"kind": "tool", "ts": "2026-11-08T10:00:00.000Z", "name": "", "summary": "", "file": None, "dur": None,
         "error": False}
    d.update(k)
    return d


class TestArret(unittest.TestCase):
    """Arret propre : bouton Quitter (origine verifiee) et arret automatique sans signe de vie."""

    def lancer(self, *extra):
        d = tempfile.mkdtemp(); self.addCleanup(shutil.rmtree, d, True)
        os.makedirs(os.path.join(d, "s"))
        port = free_port()
        proc = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, "server.py"), "--port", str(port),
                                 "--sessions", os.path.join(d, "s"), "--root", d, "--no-open", *extra],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(proc.kill)
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close(); break
            except OSError:
                time.sleep(0.1)
        return proc, port

    def post(self, port, origin):
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("POST", "/api/quit", body=b"", headers={"Origin": origin} if origin else {})
        r = c.getresponse(); r.read(); c.close()
        return r.status

    def test_quit_refuse_depuis_autre_page_puis_accepte(self):
        proc, port = self.lancer()
        self.assertEqual(self.post(port, "http://evil.example"), 403)
        self.assertEqual(self.post(port, None), 403)
        time.sleep(0.5)
        self.assertIsNone(proc.poll())
        self.assertEqual(self.post(port, "http://127.0.0.1:%d" % port), 200)
        proc.wait(10)

    def test_arret_automatique_sans_ping(self):
        proc, port = self.lancer("--idle-quit", "7")
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        c.request("GET", "/api/ping"); self.assertEqual(c.getresponse().status, 200); c.close()
        proc.wait(25)   # s'arrete tout seul (7 s sans ping + pas de verification de 5 s)


class TestPhrases(unittest.TestCase):
    def ph(self, **k):
        return server.phrase_for(ev(**k))["text"]

    def test_rules(self):
        self.assertEqual(self.ph(name="Write", file="D:\\x\\y\\notes.md"), "A \u00e9crit ou modifi\u00e9 notes.md")
        self.assertEqual(self.ph(name="Edit", file="D:\\x\\b.py"), "A \u00e9crit ou modifi\u00e9 b.py")
        self.assertEqual(self.ph(name="Bash", summary="git commit -m x", commit="Ajout du plan"),
                         "A enregistr\u00e9 une version : Ajout du plan")
        self.assertEqual(self.ph(name="Bash", summary="git push origin main"), "A publi\u00e9 sur GitHub")
        self.assertEqual(self.ph(name="Bash", summary="curl -s http://x"), "A v\u00e9rifi\u00e9 qu'un site r\u00e9pond")
        self.assertEqual(self.ph(name="Bash", summary="uv run python test_cockpit.py"), "A lanc\u00e9 un test")
        self.assertEqual(self.ph(name="Bash", summary="python -m unittest"), "A lanc\u00e9 un test")
        self.assertEqual(self.ph(name="Bash", summary="ls -la"), "A ex\u00e9cut\u00e9 une commande")
        self.assertEqual(self.ph(name="WebSearch", summary="prix timbre"), "A cherch\u00e9 sur le web : prix timbre")
        self.assertEqual(self.ph(name="Agent", summary="Scan de march\u00e9"), "A lanc\u00e9 un agent : Scan de march\u00e9")
        t = server.phrase_for({"kind": "text", "text": "x" * 300, "ts": ""})["text"]
        self.assertTrue(t.startswith("A dit : ") and len(t) <= len("A dit : ") + 140)

    def test_commit_message(self):
        self.assertEqual(server.extract_commit('git commit -m "Premier jet"'), "Premier jet")
        heredoc = "git commit -m \"$(cat <<'EOF'\nRefonte du cockpit\n\nCo-Authored-By: x\nEOF\n)\""
        self.assertEqual(server.extract_commit(heredoc), "Refonte du cockpit")
        self.assertIsNone(server.extract_commit("ls"))

    def test_grouping_reads(self):
        evs = [dict(ev(name="Read", summary="D:\\a\\f%d.md" % i), seq=i + 1) for i in range(5)]
        evs.append(dict(ev(name="Write", file="D:\\a\\z.py"), seq=6))
        tl = server.build_timeline(evs)
        self.assertEqual(len(tl), 2)
        self.assertEqual(tl[0]["text"], "A \u00e9crit ou modifi\u00e9 z.py")      # plus recent en premier
        self.assertEqual(tl[1]["text"], "A lu 5 fichiers")
        self.assertGreaterEqual(len(tl[1]["details"]), 5)

    def test_secrets_masked_in_phrases(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "s.jsonl")
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(line(type="assistant", timestamp="2026-11-08T10:00:00Z", message={"content": [
                    {"type": "tool_use", "id": "q", "name": "WebSearch", "input": {"query": "gho_" + "Z" * 30}}]}))
            r = server.IncrementalReader(p)
            r.poll()
            self.assertNotIn("gho_ZZZ", json.dumps(server.build_timeline(r.events)))
            self.assertEqual(r.searches, 1)
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestPlan(unittest.TestCase):
    def test_items_and_updates(self):
        plan = server.apply_plan([], {"items": [{"content": "A", "status": "in_progress"},
                                                {"content": "B", "status": "pending"},
                                                {"content": "C", "status": "pending"}]})
        self.assertEqual([p["status"] for p in plan], ["in_progress", "pending", "pending"])
        plan = server.apply_plan(plan, {"advance": True})
        self.assertEqual([p["status"] for p in plan], ["completed", "in_progress", "pending"])
        plan = server.apply_plan(plan, {"done": [3], "start": 2})
        self.assertEqual([p["status"] for p in plan], ["completed", "in_progress", "completed"])

    def test_reader_keeps_last_plan(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "s.jsonl")
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                for i, items in enumerate([[{"content": "Vieux", "status": "pending"}],
                                           [{"content": "Neuf 1", "status": "completed"},
                                            {"content": "Neuf 2", "status": "in_progress"}]]):
                    f.write(line(type="assistant", timestamp="2026-11-08T10:00:0%dZ" % i, message={"content": [
                        {"type": "tool_use", "id": "p%d" % i, "name": "mcp__ccd_turn__update_plan",
                         "input": {"items": items, "scope": "first_task"}}]}))
            r = server.IncrementalReader(p)
            r.poll()
            self.assertEqual([x["content"] for x in r.plan], ["Neuf 1", "Neuf 2"])
            self.assertEqual(r.plan[1]["status"], "in_progress")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestAgents(unittest.TestCase):
    def test_file_and_next_run(self):
        d = tempfile.mkdtemp()
        try:
            self.assertFalse(server.load_agents_file(os.path.join(d, "absent.json"))["found"])
            p = os.path.join(d, "AGENTS.json")
            with open(p, "w", encoding="utf-8") as f:
                json.dump({"agents": [{"id": "a", "nom": "Bilan du matin", "role": "R", "type": "planifie",
                                       "horaires": ["09:30", "14:00"], "etat": "actif"},
                                      {"id": "b", "nom": "Scan de march\u00e9", "role": "R2", "type": "sous-agent",
                                       "etat": "termine"}]}, f)
            reg = server.load_agents_file(p)
            self.assertTrue(reg["found"])
            self.assertEqual(len(reg["agents"]), 2)
            now = datetime(2026, 11, 8, 10, 0)
            self.assertEqual(server.next_run(["09:30", "14:00"], now)[1], "aujourd'hui \u00e0 14:00")
            self.assertEqual(server.next_run(["09:30"], now)[1], "demain \u00e0 09:30")
            self.assertEqual(server.next_run([], now), (None, None))
            cards = server.merge_agents(reg["agents"], [], now)
            self.assertEqual(cards[0]["status"], "planned")
            self.assertEqual(cards[0]["next_run"], "aujourd'hui \u00e0 14:00")
            self.assertEqual(cards[1]["status"], "done")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_detection_and_merge_without_duplicate(self):
        d = tempfile.mkdtemp()
        try:
            p = os.path.join(d, "s.jsonl")
            with open(p, "w", encoding="utf-8", newline="\n") as f:
                f.write(line(type="assistant", timestamp="2026-11-08T10:00:00Z", message={"content": [
                    {"type": "tool_use", "id": "ag1", "name": "Agent", "input": {"description": "Scan de march\u00e9"}},
                    {"type": "tool_use", "id": "ag2", "name": "Agent", "input": {"description": "Nouvel agent inconnu"}}]}))
                f.write(line(type="user", timestamp="2026-11-08T10:00:01Z", message={"content": [
                    {"type": "tool_result", "tool_use_id": "ag1", "content": [
                        {"type": "text", "text": "Async agent launched successfully.\nagentId: abc123 (internal)"}]},
                    {"type": "tool_result", "tool_use_id": "ag2", "content": [
                        {"type": "text", "text": "Async agent launched successfully.\nagentId: def456 (internal)"}]}]}))
                f.write(line(type="user", timestamp="2026-11-08T10:05:00Z", message={"role": "user", "content":
                    "<task-notification>\n<task-id>abc123</task-id>\n<status>completed</status>\n"
                    "<summary>Agent \"Scan de march\u00e9\" completed</summary>\n</task-notification>"}))
            r = server.IncrementalReader(p)
            r.poll()
            det = r.detected_agents()
            self.assertEqual({a["name"]: a["status"] for a in det},
                             {"Scan de march\u00e9": "done", "Nouvel agent inconnu": "running"})
            self.assertEqual([a for a in det if a["name"] == "Scan de march\u00e9"][0]["duree_s"], 300)
            self.assertFalse(any(e["kind"] == "user" and "task-notification" in e["text"] for e in r.events))
            reg = [{"id": "x", "nom": "Scan de march\u00e9", "role": "R", "type": "sous-agent", "horaires": [],
                    "fichier": "", "etat": "termine"}]
            cards = server.merge_agents(reg, det, datetime(2026, 11, 8, 12, 0))
            names = [c["nom"] for c in cards]
            self.assertEqual(names.count("Scan de march\u00e9"), 1)
            self.assertIn("Nouvel agent inconnu", names)
            self.assertEqual(len(cards), 2)
            self.assertEqual(cards[1]["status"], "running")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestNoise(unittest.TestCase):
    def test_noise_folders_excluded(self):
        d = tempfile.mkdtemp()
        try:
            for sub in ["extensions_crx_cache", "component_crx_cache", "chromium_headless_shell", "__pycache__",
                        ".git", "node_modules", "dist", "build", "venv", ".venv", "secrets", "_secrets", "tmp",
                        "logs", "profil_nav", "ok"]:
                os.makedirs(os.path.join(d, sub))
                with open(os.path.join(d, sub, "x.json"), "w") as f:
                    f.write("{}")
            with open(os.path.join(d, "profil_nav", "Preferences"), "w") as f:     # depot de profil navigateur
                f.write("{}")
            ids = {n["id"] for n in server.build_tree(d)["nodes"]}
            self.assertEqual(ids, {"", "ok", "ok/x.json"})
            self.assertIsNone(server.safe_resolve(d, "venv/x.json"))
            self.assertIsNone(server.safe_resolve(d, "logs/x.json"))
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_generic_zones_labels_colors(self):
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, "mon_outil-v2"))
            os.makedirs(os.path.join(d, "docs"))
            with open(os.path.join(d, "mon_outil-v2", "a.py"), "w") as f:
                f.write('"""Un outil."""\ndef f():\n    pass\n')
            with open(os.path.join(d, "mon_outil-v2", "b.py"), "w") as f:
                f.write("x = 1\n")
            with open(os.path.join(d, "docs", "n.md"), "w") as f:
                f.write("# Titre un\n## Titre deux\n")
            with open(os.path.join(d, "README.md"), "w") as f:
                f.write("# Lisez-moi\n")
            with open(os.path.join(d, "requirements.txt"), "w") as f:
                f.write("x\n")
            with open(os.path.join(d, "notes.md"), "w") as f:
                f.write("# Notes\n")
            t = server.build_tree(d)
            by = {n["id"]: n for n in t["nodes"]}
            self.assertEqual(by["mon_outil-v2"]["label"], "Mon outil v2")
            self.assertEqual(by["mon_outil-v2/a.py"]["zone"], by["mon_outil-v2"]["zone"])
            self.assertEqual(by["notes.md"]["zone"], "autres")
            self.assertIn("mode d'emploi", by["README.md"]["desc"])
            self.assertIn("bibliothèques", by["requirements.txt"]["desc"])
            zones = {z["label"]: z for z in t["zones"]}
            self.assertEqual(set(zones), {"Mon outil v2", "Docs", "Autres"})
            cols = [z["color"] for z in t["zones"]]
            self.assertEqual(len(set(cols)), len(cols))                     # couleurs distinctes
            self.assertEqual(zones["Mon outil v2"]["count"], 3)             # dossier + 2 fichiers
            self.assertEqual(server.read_preview(d, "docs/n.md")["outline"], ["Titre un", "Titre deux"])
            self.assertEqual(server.read_preview(d, "mon_outil-v2/a.py")["summary"], "Un outil.")
            self.assertEqual(server.read_preview(d, "mon_outil-v2/a.py")["outline"], ["f"])
            self.assertEqual(server.read_preview(d, "mon_outil-v2/b.py")["quoi"], "Pas encore de description")
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_zone_cap_and_readable_names(self):
        d = tempfile.mkdtemp()
        try:
            for i in range(12):
                os.makedirs(os.path.join(d, "dossier_%02d" % i))
                with open(os.path.join(d, "dossier_%02d" % i, "a.md"), "w") as f:
                    f.write("# a\n")
            t = server.build_tree(d)
            self.assertEqual(len(t["zones"]), server.MAX_ZONES + 1)         # 8 dossiers + Autres
            self.assertEqual(t["zones"][-1]["id"], "autres")
            self.assertEqual(sum(z["count"] for z in t["zones"]), 24)
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(server.readable_name("mon_dossier-x"), "Mon dossier x")
        self.assertEqual(server.readable_name("__"), "__")

    def test_no_profile_by_default(self):
        self.assertFalse(server.PROFILE["active"])
        self.assertEqual(set(server.IGNORED), set(server.BASE_IGNORED))

    def test_profile_loading_mechanism(self):
        d = tempfile.mkdtemp()
        try:
            prof = os.path.join(d, "p")
            os.makedirs(prof)
            with open(os.path.join(prof, "profil.json"), "w", encoding="utf-8") as f:
                json.dump({"zones": {"a": "Zone A", "autres": "Autres"}, "dir_zone": {"alpha": "a"},
                           "friendly": {"alpha": "Le dossier alpha"}, "ignored_extra": ["cache_x"],
                           "desc": {"zz.md": "Fichier special."}}, f)
            with open(os.path.join(prof, "descriptions.json"), "w", encoding="utf-8") as f:
                json.dump({"alpha/q.md": {"quoi": "Le quoi.", "pourquoi": "Le pourquoi."}}, f)
            work = os.path.join(d, "w")
            for sub in ("alpha", "cache_x", "beta"):
                os.makedirs(os.path.join(work, sub))
                with open(os.path.join(work, sub, "q.md"), "w") as f:
                    f.write("# q\n")
            with open(os.path.join(work, "zz.md"), "w") as f:
                f.write("# zz\n")
            self.assertTrue(server.load_profile(prof))
            t = server.build_tree(work)
            by = {n["id"]: n for n in t["nodes"]}
            self.assertNotIn("cache_x", by)
            self.assertEqual(by["alpha"]["label"], "Le dossier alpha")
            self.assertEqual(by["alpha/q.md"]["zone"], "a")
            self.assertEqual(by["alpha/q.md"]["why"], "Le pourquoi.")
            self.assertEqual(by["beta"]["zone"], "autres")
            self.assertEqual(by["zz.md"]["desc"], "Fichier special.")
            self.assertEqual([z["label"] for z in t["zones"]], ["Zone A", "Autres"])
            self.assertFalse(server.load_profile(os.path.join(d, "absent")))    # remet l'etat generique
            self.assertFalse(server.PROFILE["active"])
            self.assertIn("cache_x", {n["id"] for n in server.build_tree(work)["nodes"]})
        finally:
            server.reset_profile()
            shutil.rmtree(d, ignore_errors=True)


class TestPage(unittest.TestCase):
    def test_levels_and_no_external_resource(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "a.md"), "w", encoding="utf-8") as f:
                f.write("# Un" + chr(10) + "## Deux" + chr(10) + "### Trois" + chr(10) + "texte" + chr(10) + "## Quatre" + chr(10))
            p = server.read_preview(d, "a.md")
            self.assertEqual(p["outline"], ["Un", "Deux", "Trois", "Quatre"])
            self.assertEqual(p["levels"], [1, 2, 3, 2])
        finally:
            shutil.rmtree(d, ignore_errors=True)
        html = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
        for bad in ("<script src", "<link ", "@import", "url(http", "src=\"http", "fetch(\"http", "XMLHttpRequest"):
            self.assertNotIn(bad, html, bad)
        for needed in ("contextmenu", "auxclick", "setInterval(() => { if (tab === \"brain\" && !document.hidden)"):
            self.assertIn(needed, html, needed)
        self.assertGreaterEqual(html.count("function g"), 9)   # catalogue de schemas


class TestDescriptions(unittest.TestCase):
    def test_preview_has_summary_levels(self):
        d = tempfile.mkdtemp()
        try:
            with open(os.path.join(d, "README.md"), "w", encoding="utf-8") as f:
                f.write("# J\ntexte\n")
            with open(os.path.join(d, "x.py"), "w", encoding="utf-8") as f:
                f.write('"""Fait des choses utiles."""\n')
            with open(os.path.join(d, "y.py"), "w", encoding="utf-8") as f:
                f.write("x = 1\n")
            p = server.read_preview(d, "README.md")        # description generique d'un fichier courant
            self.assertTrue(p["described"])
            p = server.read_preview(d, "x.py")             # deduit du docstring
            self.assertEqual(p["quoi"], "Fait des choses utiles.")
            p = server.read_preview(d, "y.py")             # rien du tout
            self.assertEqual(p["quoi"], "Pas encore de description")
        finally:
            shutil.rmtree(d, ignore_errors=True)


class TestCodeAndTech(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.d, "logs"))
        with open(os.path.join(self.d, "logs", "a.py"), "w") as f:
            f.write("x=1")
        with open(os.path.join(self.d, "p.py"), "w", encoding="utf-8") as f:
            f.write('"""Doc."""\nimport os, json\nfrom sys import path\n\ndef alpha():\n    """Premiere."""\n    return 1\n\n'
                    'class Beta:\n    def gamma(self):\n        pass\n\ntoken = "gho_' + "Q" * 30 + '"\n')
        with open(os.path.join(self.d, "big.md"), "w") as f:
            f.write("a" * (server.CODE_MAX + 10))
        with open(os.path.join(self.d, ".env"), "w") as f:
            f.write("K=1")
        with open(os.path.join(self.d, "bin.json"), "wb") as f:
            f.write(b"\x00\x01\x02")

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def test_code(self):
        c = server.read_code(self.d, "p.py")
        self.assertTrue(c["ok"])
        self.assertIn("def alpha", c["text"])
        self.assertNotIn("QQQQ", c["text"])
        big = server.read_code(self.d, "big.md")
        self.assertFalse(big["ok"])
        self.assertIn("trop gros", big["reason"])
        self.assertFalse(server.read_code(self.d, "bin.json")["ok"])
        for bad in ["../x", "logs/a.py", ".env", "/etc/passwd", "C:\\Windows\\win.ini", "absent.py"]:
            self.assertIsNone(server.read_code(self.d, bad), bad)
            self.assertIsNone(server.tech_info(self.d, bad), bad)

    def test_tech_ast(self):
        t = server.tech_info(self.d, "p.py")
        names = [(i["name"], i["kind"]) for i in t["items"]]
        self.assertEqual(names, [("alpha", "fonction"), ("Beta", "classe"), ("Beta.gamma", "methode")])
        self.assertEqual(t["items"][0]["role"], "Premiere.")
        self.assertEqual(t["items"][2]["role"], "Rôle non documenté (nom : gamma)")
        self.assertEqual(t["imports"], ["json", "os", "sys"])
        self.assertGreater(t["lines"], 5)


class TestIcons(unittest.TestCase):
    def test_page_icons_labels_spacing(self):
        html = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
        for name in ("snake", "mdhash", "braces", "chevrons", "js", "grid", "terminal", "image"):
            self.assertIn('kind === "%s"' % name, html)
        for ext in ("py", "md", "json", "html", "js", "xlsx", "bat", "sh", "png"):
            self.assertRegex(html, r"\b%s: \"" % ext)
        for gone in ("gHoney", "hexPts", "honeyH", "nid d'abeille\" "):
            self.assertNotIn(gone, html)
        self.assertIn("BASE_R * (1 + .35 * Math.sqrt(k))", html)      # regle d'espacement documentee
        self.assertIn("DMIN = 40", html)
        self.assertIn("MAXLAB = 14", html)


class TestAutodetect(unittest.TestCase):
    def setUp(self):
        # realpath : sous Windows, le dossier temporaire peut etre donne en noms courts 8.3 (RUNNER~1 sur les
        # executeurs GitHub) ; or le nom de session est encode depuis le vrai chemin, en noms longs.
        self.d = os.path.realpath(tempfile.mkdtemp())
        # faux profil utilisateur : <d>/home/.claude/projects/<sous-dossiers de sessions>
        self.home = os.path.join(self.d, "home")
        self.proj = os.path.join(self.home, ".claude", "projects")
        os.makedirs(self.proj)

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def mk_session(self, name, mtime, cwd=None):
        folder = os.path.join(self.proj, name)
        os.makedirs(folder, exist_ok=True)
        f = os.path.join(folder, "s.jsonl")
        with open(f, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"type": "user", "cwd": cwd} if cwd else {"type": "user"}) + "\n")
        os.utime(f, (mtime, mtime))
        return folder

    def test_projects_dir_uses_current_user(self):
        p = server.claude_projects_dir({"USERPROFILE": self.home})
        self.assertEqual(p, self.proj)

    def test_newest_subfolder_wins(self):
        self.mk_session("A--old", 1_000_000)
        new = self.mk_session("B--new", 2_000_000)
        os.makedirs(os.path.join(self.proj, "C--empty"))       # sans session : ignore
        self.assertEqual(server.detect_sessions(self.proj), new)

    def test_no_projects(self):
        self.assertIsNone(server.detect_sessions(os.path.join(self.d, "absent")))
        self.assertIsNone(server.detect_sessions(self.proj))

    def test_decode_name_with_separators(self):
        work = os.path.join(self.d, "Mon projet-v2", "sous_dossier")
        os.makedirs(work)
        os.makedirs(os.path.join(self.d, "Mon", "projet"))      # piste fausse
        drive = os.path.splitdrive(work)[0] + os.sep
        rest = server.encode_project_name(os.path.relpath(work, drive))
        self.assertEqual(os.path.normcase(server.decode_project_name(rest, start=drive)), os.path.normcase(work))
        self.assertIsNone(server.decode_project_name("Inexistant-xyz", start=drive))
        self.assertIsNone(server.decode_project_name("pas un nom de session"))

    def test_decode_needs_long_names(self):
        """Cause de l'echec sur GitHub : un chemin en noms courts 8.3 s'encode autrement que le vrai chemin."""
        if sys.platform != "win32":
            self.skipTest("noms courts : Windows seulement")
        import ctypes
        work = os.path.join(self.d, "Mon projet long")
        os.makedirs(work)
        buf = ctypes.create_unicode_buffer(600)
        if not ctypes.windll.kernel32.GetShortPathNameW(work, buf, 600) or buf.value == work:
            self.skipTest("noms courts desactives sur ce volume")
        self.assertEqual(os.path.normcase(server.decode_project_name(server.encode_project_name(work))),
                         os.path.normcase(work))
        self.assertEqual(os.path.normcase(os.path.realpath(buf.value)), os.path.normcase(work))

    def test_two_different_drives(self):
        """Dossier de travail et dossier de sessions sur deux lecteurs differents."""
        if sys.platform != "win32":
            self.skipTest("lecteurs : Windows seulement")
        other = tempfile.mkdtemp(dir=HERE)           # lecteur du programme (D: sur un executeur GitHub, souvent C: ailleurs)
        try:
            other = os.path.realpath(other)
            if os.path.splitdrive(other)[0].upper() == os.path.splitdrive(self.d)[0].upper():
                # meme lecteur : on cherche un autre lecteur inscriptible a la racine
                alt = None
                for letter in "CDEFGH":
                    r = letter + ":\\"
                    if os.path.isdir(r) and letter != os.path.splitdrive(self.d)[0][:1].upper():
                        try:
                            alt = tempfile.mkdtemp(dir=r)
                            break
                        except OSError:
                            continue
                if not alt:
                    self.skipTest("un seul lecteur utilisable")
                shutil.rmtree(other, ignore_errors=True)
                other = os.path.realpath(alt)
            work = os.path.join(other, "Mon projet-x")
            os.makedirs(work)
            # sessions sur le lecteur A (self.d), dossier de travail sur le lecteur B (other)
            name = server.encode_project_name(work)
            sess = self.mk_session(name, 1_000_000)                       # sans cwd : decodage par le nom
            self.assertEqual(os.path.normcase(server.guess_root(sess)), os.path.normcase(work))
            sess2 = self.mk_session("W--cwd", 2_000_000, cwd=work)       # avec cwd
            self.assertEqual(os.path.normcase(server.guess_root(sess2)), os.path.normcase(work))
            self.assertEqual(os.path.normcase(server.resolve_settings(None, None, {}, self.proj)[1]),
                             os.path.normcase(work))
        finally:
            shutil.rmtree(other, ignore_errors=True)

    def test_decode_full_name_with_drive(self):
        if not os.path.splitdrive(self.d)[0]:
            self.skipTest("pas de lecteur")
        work = os.path.join(self.d, "Mon projet")
        os.makedirs(work)
        name = server.encode_project_name(work)       # ex. C--Users-...-Mon-projet
        self.assertEqual(os.path.normcase(server.decode_project_name(name)), os.path.normcase(work))

    def test_guess_root_from_cwd_then_name(self):
        work = os.path.join(self.d, "travail")
        os.makedirs(work)
        s1 = self.mk_session("X--a", 1_000_000, cwd=work)
        self.assertEqual(server.guess_root(s1), os.path.abspath(work))
        s2 = self.mk_session(server.encode_project_name(work), 2_000_000)    # pas de cwd : le nom
        self.assertEqual(os.path.normcase(server.guess_root(s2)), os.path.normcase(work))
        s3 = self.mk_session("Z--introuvable-xyz", 3_000_000, cwd=os.path.join(self.d, "nexistepas"))
        self.assertIsNone(server.guess_root(s3))
        self.assertIsNone(server.guess_root(None))

    def test_drive_root_refused_as_root(self):
        s = self.mk_session("Q--r", 1_000_000, cwd=os.path.abspath(os.sep))
        self.assertIsNone(server.root_from_session_file(s))

    def test_priority_cli_config_auto(self):
        work = os.path.join(self.d, "w")
        other = os.path.join(self.d, "o")
        os.makedirs(work)
        os.makedirs(other)
        auto = self.mk_session("Y--b", 2_000_000, cwd=work)
        self.assertEqual(server.resolve_settings(None, None, {}, self.proj), (auto, os.path.abspath(work)))
        self.assertEqual(server.resolve_settings(None, None, {"root": other}, self.proj)[1], other)
        self.assertEqual(server.resolve_settings("S", other, {"root": work}, self.proj), ("S", other))
        # dossier memorise disparu : retour a la detection
        gone = {"root": os.path.join(self.d, "disparu")}
        self.assertEqual(server.resolve_settings(None, None, gone, self.proj)[1], os.path.abspath(work))

    def test_config_roundtrip(self):
        p = os.path.join(self.d, "config.json")
        self.assertEqual(server.load_config(p), {})
        self.assertTrue(server.save_config(p, {"root": "C:\\x\\é"}))
        self.assertEqual(server.load_config(p), {"root": "C:\\x\\é"})
        with open(p, "w") as f:
            f.write("pas du json")
        self.assertEqual(server.load_config(p), {})
        self.assertFalse(server.save_config(os.path.join(self.d, "nope", "c.json"), {}))

    def test_no_hardcoded_user_paths(self):
        src = open(os.path.join(HERE, "server.py"), encoding="utf-8").read()
        self.assertIsNone(re.search(r"[A-Za-z]:\\{1,2}(?:Users|Claude)", src))   # aucun chemin reel


class TestSetupScreen(unittest.TestCase):
    """Racine inconnue : ecran d'accueil, choix du dossier, memorisation dans config.json."""

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.work = os.path.join(self.d, "work")
        os.makedirs(self.work)
        with open(os.path.join(self.work, "a.md"), "w") as f:
            f.write("# Titre de test\nbonjour")
        self.cfg = os.path.join(self.d, "config.json")
        self.srv = server.make_server(0, None, None, self.cfg)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()
        shutil.rmtree(self.d, ignore_errors=True)

    def req(self, method, path, body=None, headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        h = {"Host": "127.0.0.1:%d" % self.port}
        h.update(headers or {})
        c.request(method, path, body=body, headers=h)
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, data

    def post(self, folder, origin=True):
        hd = {"Content-Type": "application/json"}
        if origin:
            hd["Origin"] = "http://127.0.0.1:%d" % self.port
        return self.req("POST", "/api/setup", json.dumps({"root": folder}), hd)

    def test_needs_root_then_choose(self):
        st, b = self.req("GET", "/api/config")
        self.assertTrue(json.loads(b)["needs_root"])
        for p in ("/api/tree", "/api/agents"):
            self.assertEqual(self.req("GET", p)[0], 409)
        st, b = self.post(self.work)
        self.assertEqual(st, 200)
        self.assertTrue(json.loads(b)["saved"])
        self.assertEqual(server.load_config(self.cfg), {"root": os.path.abspath(self.work)})
        st, b = self.req("GET", "/api/tree")
        self.assertEqual(st, 200)
        self.assertIn("a.md", [n["name"] for n in json.loads(b)["nodes"]])
        st, b = self.req("GET", "/api/agents")
        self.assertFalse(json.loads(b)["found"])       # AGENTS.json absent : message d'aide dans la page

    def test_setup_refusals(self):
        self.assertEqual(self.post(os.path.join(self.d, "absent"))[0], 400)
        self.assertEqual(self.post(os.path.abspath(os.sep))[0], 400)
        self.assertEqual(self.post("")[0], 400)
        self.assertEqual(self.post(self.work, origin=False)[0], 403)      # requete venue d'une autre page
        st, _ = self.req("POST", "/api/setup", json.dumps({"root": self.work}),
                         {"Content-Type": "application/json", "Origin": "http://evil.example.com"})
        self.assertEqual(st, 403)
        st, _ = self.req("POST", "/api/setup", "root=x", {"Content-Type": "text/plain",
                                                           "Origin": "http://127.0.0.1:%d" % self.port})
        self.assertEqual(st, 400)
        st, _ = self.req("POST", "/api/setup", json.dumps({"root": self.work}),
                         {"Content-Type": "application/json", "Host": "evil.example.com"})
        self.assertEqual(st, 403)
        self.assertFalse(os.path.exists(self.cfg))                        # rien d'ecrit
        self.assertTrue(json.loads(self.req("GET", "/api/config")[1])["needs_root"])

    def test_page_has_welcome_and_agents_help(self):
        html = open(os.path.join(HERE, "index.html"), encoding="utf-8").read()
        for needle in ('id="welcome"', "/api/setup", "AGENTS.exemple.json", "Comment nommer vos agents"):
            self.assertIn(needle, html)
        path = os.path.join(HERE, "AGENTS.exemple.json")
        ex = json.load(open(path, encoding="utf-8"))
        self.assertEqual(len(server.load_agents_file(path)["agents"]), len(ex["agents"]))

    def test_live_without_sessions(self):
        st, b = self.req("GET", "/api/live")
        self.assertEqual(st, 200)
        self.assertIsNone(json.loads(b)["session"])


class TestMissions(unittest.TestCase):
    def test_absent(self):
        r = server.load_missions(os.path.join(tempfile.gettempdir(), "absent_missions_xyz.md"))
        self.assertFalse(r["found"])
        self.assertEqual(r["groups"], [])

    def test_groupes_detail_et_faites_masquees(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "MISSIONS.md")
            with open(p, "w", encoding="utf-8") as f:
                f.write("# Titre\n## Aujourd hui\n- [ ] Payer la facture\n  Detail une\n  Detail deux\n- [x] Appeler\n## Plus tard\n- [ ] Autre\n")
            r = server.load_missions(p)
        self.assertEqual([g["title"] for g in r["groups"]], ["Aujourd hui", "Plus tard"])
        a = r["groups"][0]["items"]
        self.assertEqual([i["text"] for i in a], ["Payer la facture"])      # la mission faite n'est plus affichee
        self.assertEqual(a[0]["detail"], ["Detail une", "Detail deux"])

    def test_cocher_ecrit_le_fichier_et_le_journal(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "MISSIONS.md")
            with open(p, "w", encoding="utf-8", newline="") as f:
                f.write("## G\r\n- [ ] Une\r\n  detail\r\n- [ ] Deux\r\n")
            mid = server.load_missions(p)["groups"][0]["items"][1]["id"]
            self.assertEqual(server.mark_mission_done(d, mid), "Deux")
            with open(p, "r", encoding="utf-8", newline="") as f:
                txt = f.read()
            self.assertIn("- [ ] Une\r\n  detail\r\n- [x] Deux\r\n", txt)       # fins de ligne conservees
            self.assertEqual([i["text"] for i in server.load_missions(p)["groups"][0]["items"]], ["Une"])
            with open(os.path.join(d, "MISSIONS_FAITES.jsonl"), encoding="utf-8") as f:
                self.assertIn("Deux", f.read())
            self.assertIsNone(server.mark_mission_done(d, mid))                 # deja faite
            self.assertIsNone(server.mark_mission_done(d, "../../etc"))         # id invalide

    def test_post_valider_exige_origine_et_json(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "MISSIONS.md"), "w", encoding="utf-8") as f:
                f.write("## G\n- [ ] Ma mission\n")
            srv = server.make_server(0, d, d)
            port = srv.server_address[1]
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            try:
                mid = server.load_missions(os.path.join(d, "MISSIONS.md"))["groups"][0]["items"][0]["id"]
                body = json.dumps({"id": mid})
                def post(origin):
                    c = http.client.HTTPConnection("127.0.0.1", port)
                    h = {"Content-Type": "application/json", "Host": "127.0.0.1:%d" % port}
                    if origin:
                        h["Origin"] = origin
                    c.request("POST", "/api/missions/done", body, h)
                    return c.getresponse().status
                self.assertEqual(post(None), 403)
                self.assertEqual(post("http://evil.example"), 403)
                self.assertEqual(post("http://127.0.0.1:%d" % port), 200)
                self.assertEqual(post("http://127.0.0.1:%d" % port), 404)
            finally:
                srv.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
