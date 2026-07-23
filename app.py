import os, json, uuid, shutil, subprocess, threading, time, hashlib, secrets, string, signal, sys, socket, re
import urllib.request, urllib.error
try:
    import resource as _resource  # POSIX only — used to sandbox hosted-project processes with memory/proc caps
except ImportError:
    _resource = None
from flask import Flask, request, jsonify, send_from_directory, session, redirect, url_for
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__, static_folder='static', template_folder='templates')
app.secret_key = secrets.token_hex(32)

# ─── PATHS ───────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
UPLOADS_DIR = os.path.join(BASE_DIR, 'uploads')
PROJECTS_DIR= os.path.join(BASE_DIR, 'projects')
DATA_FILE   = os.path.join(BASE_DIR, 'data', 'db.json')
for d in [UPLOADS_DIR, PROJECTS_DIR, os.path.join(BASE_DIR,'data')]:
    os.makedirs(d, exist_ok=True)

# ─── DB ──────────────────────────────────────────────
def load_db():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            return json.load(f)
    default = {
        "users": [
            {"username":"DeV Sk7 and skinz","password":hashpw("sk7andskins"),"role":"dev","file_limit":9999,"days":99999,"created_at":time.time(),"files":[]},
            {"username":"admin","password":hashpw("admin123"),"role":"admin","file_limit":50,"days":365,"created_at":time.time(),"files":[]},
        ],
        "projects": {},
        "port_counter": 9000
    }
    save_db(default)
    return default

def save_db(db):
    with open(DATA_FILE,'w') as f:
        json.dump(db, f, indent=2, ensure_ascii=False)

def hashpw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

DB = load_db()

# ─── RUNNING PROCESSES ───────────────────────────────
PROCESSES = {}   # project_id -> {"proc": Popen, "port": int, "log": [...], "status": str}

# ─── AUTH HELPERS ────────────────────────────────────
def get_user(username):
    return next((u for u in DB['users'] if u['username']==username), None)

def current_user():
    if 'username' not in session: return None
    return get_user(session['username'])

def login_required(f):
    @wraps(f)
    def wrapper(*a,**kw):
        if not current_user():
            return jsonify({"error":"unauthorized"}), 401
        return f(*a,**kw)
    return wrapper

def role_required(*roles):
    def dec(f):
        @wraps(f)
        def wrapper(*a,**kw):
            u = current_user()
            if not u or u['role'] not in roles:
                return jsonify({"error":"forbidden"}), 403
            return f(*a,**kw)
        return wrapper
    return dec

def file_limit_ok(user, extra=1):
    return len(user.get('files',[])) + extra <= user['file_limit']

def gen_password(length=12):
    chars = string.ascii_letters + string.digits + '@#$%'
    return ''.join(secrets.choice(chars) for _ in range(length))

PORT_MIN, PORT_MAX = 9000, 9999

def port_in_use(port):
    """Real OS-level check — catches ports held by leftover/external processes,
    not just ones this panel thinks it allocated."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(('127.0.0.1', port)) == 0

def next_port():
    used = {p['port'] for p in DB['projects'].values()}
    start = DB.get('port_counter', PORT_MIN)
    for i in range(PORT_MAX - PORT_MIN + 1):
        candidate = PORT_MIN + ((start - PORT_MIN + i) % (PORT_MAX - PORT_MIN + 1))
        if candidate in used or port_in_use(candidate):
            continue
        DB['port_counter'] = candidate + 1
        save_db(DB)
        return candidate
    raise RuntimeError("لا توجد منافذ متاحة (9000-9999 كلها مستخدمة)")

# ─── SERVE FRONTEND ──────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('templates','index.html')

@app.route('/static/<path:path>')
def static_files(path):
    return send_from_directory('static', path)

@app.route('/health')
def panel_health():
    return jsonify({"ok": True, "time": time.time()})

# ─── REVERSE PROXY — makes every hosted project reachable through this
# same origin/port, so it works behind Cloudflare Tunnel / nginx / ngrok /
# any single-port reverse proxy (raw "hostname:9002" links only work when
# hitting the VPS directly, which is why they broke for you before) ───
_PROXY_DROP_HEADERS = {'content-length', 'transfer-encoding', 'connection', 'keep-alive',
                        'proxy-authenticate', 'proxy-authorization', 'te', 'trailer',
                        'upgrade', 'host'}

def _probe_project(port, timeout=1.5):
    """Real HTTP probe against the project's local port. Any HTTP response
    (even a 404/500) means the app is up and listening — that's still a
    'reachable' server, just one whose route returned an error."""
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{port}/", method='GET')
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, resp.status
    except urllib.error.HTTPError as e:
        return True, e.code
    except Exception:
        return False, None

@app.route('/app/<pid>', defaults={'subpath': ''}, methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
@app.route('/app/<pid>/', defaults={'subpath': ''}, methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
@app.route('/app/<pid>/<path:subpath>', methods=['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'])
def proxy_project(pid, subpath):
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "مشروع غير موجود"}), 404
    info = PROCESSES.get(pid, {})
    if info.get('status') != 'running':
        return jsonify({"error": "السيرفر متوقف حالياً — شغّله من لوحة التحكم"}), 503

    target = f"http://127.0.0.1:{proj['port']}/{subpath}"
    if request.query_string:
        target += '?' + request.query_string.decode()
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _PROXY_DROP_HEADERS}
    try:
        req = urllib.request.Request(target, data=request.get_data() or None,
                                      headers=fwd_headers, method=request.method)
        with urllib.request.urlopen(req, timeout=25) as resp:
            body = resp.read()
            resp_headers = [(k, v) for k, v in resp.getheaders() if k.lower() not in _PROXY_DROP_HEADERS]
            return (body, resp.status, resp_headers)
    except urllib.error.HTTPError as e:
        body = e.read()
        resp_headers = [(k, v) for k, v in e.headers.items() if k.lower() not in _PROXY_DROP_HEADERS]
        return (body, e.code, resp_headers)
    except Exception as e:
        return jsonify({"error": f"تعذر الوصول للمشروع محلياً: {e}"}), 502

# ─── AUTH ROUTES ─────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.json or {}
    u = get_user(data.get('username',''))
    if not u or u['password'] != hashpw(data.get('password','')):
        return jsonify({"error":"بيانات خاطئة"}), 401
    # check expiry
    expires = datetime.fromtimestamp(u['created_at']) + timedelta(days=u['days'])
    if datetime.now() > expires and u['role'] not in ('dev',):
        return jsonify({"error":"الحساب منتهي الصلاحية"}), 403
    session['username'] = u['username']
    return jsonify({"ok":True,"role":u['role'],"username":u['username'],"file_limit":u['file_limit']})

@app.route('/api/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({"ok":True})

@app.route('/api/me')
def api_me():
    u = current_user()
    if not u: return jsonify({"error":"unauth"}),401
    expires = datetime.fromtimestamp(u['created_at']) + timedelta(days=u['days'])
    return jsonify({"username":u['username'],"role":u['role'],"file_limit":u['file_limit'],"files_used":len(u.get('files',[])),"expires":expires.strftime('%Y-%m-%d')})

# ─── UPLOAD & DEPLOY ─────────────────────────────────
ALLOWED_EXTENSIONS = {
    'py','js','ts','html','css','json','txt','md','sh','env','yaml','yml',
    'php','rb','go','rs','java','cpp','c','h','xml','csv','sql','zip','tar',
    'gz','png','jpg','jpeg','gif','svg','pdf','mp4','mp3','woff','woff2','ttf'
}

def allowed(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/api/upload', methods=['POST'])
@login_required
def api_upload():
    u = current_user()
    files = request.files.getlist('files')
    if not files: return jsonify({"error":"لا توجد ملفات"}),400

    uploaded = []
    errors   = []
    for f in files:
        if not allowed(f.filename):
            errors.append(f"{f.filename}: نوع غير مدعوم")
            continue
        if len(u.get('files',[])) >= u['file_limit']:
            errors.append(f"{f.filename}: تجاوزت الحد الأقصى ({u['file_limit']})")
            break
        filename = secure_filename(f.filename)
        user_dir = os.path.join(UPLOADS_DIR, u['username'])
        os.makedirs(user_dir, exist_ok=True)
        dest = os.path.join(user_dir, filename)
        f.save(dest)
        size = os.path.getsize(dest)
        record = {"name":filename,"size":size,"date":datetime.now().strftime('%Y-%m-%d %H:%M'),"path":dest}
        if 'files' not in u: u['files']=[]
        u['files'].append(record)
        uploaded.append(record)

    save_db(DB)
    return jsonify({"uploaded":uploaded,"errors":errors,"total_files":len(u.get('files',[]))})

@app.route('/api/files', methods=['GET'])
@login_required
def api_files():
    u = current_user()
    return jsonify({"files":u.get('files',[]),"limit":u['file_limit']})

@app.route('/api/files/<filename>', methods=['DELETE'])
@login_required
def api_delete_file(filename):
    u = current_user()
    files = u.get('files',[])
    record = next((f for f in files if f['name']==filename),None)
    if not record: return jsonify({"error":"ملف غير موجود"}),404
    try: os.remove(record['path'])
    except: pass
    u['files'] = [f for f in files if f['name']!=filename]
    save_db(DB)
    return jsonify({"ok":True})

# ─── PROJECTS / SERVERS (native subprocess engine — no Docker) ──
# Every hosted project runs as a plain OS process, isolated by its own
# folder + (for python) its own venv, supervised by a watchdog thread
# that restarts it if it dies — this is what gives 24/7 uptime without
# needing container isolation.

BIMO_RUNNER = '''import sys, os, runpy
try:
    from flask import Flask
    _orig = Flask.run
    def _patched(self, host=None, port=None, **kw):
        _orig(self, host="0.0.0.0", port=int(os.environ.get("PORT", {port})), **kw)
    Flask.run = _patched
except ImportError:
    pass
try:
    from fastapi import FastAPI
    import uvicorn
    _orig_run = uvicorn.run
    def _uvicorn_patched(app, host=None, port=None, **kw):
        _orig_run(app, host="0.0.0.0", port=int(os.environ.get("PORT", {port})), **kw)
    uvicorn.run = _uvicorn_patched
except ImportError:
    pass
sys.argv = [sys.argv[1]] + sys.argv[2:]
runpy.run_path(sys.argv[0], run_name="__main__")
'''

def now():
    return datetime.now().strftime('%H:%M:%S')

def parse_env(env_vars):
    out = {}
    for line in (env_vars or '').split('\n'):
        line = line.strip()
        if line and '=' in line and not line.startswith('#'):
            k, v = line.split('=', 1)
            out[k.strip()] = v.strip()
    return out

# ─── AUTO-DETECT project type, entry file, and framework ────
# This is what lets people upload a raw folder/zip and have it "just work"
# without manually picking type/main_file — similar to how Railway/Render
# inspect the repo to pick a builder.
_PY_ENTRY_CANDIDATES = ['main.py', 'app.py', 'bot.py', 'run.py', 'server.py', 'wsgi.py', 'asgi.py']
_NODE_ENTRY_CANDIDATES = ['index.js', 'server.js', 'app.js', 'main.js']
_PHP_ENTRY_CANDIDATES = ['index.php', 'app.php', 'server.php']

def _walk_top_levels(proj_dir, max_depth=2):
    """Files within the first couple of levels — deep enough to catch e.g.
    src/main.py, shallow enough to ignore vendored/node_modules noise."""
    for root, dirs, files in os.walk(proj_dir):
        depth = root[len(proj_dir):].count(os.sep)
        dirs[:] = [d for d in dirs if d not in ('venv', 'node_modules', '.git', '__pycache__', 'vendor')]
        if depth >= max_depth:
            dirs[:] = []
        for f in files:
            yield os.path.join(root, f)

def detect_project(proj_dir):
    """Returns {'type', 'main_file', 'framework'}. Best-effort — falls back to
    python/main.py (existing default) when nothing matches, and the deploy
    log always states what was detected so the user can correct it."""
    entries = os.listdir(proj_dir)
    lower = {e.lower(): e for e in entries}

    # Go
    if 'go.mod' in lower:
        return {'type': 'go', 'main_file': 'main.go', 'framework': None}

    # Django (must win over generic python before generic entry search)
    if 'manage.py' in lower:
        return {'type': 'python', 'main_file': 'manage.py', 'framework': 'django'}

    # Node
    if 'package.json' in lower:
        main_file = None
        try:
            with open(os.path.join(proj_dir, lower['package.json'])) as f:
                pkg = json.load(f)
            cand = pkg.get('main') or (pkg.get('scripts', {}).get('start', '').replace('node ', '').strip() or None)
            if cand and os.path.exists(os.path.join(proj_dir, cand)):
                main_file = cand
        except Exception:
            pass
        if not main_file:
            for c in _NODE_ENTRY_CANDIDATES:
                if c in lower:
                    main_file = lower[c]; break
        return {'type': 'node', 'main_file': main_file or 'index.js', 'framework': None}

    # PHP
    php_files = [e for e in entries if e.lower().endswith('.php')]
    if 'composer.json' in lower or php_files:
        main_file = next((lower[c] for c in _PHP_ENTRY_CANDIDATES if c in lower), None) or (php_files[0] if php_files else 'index.php')
        return {'type': 'php', 'main_file': main_file, 'framework': None}

    # Python
    py_files = [e for e in entries if e.lower().endswith('.py')]
    if 'requirements.txt' in lower or py_files:
        main_file = next((lower[c] for c in _PY_ENTRY_CANDIDATES if c in lower), None)
        if not main_file and py_files:
            main_file = py_files[0]
        return {'type': 'python', 'main_file': main_file or 'main.py', 'framework': None}

    # Static site
    if 'index.html' in lower or any(e.lower().endswith('.html') for e in entries):
        return {'type': 'static', 'main_file': 'index.html', 'framework': None}

    return {'type': 'python', 'main_file': 'main.py', 'framework': None}

# Common third-party import name -> pip package name, for projects that
# forgot (or never had) a requirements.txt. Only used when requirements.txt
# is missing — never overrides one the user actually provided.
_IMPORT_TO_PIP = {
    'flask': 'flask', 'fastapi': 'fastapi', 'uvicorn': 'uvicorn', 'django': 'django',
    'requests': 'requests', 'bs4': 'beautifulsoup4', 'PIL': 'pillow', 'cv2': 'opencv-python-headless',
    'numpy': 'numpy', 'pandas': 'pandas', 'yaml': 'pyyaml', 'dotenv': 'python-dotenv',
    'telebot': 'pyTelegramBotAPI', 'telegram': 'python-telegram-bot', 'aiogram': 'aiogram',
    'discord': 'discord.py', 'pymongo': 'pymongo', 'psycopg2': 'psycopg2-binary',
    'redis': 'redis', 'sqlalchemy': 'sqlalchemy', 'jinja2': 'jinja2', 'gunicorn': 'gunicorn',
    'aiohttp': 'aiohttp', 'httpx': 'httpx', 'pydantic': 'pydantic', 'websockets': 'websockets',
    'selenium': 'selenium', 'openai': 'openai', 'anthropic': 'anthropic', 'jwt': 'pyjwt',
    'dateutil': 'python-dateutil', 'bcrypt': 'bcrypt', 'passlib': 'passlib', 'lxml': 'lxml',
}
_IMPORT_RE = re.compile(r'^\s*(?:import|from)\s+([a-zA-Z0-9_]+)', re.MULTILINE)

def guess_requirements(proj_dir):
    """Scan .py files for top-level imports and propose pip packages for the
    non-stdlib ones we recognize. Best effort — written to requirements.txt
    ONLY when the project didn't already ship one."""
    stdlib = getattr(sys, 'stdlib_module_names', set())
    found = set()
    for path in _walk_top_levels(proj_dir):
        if not path.endswith('.py') or os.path.basename(path) == '_bimo_run.py':
            continue
        try:
            with open(path, 'r', errors='ignore') as f:
                text = f.read()
        except OSError:
            continue
        for m in _IMPORT_RE.finditer(text):
            mod = m.group(1)
            if mod in stdlib or mod in ('__future__',):
                continue
            pkg = _IMPORT_TO_PIP.get(mod)
            if pkg:
                found.add(pkg)
    return sorted(found)

def venv_python(proj_dir):
    return os.path.join(proj_dir, 'venv', 'bin', 'python3')

def build_env(proj_dir, proj_type, port, env_vars):
    env = os.environ.copy()
    env['PORT'] = str(port)
    env.update(parse_env(env_vars))
    if proj_type == 'python':
        vbin = os.path.join(proj_dir, 'venv', 'bin')
        env['PATH'] = vbin + os.pathsep + env.get('PATH', '')
        env['VIRTUAL_ENV'] = os.path.join(proj_dir, 'venv')
    return env

def resolve_cmd(proj_dir, proj_type, main_file, port, start_cmd=None, framework=None):
    """Build the argv list used to launch the project. A custom start_cmd
    (advanced users) always wins; otherwise use sane per-type/per-framework defaults."""
    if start_cmd:
        return ['/bin/sh', '-c', start_cmd]
    if proj_type == 'python' and framework == 'django':
        return [venv_python(proj_dir), 'manage.py', 'runserver', f'0.0.0.0:{port}', '--noreload']
    main_file = main_file or {'python': 'main.py', 'node': 'index.js', 'php': 'index.php', 'go': 'main.go'}.get(proj_type, 'main.py')
    if proj_type == 'python':
        return [venv_python(proj_dir), os.path.join(proj_dir, '_bimo_run.py'), main_file]
    if proj_type == 'node':
        return ['node', main_file]
    if proj_type == 'php':
        return ['php', '-S', f'0.0.0.0:{port}', main_file]
    if proj_type == 'static':
        return [sys.executable, '-m', 'http.server', str(port), '--directory', proj_dir, '--bind', '0.0.0.0']
    if proj_type == 'go':
        return [os.path.join(proj_dir, '_sk7_go_bin')]
    return [venv_python(proj_dir), os.path.join(proj_dir, '_bimo_run.py'), main_file]

_DANGEROUS_CMD_PATTERNS = [
    (re.compile(r'\brm\s+(-\w*r\w*f\w*|-\w*f\w*r\w*)\s+/(\s|$)'), 'حذف جذر النظام'),
    (re.compile(r'\bmkfs\b'), 'تهيئة قرص'),
    (re.compile(r'\bdd\s+.*of=/dev/(sd|nvme|vd)'), 'كتابة مباشرة على قرص النظام'),
    (re.compile(r':\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:'), 'fork bomb'),
    (re.compile(r'\b(shutdown|reboot|poweroff|halt)\b'), 'إيقاف/إعادة تشغيل السيرفر'),
    (re.compile(r'\biptables\s+.*-F\b'), 'مسح قواعد الجدار الناري'),
    (re.compile(r'>\s*/dev/sd[a-z]'), 'الكتابة فوق قرص النظام'),
    (re.compile(r'\bchmod\s+-R\s+777\s+/(\s|$)'), 'تغيير صلاحيات جذر النظام'),
    (re.compile(r'\bcat\s+/etc/(shadow|sudoers)\b'), 'قراءة ملفات نظام حساسة'),
]

def is_dangerous_command(cmd):
    for pattern, why in _DANGEROUS_CMD_PATTERNS:
        if pattern.search(cmd):
            return True, why
    return False, None

_PKG_PATTERNS = [
    (re.compile(r"ModuleNotFoundError: No module named '([\w\-.]+)'"), 'pip'),
    (re.compile(r"ImportError: No module named ([\w\-.]+)"), 'pip'),
    (re.compile(r"Cannot find module '([\w\-@/.]+)'"), 'npm'),
    (re.compile(r"sh: \d+: (\S+): not found"), 'apt'),
    (re.compile(r"(?:php|Fatal error): .*?require\(.*?'([\w\-/.]+)'"), None),
]

def detect_missing_package(pid):
    """Scan a project's actual process output (run.log) for a missing-dependency
    signature so the UI can surface 'مكتبة ناقصة: X' with a one-click install
    instead of a raw traceback."""
    info = PROCESSES.get(pid, {})
    log_path = info.get('log_file')
    text = ''
    if log_path and os.path.exists(log_path):
        try:
            with open(log_path, 'r', errors='replace') as f:
                text = f.read()[-6000:]
        except OSError:
            pass
    if not text:
        text = '\n'.join(info.get('log', [])[-40:])
    for pattern, kind in _PKG_PATTERNS:
        m = pattern.search(text)
        if m and kind:
            return {"package": m.group(1), "installer": kind}
    return None

def _append_log(pid, msg):
    info = PROCESSES.get(pid)
    if info is not None:
        info.setdefault('log', []).append(f"[{now()}] {msg}")

def kill_process(pid):
    """Terminate the whole process group for a project (kills child procs too, e.g. npm->node)."""
    info = PROCESSES.get(pid)
    if not info or not info.get('proc'):
        return
    proc = info['proc']
    if proc.poll() is not None:
        return
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
        for _ in range(20):
            if proc.poll() is not None:
                break
            time.sleep(0.25)
        if proc.poll() is None:
            os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass

PROJECT_MEM_LIMIT_MB = int(os.environ.get('SK7_PROJECT_MEM_MB', 768))
PROJECT_NPROC_LIMIT = int(os.environ.get('SK7_PROJECT_NPROC', 64))

def _limit_project_resources():
    """Runs inside the child right after fork (POSIX only). Without container
    isolation this is a safety net, not a sandbox — it stops one runaway
    project (memory leak, fork bomb) from taking the whole VPS down, but it
    does not isolate the filesystem, network, or users from each other."""
    if _resource is None:
        return
    try:
        mem_bytes = PROJECT_MEM_LIMIT_MB * 1024 * 1024
        _resource.setrlimit(_resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    except (ValueError, OSError):
        pass
    try:
        _resource.setrlimit(_resource.RLIMIT_NPROC, (PROJECT_NPROC_LIMIT, PROJECT_NPROC_LIMIT))
    except (ValueError, OSError):
        pass

def start_process(pid, proj_dir, port, proj_type, main_file, env_vars, start_cmd=None, framework=None):
    """Launch (or relaunch) the actual project process. Assumes deps are already installed."""
    log_path = os.path.join(proj_dir, 'run.log')
    logf = open(log_path, 'a', buffering=1)
    cmd = resolve_cmd(proj_dir, proj_type, main_file, port, start_cmd, framework)
    env = build_env(proj_dir, proj_type, port, env_vars)
    try:
        proc = subprocess.Popen(cmd, cwd=proj_dir, stdout=logf, stderr=subprocess.STDOUT,
                                 env=env, start_new_session=True,
                                 preexec_fn=_limit_project_resources if _resource else None)
    except FileNotFoundError as e:
        _append_log(pid, f"❌ فشل التشغيل: {e}")
        PROCESSES[pid]['status'] = 'error'
        PROCESSES[pid]['error'] = str(e)
        return
    PROCESSES[pid].update({
        'proc': proc, 'status': 'running', 'error': None, 'log_file': log_path,
        'cmd': cmd, 'env': env, 'cwd': proj_dir, 'desired': 'running',
        'started_at': time.time(), 'restart_count': 0, 'restart_window_start': time.time(),
    })
    _append_log(pid, f"🚀 السيرفر شغال (PID {proc.pid}) على المنفذ {port}")

def build_and_run(project_id, proj_dir, port, proj_type, main_file, env_vars, start_cmd=None, framework=None):
    """Install deps (in a background thread) then launch the process."""
    pid_info = PROCESSES[project_id]
    pid_info['status'] = 'building'
    pid_info['log'].append(f"[{now()}] 🏗️  تجهيز البيئة...")

    # Environment variables also go to a .env file (for python-dotenv / dotenv-node
    # based projects that call load_dotenv() themselves, in addition to being
    # passed as real process env vars either way).
    if env_vars and env_vars.strip():
        try:
            with open(os.path.join(proj_dir, '.env'), 'w') as f:
                f.write(env_vars)
        except OSError:
            pass

    def run_cmd(cmd_list, log_prefix=''):
        proc = subprocess.run(cmd_list, cwd=proj_dir, capture_output=True, text=True)
        out = (proc.stdout or '') + (proc.stderr or '')
        for l in out.strip().split('\n')[-20:]:
            if l.strip():
                pid_info['log'].append(f"[{now()}] {log_prefix}{l}")
        return proc.returncode

    if not start_cmd:
        if proj_type == 'python':
            with open(os.path.join(proj_dir, '_bimo_run.py'), 'w') as f:
                f.write(BIMO_RUNNER.format(port=port))
            venv_dir = os.path.join(proj_dir, 'venv')
            if not os.path.exists(venv_python(proj_dir)):
                pid_info['log'].append(f"[{now()}] 🐍 إنشاء بيئة Python افتراضية...")
                rc = run_cmd([sys.executable, '-m', 'venv', venv_dir], 'VENV: ')
                if rc != 0:
                    pid_info['status'] = 'error'
                    pid_info['error'] = '\n'.join(pid_info['log'][-15:])
                    return
            req = os.path.join(proj_dir, 'requirements.txt')
            if not os.path.exists(req):
                guessed = guess_requirements(proj_dir)
                if guessed:
                    with open(req, 'w') as f:
                        f.write('\n'.join(guessed))
                    pid_info['log'].append(f"[{now()}] 🔍 ما فيه requirements.txt — خمّنّا المكتبات من الاستيرادات: {', '.join(guessed)}")
            if os.path.exists(req):
                pid_info['log'].append(f"[{now()}] 📦 تثبيت المكتبات (pip)...")
                pip = os.path.join(venv_dir, 'bin', 'pip')
                rc = run_cmd([pip, 'install', '-q', '--no-cache-dir', '-r', req], 'PIP: ')
                if rc != 0:
                    pid_info['log'].append(f"[{now()}] ⚠️ بعض المكتبات فشل تثبيتها — راجع السجل، قد يعمل المشروع جزئياً")
            if framework == 'django':
                pid_info['log'].append(f"[{now()}] 🗄️  Django: تطبيق migrate...")
                py = venv_python(proj_dir)
                run_cmd([py, 'manage.py', 'migrate', '--noinput'], 'DJANGO: ')
        elif proj_type == 'node':
            if os.path.exists(os.path.join(proj_dir, 'package.json')):
                pid_info['log'].append(f"[{now()}] 📦 تثبيت المكتبات (npm)...")
                rc = run_cmd(['npm', 'install', '--omit=dev'], 'NPM: ')
                if rc != 0:
                    pid_info['log'].append(f"[{now()}] ⚠️ فشل npm install — راجع السجل")
        elif proj_type == 'php':
            if os.path.exists(os.path.join(proj_dir, 'composer.json')) and shutil.which('composer'):
                pid_info['log'].append(f"[{now()}] 📦 تثبيت المكتبات (composer)...")
                run_cmd(['composer', 'install', '--no-dev'], 'COMPOSER: ')
        elif proj_type == 'go':
            if not shutil.which('go'):
                pid_info['status'] = 'error'
                pid_info['error'] = 'Go غير مثبت على السيرفر — راجع install.sh'
                pid_info['log'].append(f"[{now()}] ❌ Go غير مثبت على هذا السيرفر")
                return
            pid_info['log'].append(f"[{now()}] 🛠️  بناء مشروع Go (go build)...")
            bin_path = os.path.join(proj_dir, '_sk7_go_bin')
            genv = os.environ.copy(); genv['CGO_ENABLED'] = '0'
            rc = run_cmd(['go', 'build', '-o', bin_path, '.'], 'GO BUILD: ')
            if rc != 0:
                pid_info['status'] = 'error'
                pid_info['error'] = '\n'.join(pid_info['log'][-15:])
                pid_info['log'].append(f"[{now()}] ❌ فشل بناء مشروع Go")
                return
            os.chmod(bin_path, 0o755)

    pid_info['status'] = 'starting'
    pid_info['log'].append(f"[{now()}] ▶️  جاري التشغيل على المنفذ {port}...")
    if pid_info.get('desired') == 'stopped':
        pid_info['status'] = 'stopped'
        pid_info['log'].append(f"[{now()}] ⏹️  تم إلغاء التشغيل (تم طلب الإيقاف أثناء التجهيز)")
        return
    start_process(project_id, proj_dir, port, proj_type, main_file, env_vars, start_cmd, framework)

# ─── WATCHDOG — keeps hosted projects alive 24/7 ─────
def _watchdog_loop():
    while True:
        time.sleep(5)
        for pid, info in list(PROCESSES.items()):
            if info.get('desired') != 'running':
                continue
            proc = info.get('proc')
            if proc is None or proc.poll() is None:
                continue  # still running or never started yet (still building)
            if info.get('status') in ('building', 'starting'):
                continue
            # process died unexpectedly — restart with simple flood protection
            win_start = info.get('restart_window_start', 0)
            if time.time() - win_start > 60:
                info['restart_window_start'] = time.time()
                info['restart_count'] = 0
            info['restart_count'] = info.get('restart_count', 0) + 1
            if info['restart_count'] > 8:
                info['status'] = 'error'
                info['error'] = 'توقف السيرفر بشكل متكرر — تم إيقاف إعادة التشغيل التلقائي'
                _append_log(pid, "❌ تكرار الأعطال — أوقفنا إعادة التشغيل التلقائي، افحص السجل وشغّله يدوياً")
                info['desired'] = 'crashed'
                continue
            _append_log(pid, f"⚠️  توقف السيرفر (exit code {proc.returncode}) — إعادة التشغيل تلقائياً...")
            proj = DB['projects'].get(pid)
            if not proj:
                continue
            start_process(pid, proj['dir'], proj['port'], proj['type'], proj.get('main_file'),
                          proj.get('env', ''), proj.get('start_cmd'), proj.get('framework'))

_watchdog_thread = threading.Thread(target=_watchdog_loop, daemon=True)
_watchdog_thread.start()

def resume_projects_on_boot():
    """Called once at process start — relaunches any project that was running
    before the panel itself was restarted (systemd restart, VPS reboot, etc)."""
    for pid, proj in DB['projects'].items():
        if proj.get('desired_state') == 'running':
            PROCESSES[pid] = {"status": "queued", "port": proj['port'], "log": [f"[{now()}] 🔄 استئناف بعد إعادة تشغيل اللوحة..."],
                               "error": None, "desired": "running", "started_at": None}
            t = threading.Thread(target=build_and_run, args=(pid, proj['dir'], proj['port'], proj['type'],
                                  proj.get('main_file'), proj.get('env', ''), proj.get('start_cmd'), proj.get('framework')), daemon=True)
            t.start()

MAX_RUNNING_PER_USER = 8  # regular users; dev/admin unlimited — keeps one account from exhausting the VPS

@app.route('/api/deploy', methods=['POST'])
@login_required
def api_deploy():
    u = current_user()
    data = request.form
    files = request.files.getlist('files')
    project_name = (data.get('name') or '').strip()
    proj_type = (data.get('type') or 'auto').strip()
    env_vars = data.get('env','')
    start_cmd = data.get('start_cmd','').strip()
    main_file = data.get('main_file','').strip()

    if not project_name:
        return jsonify({"error":"أدخل اسم المشروع"}),400
    if not files or not any(f.filename for f in files):
        return jsonify({"error":"ارفع ملفات أولاً"}),400

    # check file limit
    current_count = len(u.get('files',[]))
    if current_count + len(files) > u['file_limit']:
        return jsonify({"error":f"تجاوزت الحد الأقصى ({u['file_limit']} ملف)"}),400

    # concurrency cap — protects the VPS from one account launching unlimited processes
    if u['role'] == 'user':
        active = sum(1 for pid, proj in DB['projects'].items()
                     if proj.get('owner') == u['username'] and PROCESSES.get(pid, {}).get('status') in
                     ('running', 'building', 'starting', 'queued'))
        if active >= MAX_RUNNING_PER_USER:
            return jsonify({"error": f"وصلت للحد الأقصى من المشاريع الشغالة بنفس الوقت ({MAX_RUNNING_PER_USER}) — أوقف مشروع آخر أولاً"}), 400

    project_id = str(uuid.uuid4())[:8]
    port = next_port()
    proj_dir = os.path.join(PROJECTS_DIR, project_id)
    os.makedirs(proj_dir, exist_ok=True)

    saved_files = []
    for f in files:
        if f.filename:
            fname = secure_filename(f.filename)
            dest = os.path.join(proj_dir, fname)
            f.save(dest)
            size = os.path.getsize(dest)
            saved_files.append({"name":fname,"size":size})
            # track in user files too
            if 'files' not in u: u['files']=[]
            u['files'].append({"name":fname,"size":size,"date":datetime.now().strftime('%Y-%m-%d %H:%M'),"path":dest,"project":project_id})

    # Extract archives so projects with subfolders actually work (they were
    # previously just copied as a raw .zip/.tar.gz into the image, which never runs)
    import zipfile, tarfile
    def _safe_members(names, base):
        """Reject any archive entry that would extract outside `base` (zip-slip protection)."""
        base = os.path.realpath(base)
        for n in names:
            target = os.path.realpath(os.path.join(base, n))
            if not (target == base or target.startswith(base + os.sep)):
                raise ValueError(f"مسار غير آمن داخل الأرشيف: {n}")

    for sf in list(saved_files):
        archive_path = os.path.join(proj_dir, sf['name'])
        lower = sf['name'].lower()
        try:
            if lower.endswith('.zip') and zipfile.is_zipfile(archive_path):
                with zipfile.ZipFile(archive_path) as zf:
                    _safe_members(zf.namelist(), proj_dir)
                    zf.extractall(proj_dir)
                os.remove(archive_path)
            elif lower.endswith(('.tar.gz', '.tgz', '.tar')) and tarfile.is_tarfile(archive_path):
                with tarfile.open(archive_path) as tf:
                    _safe_members([m.name for m in tf.getmembers()], proj_dir)
                    tf.extractall(proj_dir)
                os.remove(archive_path)
        except Exception:
            pass  # keep the raw archive if extraction fails; build will just fail loudly instead of silently

    # If extraction left a single wrapping folder (common with GitHub zip
    # downloads / exported projects), flatten it so main_file paths resolve.
    entries = [e for e in os.listdir(proj_dir) if not e.startswith('.')]
    if len(entries) == 1 and os.path.isdir(os.path.join(proj_dir, entries[0])):
        wrapper = os.path.join(proj_dir, entries[0])
        for item in os.listdir(wrapper):
            shutil.move(os.path.join(wrapper, item), os.path.join(proj_dir, item))
        os.rmdir(wrapper)

    # Auto-detect type / entry file / framework (Railway-style "just works" flow).
    # A type the user explicitly picked always wins; 'auto' (the default) or a
    # blank main_file get filled in from what's actually in the upload.
    detected = detect_project(proj_dir)
    detect_note = None
    if proj_type == 'auto':
        proj_type = detected['type']
        if not main_file:
            main_file = detected['main_file']
        detect_note = f"🔍 تم اكتشاف المشروع تلقائياً: {proj_type}" + (f" ({detected['framework']})" if detected['framework'] else "") + f" — ملف التشغيل: {main_file}"
    elif not main_file and proj_type == detected['type']:
        main_file = detected['main_file']
    framework = detected['framework'] if proj_type == detected['type'] else None
    if not main_file:
        main_file = {'python':'main.py','node':'index.js','php':'index.php','go':'main.go'}.get(proj_type,'main.py')

    # Save project info
    proj_info = {
        "id": project_id,
        "name": project_name,
        "type": proj_type,
        "framework": framework,
        "port": port,
        "owner": u['username'],
        "created_at": time.time(),
        "files": [f['name'] for f in saved_files],
        "env": env_vars,
        "main_file": main_file,
        "start_cmd": start_cmd or None,
        "dir": proj_dir,
        "desired_state": "running",
    }
    DB['projects'][project_id] = proj_info
    save_db(DB)

    # Init process tracker
    init_log = [f"[{now()}] 📦 استلام {len(saved_files)} ملف..."]
    if detect_note:
        init_log.append(f"[{now()}] {detect_note}")
    PROCESSES[project_id] = {
        "status": "queued",
        "port": port,
        "log": init_log,
        "error": None,
        "desired": "running",
        "started_at": None,
    }

    # Install deps & run in background
    t = threading.Thread(target=build_and_run, args=(project_id, proj_dir, port, proj_type, main_file, env_vars, start_cmd or None, framework), daemon=True)
    t.start()

    return jsonify({"ok":True,"project_id":project_id,"port":port,"name":project_name,"detected_type":proj_type,"detected_main_file":main_file,"framework":framework})

@app.route('/api/projects', methods=['GET'])
@login_required
def api_projects():
    u = current_user()
    projects = []
    for pid, proj in DB['projects'].items():
        if u['role'] in ('dev','admin') or proj['owner']==u['username']:
            proc = PROCESSES.get(pid, {})
            # real docker status
            status = proc.get('status','unknown')
            error  = proc.get('error','')
            if status == 'running':
                p = proc.get('proc')
                if p is None or p.poll() is not None:
                    status = 'stopped'
                    proc['status'] = 'stopped'
            mem = None
            p = proc.get('proc')
            if status == 'running' and p is not None:
                try:
                    with open(f'/proc/{p.pid}/status') as fh:
                        for line in fh:
                            if line.startswith('VmRSS:'):
                                mem = round(int(line.split()[1]) / 1024, 1)
                                break
                except (FileNotFoundError, ProcessLookupError):
                    pass
            reachable = None
            if status == 'running':
                reachable, _ = _probe_project(proj['port'], timeout=1.2)
            projects.append({
                "id": pid,
                "name": proj['name'],
                "type": proj['type'],
                "port": proj['port'],
                "owner": proj['owner'],
                "status": status,
                "error": error,
                "files": proj.get('files',[]),
                "created_at": proj.get('created_at',0),
                "log": proc.get('log',[])[-30:],
                "mem_mb": mem,
                "missing_package": detect_missing_package(pid) if status in ('error','stopped') else None,
                "reachable": reachable,
                "proxy_path": f"/app/{pid}/",
            })
    projects.sort(key=lambda x: x['created_at'], reverse=True)
    return jsonify({"projects":projects})

@app.route('/api/projects/<pid>/status')
@login_required
def api_project_status(pid):
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403
    proc = PROCESSES.get(pid,{})
    status = proc.get('status','unknown')
    cpu, mem = '-', '-'
    p = proc.get('proc')
    if status == 'running' and p is not None and p.poll() is None:
        try:
            with open(f'/proc/{p.pid}/status') as f:
                for line in f:
                    if line.startswith('VmRSS:'):
                        mem = f"{int(line.split()[1]) / 1024:.1f} MB"
                        break
        except (FileNotFoundError, ProcessLookupError):
            pass
    return jsonify({
        "status": status,
        "error": proc.get('error',''),
        "log": proc.get('log',[])[-50:],
        "port": proj.get('port',0),
        "cpu": cpu,
        "mem": mem,
    })

@app.route('/api/projects/<pid>/health')
@login_required
def api_project_health(pid):
    """On-demand real check — used right before opening a project's link, so we
    never hand the user a URL that we haven't actually verified responds."""
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403
    proc = PROCESSES.get(pid, {})
    if proc.get('status') != 'running':
        return jsonify({"reachable": False, "reason": "stopped"})
    ok, code = _probe_project(proj['port'], timeout=4)
    return jsonify({"reachable": ok, "status_code": code})

@app.route('/api/projects/<pid>/start', methods=['POST'])
@login_required
def api_start(pid):
    proj = DB['projects'].get(pid)
    if not proj: return jsonify({"error":"not found"}),404
    u = current_user()
    if u['role']=='user' and proj['owner']!=u['username']:
        return jsonify({"error":"forbidden"}),403
    proj['desired_state'] = 'running'
    save_db(DB)
    if pid not in PROCESSES:
        PROCESSES[pid] = {"status":"queued","port":proj['port'],"log":[],"error":None,"desired":"running","started_at":None}
    info = PROCESSES[pid]
    p = info.get('proc')
    if p is not None and p.poll() is None:
        return jsonify({"ok":True})  # already running
    # (re)install deps if needed and launch — cheap if venv/node_modules already exist
    info['status'] = 'queued'
    info['desired'] = 'running'
    info.setdefault('log', []).append(f"[{now()}] 🔄 جاري التشغيل...")
    t = threading.Thread(target=build_and_run, args=(pid, proj['dir'], proj['port'], proj['type'], proj.get('main_file','main.py'), proj.get('env',''), proj.get('start_cmd'), proj.get('framework')), daemon=True)
    t.start()
    return jsonify({"ok":True,"starting":True})

@app.route('/api/projects/<pid>/stop', methods=['POST'])
@login_required
def api_stop(pid):
    proj = DB['projects'].get(pid)
    if not proj: return jsonify({"error":"not found"}),404
    proj['desired_state'] = 'stopped'
    save_db(DB)
    if pid in PROCESSES:
        PROCESSES[pid]['desired'] = 'stopped'
        kill_process(pid)
        PROCESSES[pid]['status']='stopped'
        PROCESSES[pid]['log'].append(f"[{now()}] ⏹️  تم الإيقاف")
    return jsonify({"ok":True})

@app.route('/api/projects/<pid>/restart', methods=['POST'])
@login_required
def api_restart(pid):
    api_stop(pid)
    time.sleep(1)
    return api_start(pid)

@app.route('/api/projects/<pid>/exec', methods=['POST'])
@login_required
def api_exec(pid):
    """Run a command inside the project's running container (e.g. pip install X, npm install X)."""
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403

    cmd = (request.json or {}).get('cmd', '').strip()
    if not cmd:
        return jsonify({"error": "أدخل أمر"}), 400

    danger, why = is_dangerous_command(cmd)
    if danger:
        return jsonify({"error": f"🚫 هذا الأمر محظور: {why}"}), 403

    # NOTE: there's no container here — this runs directly on the host, scoped
    # to the project's own folder (and Python venv, if any) via cwd, but the
    # shell itself is NOT sandboxed (no filesystem/network isolation).
    proj_dir = proj.get('dir')
    env = build_env(proj_dir, proj['type'], proj['port'], proj.get('env', ''))
    try:
        r = subprocess.run(
            ["/bin/sh", "-c", cmd],
            cwd=proj_dir, env=env, capture_output=True, text=True, timeout=180,
            preexec_fn=_limit_project_resources if _resource else None,
        )
        output = (r.stdout or '') + (r.stderr or '')
        PROCESSES.get(pid, {}).setdefault('log', []).append(f"[{now()}] 💻 $ {cmd}")
        return jsonify({"ok": True, "exit_code": r.returncode, "output": output[-8000:]})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "انتهت المهلة (180 ثانية) — الأمر طويل جداً"}), 408

@app.route('/api/projects/<pid>/install', methods=['POST'])
@login_required
def api_install(pid):
    """One-click 'مكتبة ناقصة؟' fix — installs a package with the right tool for the
    project type (pip for python venv, npm for node) and optionally restarts the project."""
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403

    body = request.json or {}
    package = (body.get('package') or '').strip()
    if not package or not re.match(r'^[\w\-.@/]+$', package):
        return jsonify({"error": "اسم مكتبة غير صالح"}), 400

    proj_dir = proj.get('dir')
    proj_type = proj['type']
    if proj_type == 'python':
        pip = os.path.join(proj_dir, 'venv', 'bin', 'pip')
        if not os.path.exists(pip):
            return jsonify({"error": "لم يتم إنشاء بيئة Python بعد — انتظر انتهاء أول تشغيل"}), 400
        cmd = [pip, 'install', '-q', '--no-cache-dir', package]
    elif proj_type == 'node':
        cmd = ['npm', 'install', package]
    else:
        return jsonify({"error": "التثبيت التلقائي متاح فقط لمشاريع Python وNode حالياً"}), 400

    r = subprocess.run(cmd, cwd=proj_dir, capture_output=True, text=True, timeout=180)
    ok = r.returncode == 0
    out = ((r.stdout or '') + (r.stderr or ''))[-4000:]
    PROCESSES.setdefault(pid, {}).setdefault('log', []).append(
        f"[{now()}] {'📦 ثبّتنا' if ok else '❌ فشل تثبيت'} {package}"
    )
    if ok and body.get('restart', True):
        api_stop(pid)
        time.sleep(0.5)
        api_start(pid)
    return jsonify({"ok": ok, "output": out})

@app.route('/api/projects/<pid>/logs')
@login_required
def api_logs(pid):
    proj = DB['projects'].get(pid)
    if not proj:
        return jsonify({"error": "not found"}), 404
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return jsonify({"error": "forbidden"}), 403
    proc = PROCESSES.get(pid,{})
    proc_log = []
    log_path = proc.get('log_file') or os.path.join(proj.get('dir',''), 'run.log')
    try:
        with open(log_path, 'r', errors='replace') as f:
            proc_log = f.readlines()[-50:]
    except FileNotFoundError:
        pass
    return jsonify({"log": proc.get('log',[]), "docker_log": [l.rstrip('\n') for l in proc_log]})

# ─── PER-PROJECT FILE MANAGER — browse/edit files inside a project's own
# folder from the dashboard, without needing SSH/terminal access ───
_FM_HIDDEN_DIRS = {'venv', 'node_modules', '__pycache__', '.git'}
_FM_MAX_EDIT_BYTES = 300 * 1024  # 300KB — bigger files are for download/terminal, not the inline editor
_FM_BINARY_EXTS = {'.pyc', '.so', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.pdf', '.zip', '.db', '.sqlite3'}

def _fm_resolve(proj_dir, rel_path):
    """Resolve a user-supplied relative path against proj_dir, refusing anything
    that would escape it (path traversal / symlink escape protection)."""
    base = os.path.realpath(proj_dir)
    target = os.path.realpath(os.path.join(base, rel_path or ''))
    if target != base and not target.startswith(base + os.sep):
        return None
    return target

def _fm_authorize(pid):
    proj = DB['projects'].get(pid)
    if not proj:
        return None, (jsonify({"error": "not found"}), 404)
    u = current_user()
    if u['role'] == 'user' and proj['owner'] != u['username']:
        return None, (jsonify({"error": "forbidden"}), 403)
    return proj, None

@app.route('/api/projects/<pid>/fs/list')
@login_required
def api_fm_list(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    rel = request.args.get('path', '')
    target = _fm_resolve(proj['dir'], rel)
    if target is None or not os.path.isdir(target):
        return jsonify({"error": "مسار غير صالح"}), 400
    entries = []
    for name in sorted(os.listdir(target)):
        if name in _FM_HIDDEN_DIRS or name.startswith('.'):
            continue
        full = os.path.join(target, name)
        try:
            st = os.stat(full)
            entries.append({"name": name, "is_dir": os.path.isdir(full), "size": st.st_size})
        except OSError:
            continue
    return jsonify({"path": rel, "entries": entries})

@app.route('/api/projects/<pid>/fs/read')
@login_required
def api_fm_read(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    rel = request.args.get('path', '')
    target = _fm_resolve(proj['dir'], rel)
    if target is None or not os.path.isfile(target):
        return jsonify({"error": "ملف غير موجود"}), 404
    if os.path.splitext(target)[1].lower() in _FM_BINARY_EXTS:
        return jsonify({"error": "ملف ثنائي — لا يمكن تحريره هنا"}), 400
    size = os.path.getsize(target)
    if size > _FM_MAX_EDIT_BYTES:
        return jsonify({"error": f"الملف كبير جداً للتحرير ({size//1024} KB) — استخدم التيرمنل"}), 400
    try:
        with open(target, 'r', errors='replace') as f:
            content = f.read()
    except OSError as e:
        return jsonify({"error": str(e)}), 500
    return jsonify({"path": rel, "content": content, "size": size})

@app.route('/api/projects/<pid>/fs/write', methods=['POST'])
@login_required
def api_fm_write(pid):
    proj, err = _fm_authorize(pid)
    if err: return err
    body = request.json or {}
    rel = body.get('path', '')
    content = body.get('content', '')
    if len(content.encode('utf-8', errors='ignore')) > _FM_MAX_EDIT_BYTES:
        return jsonify({"error": "المحتوى كبير جداً"}), 400
    target = _fm_resolve(proj['dir'], rel)
    if target is None:
        return jsonify({"error": "مسار غير صالح"}), 400
    if os.path.isdir(target):
        return jsonify({"error": "هذا مجلد وليس ملف"}), 400
    try:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'w') as f:
            f.write(content)
    except OSError as e:
        return jsonify({"error": str(e)}), 500
    PROCESSES.setdefault(pid, {}).setdefault('log', []).append(f"[{now()}] 📝 تم تعديل {rel}")
    return jsonify({"ok": True})

@app.route('/api/projects/<pid>', methods=['DELETE'])
@login_required
def api_delete_project(pid):
    proj = DB['projects'].get(pid)
    if not proj: return jsonify({"error":"not found"}),404
    u = current_user()
    if u['role']=='user' and proj['owner']!=u['username']:
        return jsonify({"error":"forbidden"}),403
    kill_process(pid)
    try: shutil.rmtree(proj.get('dir',''))
    except: pass
    PROCESSES.pop(pid,None)
    # remove files from user
    owner = get_user(proj['owner'])
    if owner:
        owner['files'] = [f for f in owner.get('files',[]) if f.get('project')!=pid]
    del DB['projects'][pid]
    save_db(DB)
    return jsonify({"ok":True})

# ─── USERS MANAGEMENT ────────────────────────────────
@app.route('/api/users', methods=['GET'])
@login_required
@role_required('dev','admin')
def api_users():
    u = current_user()
    users = []
    for usr in DB['users']:
        if u['role']=='admin' and usr['role']=='dev': continue
        exp = datetime.fromtimestamp(usr['created_at']) + timedelta(days=usr['days'])
        users.append({
            "username": usr['username'],
            "role": usr['role'],
            "file_limit": usr['file_limit'],
            "files_used": len(usr.get('files',[])),
            "days": usr['days'],
            "expires": exp.strftime('%Y-%m-%d'),
            "expired": datetime.now() > exp and usr['role']!='dev',
        })
    return jsonify({"users":users})

@app.route('/api/users', methods=['POST'])
@login_required
@role_required('dev','admin')
def api_create_user():
    u = current_user()
    data = request.json or {}
    username = data.get('username','').strip()
    password = data.get('password','') or gen_password()
    role = data.get('role','user')
    file_limit = int(data.get('file_limit',15))
    days = int(data.get('days',30))

    if not username:
        return jsonify({"error":"أدخل اسم المستخدم"}),400
    if get_user(username):
        return jsonify({"error":"اسم المستخدم موجود مسبقاً"}),400
    if u['role']=='admin' and role in ('dev',):
        role='user'
    if u['role']=='admin':
        file_limit = min(file_limit, 50)

    new_user = {"username":username,"password":hashpw(password),"role":role,"file_limit":file_limit,"days":days,"created_at":time.time(),"files":[]}
    DB['users'].append(new_user)
    save_db(DB)
    return jsonify({"ok":True,"username":username,"password":password,"role":role})

@app.route('/api/users/<username>', methods=['DELETE'])
@login_required
@role_required('dev','admin')
def api_delete_user(username):
    u = current_user()
    target = get_user(username)
    if not target: return jsonify({"error":"المستخدم غير موجود"}),404
    if username == u['username']: return jsonify({"error":"لا يمكنك حذف نفسك"}),400
    if u['role']=='admin' and target['role'] in ('dev','admin'): return jsonify({"error":"لا صلاحية"}),403
    DB['users'] = [x for x in DB['users'] if x['username']!=username]
    save_db(DB)
    return jsonify({"ok":True})

@app.route('/api/users/<username>/password', methods=['PUT'])
@login_required
@role_required('dev','admin')
def api_reset_password(username):
    target = get_user(username)
    if not target: return jsonify({"error":"غير موجود"}),404
    new_pw = gen_password()
    target['password'] = hashpw(new_pw)
    save_db(DB)
    return jsonify({"ok":True,"password":new_pw})

# ─── SYSTEM STATS ────────────────────────────────────
@app.route('/api/stats')
@login_required
def api_stats():
    # CPU / RAM via /proc
    try:
        with open('/proc/loadavg') as f: load = f.read().split()[0]
        with open('/proc/meminfo') as f:
            mem = {}
            for line in f:
                parts=line.split()
                if len(parts)>=2: mem[parts[0].rstrip(':')]=int(parts[1])
        total=mem.get('MemTotal',1); avail=mem.get('MemAvailable',0)
        ram_pct=round((1-avail/total)*100,1)
    except:
        load='0'; ram_pct=0
    # disk
    try:
        disk=shutil.disk_usage('/')
        disk_pct=round(disk.used/disk.total*100,1)
        disk_free=round(disk.free/1e9,1)
        disk_total=round(disk.total/1e9,1)
    except:
        disk_pct=0; disk_free=0; disk_total=0
    # live hosted processes (native, no Docker)
    containers=sum(1 for p in PROCESSES.values() if p.get('proc') is not None and p.get('proc').poll() is None)
    u=current_user()
    running = sum(1 for pid,p in PROCESSES.items() if p.get('status')=='running')
    errors  = sum(1 for pid,p in PROCESSES.items() if p.get('status')=='error')
    return jsonify({"load":load,"ram":ram_pct,"disk":disk_pct,"disk_free":disk_free,"disk_total":disk_total,"containers":containers,"running":running,"errors":errors,"users":len(DB['users']),"projects":len(DB['projects'])})

# ─── SETTINGS ────────────────────────────────────────
@app.route('/api/me/password', methods=['PUT'])
@login_required
def api_change_password():
    u = current_user()
    data = request.json or {}
    if u['password'] != hashpw(data.get('current','')):
        return jsonify({"error":"كلمة المرور الحالية خاطئة"}),400
    new = data.get('new','')
    if len(new)<6: return jsonify({"error":"كلمة المرور قصيرة جداً (6 أحرف على الأقل)"}),400
    u['password']=hashpw(new)
    save_db(DB)
    return jsonify({"ok":True})

resume_projects_on_boot()

if __name__=='__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
