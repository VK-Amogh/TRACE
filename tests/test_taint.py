"""Intra-procedural taint analysis: real flows are found, safe code stays quiet."""

from trace_engine.security.taint import analyze_js, analyze_python, analyze_source


def kinds(flows):
    return sorted({(f.kind, f.function) for f in flows})


def test_flask_sql_injection_via_fstring_variable():
    src = '''
from flask import request

@app.route("/search")
def search():
    term = request.args.get("q")
    sql = f"SELECT * FROM items WHERE name LIKE '%{term}%'"
    cur.execute(sql)
    return "ok"
'''
    flows = analyze_python(src)
    assert kinds(flows) == [("sql", "search")]
    f = flows[0]
    assert f.sink_line == 8 and f.source_line == 6
    assert f.source.startswith("request.args") and "term" in f.trail


def test_parameterized_query_is_clean():
    src = '''
@app.get("/u")
def u(name: str):
    cur.execute("SELECT * FROM users WHERE name = %s", (name,))
'''
    assert analyze_python(src) == []


def test_fastapi_typed_int_param_is_validated_but_str_is_not():
    safe = '''
@app.get("/items/{item_id}")
def get(item_id: int):
    db.execute(f"SELECT * FROM items WHERE id = {item_id}")
'''
    unsafe = safe.replace("item_id: int", "item_id")
    assert analyze_python(safe) == []
    assert kinds(analyze_python(unsafe)) == [("sql", "get")]


def test_sanitizer_and_guard_clean_taint():
    src = '''
@app.post("/a")
def a():
    uid = int(request.form["uid"])
    db.execute("SELECT %d" % uid)

@app.post("/b")
def b():
    uid = request.form["uid"]
    if not uid.isdigit():
        abort(400)
    db.execute("SELECT " + uid)

@app.post("/c")
def c():
    uid = request.form["uid"]
    if uid.isdigit():
        db.execute("SELECT " + uid)

@app.post("/d")
def d():
    uid = request.form["uid"]
    db.execute("SELECT " + uid)
'''
    assert kinds(analyze_python(src)) == [("sql", "d")]


def test_command_ssrf_path_deserialization_ssti_redirect_sinks():
    src = '''
@app.route("/x")
def x():
    host = request.args["host"]
    os.system("ping " + host)
    subprocess.run(["ping", host])
    subprocess.run("ping " + host, shell=True)
    requests.get(request.args["u"])
    requests.get("https://api.example.com/v1/" + request.args["id"])
    open(request.args["f"])
    pickle.loads(request.get_data())
    return render_template_string("<p>" + request.args["n"])

@app.route("/r")
def r():
    return redirect(request.args.get("next"))
'''
    got = sorted(f.kind for f in analyze_python(src))
    assert got == ["command", "command", "deserialization", "path", "redirect", "ssrf", "ssti"]


def test_path_containment_guard_suppresses_traversal():
    src = '''
@app.get("/f")
def f():
    p = (BASE / request.args["name"]).resolve()
    if not p.is_relative_to(BASE):
        abort(400)
    return open(p).read()
'''
    assert analyze_python(src) == []


def test_undecorated_helper_params_are_unknown_not_tainted():
    src = '''
def helper(conn, uid):
    conn.execute(f"SELECT {uid}")
'''
    assert analyze_python(src) == []


def test_django_view_and_class_based_view():
    src = '''
def view(request, pk):
    cursor.execute("SELECT * FROM t WHERE id=" + pk)

class V:
    def get(self, request):
        q = request.GET["q"]
        cursor.execute("SELECT '%s'" % q)
'''
    assert [f.function for f in analyze_python(src)] == ["view", "get"]


def test_yaml_load_requires_safe_loader():
    src = '''
@app.post("/y")
def y():
    a = yaml.load(request.data)
    b = yaml.load(request.data, Loader=yaml.SafeLoader)
'''
    flows = analyze_python(src)
    assert len(flows) == 1 and flows[0].sink_line == 4


def test_syntax_errors_do_not_raise():
    assert analyze_python("def broken(:\n") == []
    assert analyze_source("x", "go") == []


def test_express_sql_template_literal_and_destructuring():
    src = '''
app.get('/items', async (req, res) => {
  const { name, limit } = req.query;
  const rows = await db.query(`SELECT * FROM items WHERE name = '${name}'`);
  res.json(rows);
});

app.get('/safe', (req, res) => {
  db.query('SELECT * FROM items WHERE id = $1', [req.params.id]);
  const n = parseInt(req.query.n);
  db.query(`SELECT ${n}`);
});
'''
    flows = analyze_js(src)
    assert [(f.kind, f.sink_line) for f in flows] == [("sql", 4)]
    assert flows[0].source.startswith("req.query")


def test_express_other_sinks_and_pinned_ssrf():
    src = '''
router.post('/run', (req, res) => {
  exec('ls ' + req.body.dir);
  const target = req.body.url;
  fetch(target);
  fetch(`https://api.example.com/users/${req.body.id}`);
  fs.readFile(req.query.file, cb);
  res.redirect(req.query.next);
  eval(req.body.code);
});
'''
    assert sorted(f.kind for f in analyze_js(src)) == ["code", "command", "path", "redirect", "ssrf"]


def test_analyze_source_dispatches_by_language():
    py = '@app.get("/p")\ndef p():\n    os.system(request.args["c"])\n'
    assert analyze_source(py, "python")
    assert analyze_source("app.get('/', (req,res)=>{ eval(req.query.c) })", "typescript")


def test_hypotheses_use_taint_flows_regardless_of_route_name(tmp_path):
    from trace_engine.apm.model import AttackPathModel
    from trace_engine.framework.base import Endpoint
    from trace_engine.parsing.locations import SourceLocation
    from trace_engine.security.hypotheses import HypothesisEngine, VulnerabilityCategory

    app = tmp_path / "app.py"
    app.write_text(
        'from flask import request\n\n'
        '@app.route("/lookup")\n'
        'def lookup():\n'
        '    name = request.args.get("name")\n'
        '    cur.execute("SELECT * FROM t WHERE n = \'" + name + "\'")\n'
        '    return "ok"\n\n'
        '@app.route("/other")\n'
        'def other():\n'
        '    return "static"\n',
        encoding="utf-8",
    )

    def ep(i, path, handler, line):
        return Endpoint(id=i, method="GET", path=path, handler_name=handler,
                        source=SourceLocation(file=str(app), line_start=line, line_end=line))

    eps = [ep("e1", "/lookup", "lookup", 3), ep("e2", "/other", "other", 9)]
    engine = HypothesisEngine()
    on = engine.derive_hypotheses(AttackPathModel("t"), eps)
    inj = [h for h in on if h.category == VulnerabilityCategory.INJECTION]
    assert [h.endpoint_display for h in inj] == ["GET /lookup"]
    assert "Tainted data flow" in inj[0].static_evidence[0]
    assert inj[0].source_location.line_start == 6
    off = engine.derive_hypotheses(AttackPathModel("t"), eps, use_taint=False)
    assert not [h for h in off if h.category == VulnerabilityCategory.INJECTION]
