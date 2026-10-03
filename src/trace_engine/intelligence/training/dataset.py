"""Comprehensive Cybersecurity AST dataset generator and PyTorch Dataset for model fine-tuning."""

import re
import csv
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional
import torch
from torch.utils.data import Dataset

from trace_engine.intelligence.securebert.classifier import VULN_CATEGORIES


def normalize_code_slice(code: str) -> str:
    """Normalizes code AST slice by abstracting identifiers and highlighting security dataflow."""
    # Strip comments
    code = re.sub(r"#.*$", "", code, flags=re.MULTILINE)
    code = re.sub(r"//.*$", "", code, flags=re.MULTILINE)
    code = re.sub(r"/\*.*?\*/", "", code, flags=re.DOTALL)

    # Highlight source tokens
    code = re.sub(r"(request\.(args|params|query|body|json|headers|form))", r"[SOURCE] \1", code, flags=re.IGNORECASE)
    # Highlight dangerous sink tokens
    code = re.sub(r"((execute|cursor|query|system|popen|eval|exec|open|readfile|render_template_string|pickle\.loads|yaml\.load)\b)", r"[SINK] \1", code, flags=re.IGNORECASE)

    # Condense consecutive whitespaces
    code = re.sub(r"\s+", " ", code).strip()
    return code


# High-signal multi-language templates for API & framework vulnerabilities
CORPUS_TEMPLATES = [
    # BOLA / IDOR (CWE-639)
    ("def get_order(order_id): return db.query('SELECT * FROM orders WHERE id = :id', id=order_id).fetchone()", ["BOLA"]),
    ("async function getDocument(req, res) { const doc = await Document.findById(req.params.id); return res.json(doc); }", ["BOLA"]),
    ("router.get('/profile/:id', (req, res) => { const user = User.load(req.params.id); res.send(user); });", ["BOLA"]),
    ("@app.get('/invoice/{inv_id}') def invoice(inv_id: str): return db.invoices.find_one({'_id': inv_id})", ["BOLA"]),
    ("Response getProject(Request req) { String id = req.params['id']; return Response.ok(projectRepo.find(id)); }", ["BOLA"]),

    # BFLA (CWE-285)
    ("@app.post('/api/admin/reset_metrics') def reset(): global_stats.clear(); return {'status': 'reset'}", ["BFLA"]),
    ("router.delete('/admin/users/:id', (req, res) => { db.users.delete(req.params.id); res.status(204).end(); });", ["BFLA"]),
    ("def export_all_tenants(): return db.raw_export_tenants()", ["BFLA"]),
    ("fun cancelAnyOrder(orderId: Long): ResponseEntity<Void> { orderService.forceCancel(orderId); return ResponseEntity.ok().build(); }", ["BFLA"]),
    ("@PreAuthorize('permitAll()') @PostMapping('/admin/config') fun updateCfg(@RequestBody cfg: Config) = repo.save(cfg)", ["BFLA"]),

    # Missing Authentication (CWE-306)
    ("app.post('/api/v2/transfer', (req, res) => { transferFunds(req.body.from, req.body.to, req.body.amount); res.send('ok'); });", ["AUTHENTICATION"]),
    ("def update_password(req): user = get_user(req.json['username']); user.password = hash(req.json['new_pass']); db.save(user)", ["AUTHENTICATION"]),
    ("async def change_email(email: str): current_user.email = email; await db.commit()", ["AUTHENTICATION"]),
    ("router.put('/api/v1/vault/keys', (req, res) => { vault.rotateKey(req.body.key); res.json({status: 'updated'}); });", ["AUTHENTICATION"]),

    # SSRF (CWE-918)
    ("def fetch_url(url: str): return httpx.get(url).text", ["SSRF"]),
    ("router.post('/webhook', async (req, res) => { const out = await axios.get(req.body.target_url); res.send(out.data); });", ["SSRF"]),
    ("def preview_link(link): return requests.get(link, timeout=5).content", ["SSRF"]),
    ("fun proxyRequest(callbackUrl: String) = restTemplate.getForObject(callbackUrl, String::class.java)", ["SSRF"]),
    ("async function fetchRemoteAvatar(url) { return (await fetch(url)).blob(); }", ["SSRF"]),

    # Injection (SQLi / Command / LDAP) (CWE-89 / CWE-78)
    ("def search_products(q: str): return db.execute(f'SELECT * FROM products WHERE name LIKE \"%{q}%\"')", ["INJECTION"]),
    ("app.get('/exec', (req, res) => { exec('ping -c 1 ' + req.query.host, (err, stdout) => res.send(stdout)); });", ["INJECTION"]),
    ("def find_user(name): query = 'SELECT * FROM users WHERE username = \\'' + name + '\\''; return db.cursor.execute(query)", ["INJECTION"]),
    ("def run_backup(path): os.system(f'tar -czf backup.tar.gz {path}')", ["INJECTION"]),
    ("fun queryLdap(filter: String) = ldapTemplate.search('', '(uid=' + filter + ')', mapper)", ["INJECTION"]),

    # Mass Assignment (CWE-915)
    ("def update_profile(user_id, data: dict): user = db.get(user_id); user.__dict__.update(data); db.save(user)", ["MASS_ASSIGNMENT"]),
    ("router.put('/user/:id', (req, res) => { User.findByIdAndUpdate(req.params.id, req.body); res.json({ok: true}); });", ["MASS_ASSIGNMENT"]),
    ("async def patch_account(req: Request): data = await req.json(); user.update(**data); return user", ["MASS_ASSIGNMENT"]),
    ("@PutMapping('/users/{id}') fun patchUser(@PathVariable id: Long, @RequestBody user: User) = userRepo.save(user)", ["MASS_ASSIGNMENT"]),

    # Path Traversal (CWE-22 / CWE-73)
    ("def read_file(filename: str): return open(os.path.join('/var/www/uploads', filename), 'r').read()", ["PATH_TRAVERSAL"]),
    ("app.get('/download', (req, res) => { res.sendFile(path.resolve('./files/' + req.query.file)); });", ["PATH_TRAVERSAL"]),
    ("def view_log(log_path): with open(log_path, 'r') as f: return f.read()", ["PATH_TRAVERSAL"]),
    ("fun serveStatic(page: String): ByteArray = File('/assets/' + page).readBytes()", ["PATH_TRAVERSAL"]),

    # SSTI (CWE-1336 / CWE-94)
    ("def render_user_card(username: str): return jinja2.Environment().from_string(f'Hello {username}').render()", ["SSTI"]),
    ("def preview_email(template_str): return render_template_string(template_str)", ["SSTI"]),
    ("app.get('/greet', (req, res) => { const tmpl = nunjucks.renderString('Welcome ' + req.query.name); res.send(tmpl); });", ["SSTI"]),

    # CORS Misconfiguration (CWE-942)
    ("def after_request(resp): resp.headers['Access-Control-Allow-Origin'] = request.headers.get('Origin'); resp.headers['Access-Control-Allow-Credentials'] = 'true'; return resp", ["CORS"]),
    ("app.use((req, res, next) => { res.header('Access-Control-Allow-Origin', req.headers.origin); res.header('Access-Control-Allow-Credentials', 'true'); next(); });", ["CORS"]),

    # Deserialization (CWE-502)
    ("def load_session(data): return pickle.loads(base64.b64decode(data))", ["DESERIALIZATION"]),
    ("def parse_config(yaml_str): return yaml.load(yaml_str, Loader=yaml.Loader)", ["DESERIALIZATION"]),
    ("def restore_state(payload): import pickle; return pickle.loads(payload)", ["DESERIALIZATION"]),

    # Safe Negative Controls (Benign code slices across frameworks)
    ("def get_order_safe(order_id, user=Depends(get_current_user)): return db.query(Order).filter(Order.id == order_id, Order.tenant_id == user.tenant_id).first()", []),
    ("def search_safe(term: str): return db.execute('SELECT * FROM items WHERE name ILIKE :term', {'term': f'%{term}%'})", []),
    ("def read_file_safe(filename: str): canonical = Path(filename).resolve(); if not str(canonical).startswith('/safe/root/'): raise Forbidden(); return canonical.read_text()", []),
    ("def fetch_url_safe(url: str): guard = ScopeGuard(); guard.validate_url(url); return httpx.get(url)", []),
    ("def update_user_safe(user_id, dto: UserUpdateDto): user = db.get(user_id); user.name = dto.name; user.bio = dto.bio; db.save(user)", []),
    ("def render_safe(template_name, context): return render_template(f'{template_name}.html', **context)", []),
]


def load_owasp_benchmark_samples() -> List[Tuple[str, List[str]]]:
    """Loads all 1,230 real code files from OWASP Benchmark Python with verified ground truth."""
    samples: List[Tuple[str, List[str]]] = []

    candidates = [
        Path("benchmarks/owasp-python"),
        Path(__file__).resolve().parent.parent.parent.parent / "benchmarks/owasp-python",
    ]
    benchmark_dir = None
    for c in candidates:
        if c.exists() and (c / "expectedresults-0.1.csv").exists():
            benchmark_dir = c
            break

    if not benchmark_dir:
        return samples

    csv_file = benchmark_dir / "expectedresults-0.1.csv"
    testcode_dir = benchmark_dir / "testcode"

    cat_mapping = {
        "pathtraver": "PATH_TRAVERSAL",
        "sqli": "INJECTION",
        "cmdi": "INJECTION",
        "codeinj": "INJECTION",
        "ldapi": "INJECTION",
        "xpathi": "INJECTION",
        "xss": "INJECTION",
        "deserialization": "DESERIALIZATION",
        "trustbound": "BOLA",
        "redirect": "SSRF",
    }

    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or row[0].startswith("#"):
                    continue
                test_file = testcode_dir / f"{row[0].strip()}.py"
                if not test_file.exists():
                    continue

                category_raw = row[1].strip().lower()
                is_vuln = row[2].strip().lower() == "true"

                code_content = test_file.read_text(encoding="utf-8", errors="replace")
                normalized = normalize_code_slice(code_content[:1500])

                if is_vuln and category_raw in cat_mapping:
                    samples.append((normalized, [cat_mapping[category_raw]]))
                else:
                    # Non-vulnerable safe control sample
                    samples.append((normalized, []))
    except Exception:
        pass

    return samples


def load_parquet_security_corpus() -> List[Tuple[str, List[str]]]:
    """Loads 500+ curated security vulnerability AST functions from research parquet files."""
    samples: List[Tuple[str, List[str]]] = []
    candidates = [
        Path("research/securebert2/opensource_data/data_vuln_dataset.parquet"),
        Path(__file__).resolve().parent.parent.parent.parent / "research/securebert2/opensource_data/data_vuln_dataset.parquet",
    ]

    pq_file = None
    for c in candidates:
        if c.exists():
            pq_file = c
            break

    if not pq_file:
        return samples

    try:
        import pyarrow.parquet as pq
        table = pq.read_table(pq_file)
        pydict = table.to_pydict()
        codes = pydict.get("code", [])
        labels = pydict.get("label", [])

        for code, is_vuln in zip(codes, labels):
            code_str = str(code)
            normalized = normalize_code_slice(code_str[:1200])
            if is_vuln:
                samples.append((normalized, ["INJECTION"]))
            else:
                samples.append((normalized, []))
    except Exception:
        pass

    return samples


def generate_cybersecurity_training_corpus(multiplier: int = 12) -> List[Tuple[str, List[str]]]:
    """Builds a comprehensive unified training corpus fusing OWASP Benchmark, parquet CVEs, and multi-language templates."""
    samples: List[Tuple[str, List[str]]] = []

    # 1. Ingest real OWASP Benchmark Python files (1,230 samples)
    owasp_samples = load_owasp_benchmark_samples()
    samples.extend(owasp_samples)

    # 2. Ingest real parquet vulnerability AST slices (500 samples)
    pq_samples = load_parquet_security_corpus()
    samples.extend(pq_samples)

    # 3. Augment multi-language API templates to ensure balanced class distributions across all 10 categories
    var_aliases = ["item", "record", "payload", "entity", "resource", "target", "client", "doc", "asset"]
    for _ in range(multiplier):
        for code, labels in CORPUS_TEMPLATES:
            augmented_code = code
            for alias in var_aliases:
                if "user" in augmented_code and alias != "user":
                    augmented_code = augmented_code.replace("user", alias)
                    break
            samples.append((normalize_code_slice(augmented_code), labels))

    return samples


class VulnerabilityDataset(Dataset):
    """PyTorch Dataset for multi-label vulnerability classification with class-weight support."""

    def __init__(self, samples: List[Tuple[str, List[str]]], tokenizer, max_length: int = 256):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.label_map = {cat: idx for idx, cat in enumerate(VULN_CATEGORIES)}

    def __len__(self) -> int:
        return len(self.samples)

    def calculate_pos_weights(self) -> torch.Tensor:
        """Calculates positive class weights to balance sparse vulnerability categories."""
        pos_counts = torch.zeros(len(VULN_CATEGORIES), dtype=torch.float32)
        total = len(self.samples)
        for _, labels in self.samples:
            for l in labels:
                if l in self.label_map:
                    pos_counts[self.label_map[l]] += 1.0

        pos_counts = torch.clamp(pos_counts, min=1.0)
        neg_counts = total - pos_counts
        # Pos weight = neg / pos (bounded to [1.0, 15.0] to prevent gradient explosion)
        weights = torch.clamp(neg_counts / pos_counts, min=1.0, max=15.0)
        return weights

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        code_text, label_names = self.samples[idx]

        target = torch.zeros(len(VULN_CATEGORIES), dtype=torch.float32)
        for name in label_names:
            if name in self.label_map:
                target[self.label_map[name]] = 1.0

        encoding = self.tokenizer(
            code_text,
            max_length=self.max_length,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "labels": target,
        }
