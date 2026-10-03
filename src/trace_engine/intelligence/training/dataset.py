"""Cybersecurity AST dataset generator and PyTorch Dataset for model fine-tuning."""

import re
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


# Seed dataset of labeled vulnerability patterns and safe controls
CORPUS_TEMPLATES = [
    # BOLA / IDOR (CWE-639)
    ("def get_order(order_id): return db.query('SELECT * FROM orders WHERE id = :id', id=order_id).fetchone()", ["BOLA"]),
    ("async function getDocument(req, res) { const doc = await Document.findById(req.params.id); return res.json(doc); }", ["BOLA"]),
    ("router.get('/profile/:id', (req, res) => { const user = User.load(req.params.id); res.send(user); });", ["BOLA"]),
    ("@app.get('/invoice/{inv_id}') def invoice(inv_id: str): return db.invoices.find_one({'_id': inv_id})", ["BOLA"]),

    # BFLA (CWE-285)
    ("@app.post('/api/admin/reset_metrics') def reset(): global_stats.clear(); return {'status': 'reset'}", ["BFLA"]),
    ("router.delete('/admin/users/:id', (req, res) => { db.users.delete(req.params.id); res.status(204).end(); });", ["BFLA"]),
    ("def export_all_tenants(): return db.raw_export_tenants()", ["BFLA"]),
    ("fun cancelAnyOrder(orderId: Long): ResponseEntity<Void> { orderService.forceCancel(orderId); return ResponseEntity.ok().build(); }", ["BFLA"]),

    # Missing Authentication (CWE-306)
    ("app.post('/api/v2/transfer', (req, res) => { transferFunds(req.body.from, req.body.to, req.body.amount); res.send('ok'); });", ["AUTHENTICATION"]),
    ("def update_password(req): user = get_user(req.json['username']); user.password = hash(req.json['new_pass']); db.save(user)", ["AUTHENTICATION"]),
    ("async def change_email(email: str): current_user.email = email; await db.commit()", ["AUTHENTICATION"]),

    # SSRF (CWE-918)
    ("def fetch_url(url: str): return httpx.get(url).text", ["SSRF"]),
    ("router.post('/webhook', async (req, res) => { const out = await axios.get(req.body.target_url); res.send(out.data); });", ["SSRF"]),
    ("def preview_link(link): return requests.get(link, timeout=5).content", ["SSRF"]),
    ("fun proxyRequest(callbackUrl: String) = restTemplate.getForObject(callbackUrl, String::class.java)", ["SSRF"]),

    # Injection (SQLi / Command / LDAP) (CWE-89 / CWE-78)
    ("def search_products(q: str): return db.execute(f'SELECT * FROM products WHERE name LIKE \"%{q}%\"')", ["INJECTION"]),
    ("app.get('/exec', (req, res) => { exec('ping -c 1 ' + req.query.host, (err, stdout) => res.send(stdout)); });", ["INJECTION"]),
    ("def find_user(name): query = 'SELECT * FROM users WHERE username = \\'' + name + '\\''; return db.cursor.execute(query)", ["INJECTION"]),
    ("def run_backup(path): os.system(f'tar -czf backup.tar.gz {path}')", ["INJECTION"]),

    # Mass Assignment (CWE-915)
    ("def update_profile(user_id, data: dict): user = db.get(user_id); user.__dict__.update(data); db.save(user)", ["MASS_ASSIGNMENT"]),
    ("router.put('/user/:id', (req, res) => { User.findByIdAndUpdate(req.params.id, req.body); res.json({ok: true}); });", ["MASS_ASSIGNMENT"]),
    ("async def patch_account(req: Request): data = await req.json(); user.update(**data); return user", ["MASS_ASSIGNMENT"]),

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

    # Safe Negative Controls (Benign code slices)
    ("def get_order_safe(order_id, user=Depends(get_current_user)): return db.query(Order).filter(Order.id == order_id, Order.tenant_id == user.tenant_id).first()", []),
    ("def search_safe(term: str): return db.execute('SELECT * FROM items WHERE name ILIKE :term', {'term': f'%{term}%'})", []),
    ("def read_file_safe(filename: str): canonical = Path(filename).resolve(); if not str(canonical).startswith('/safe/root/'): raise Forbidden(); return canonical.read_text()", []),
    ("def fetch_url_safe(url: str): guard = ScopeGuard(); guard.validate_url(url); return httpx.get(url)", []),
]


def generate_cybersecurity_training_corpus(multiplier: int = 15) -> List[Tuple[str, List[str]]]:
    """Generates an augmented training corpus of vulnerable and safe code samples."""
    samples: List[Tuple[str, List[str]]] = []

    # Augment corpus by simulating variations in formatting, naming, and function wrappers
    var_aliases = ["item", "record", "payload", "entity", "resource", "target", "client"]
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
    """PyTorch Dataset for multi-label vulnerability classification."""

    def __init__(self, samples: List[Tuple[str, List[str]]], tokenizer, max_length: int = 256):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length
        self.label_map = {cat: idx for idx, cat in enumerate(VULN_CATEGORIES)}

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        code_text, label_names = self.samples[idx]

        # Multi-label binary target vector of size (num_categories,)
        target = torch.zeros(len(VULN_CATEGORIES), dtype=torch.float32)
        for name in label_names:
            if name in self.label_map:
                target[self.label_map[name]] = 1.0

        # Tokenize code
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
