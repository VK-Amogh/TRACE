"""Default configuration values for TRACE."""

DEFAULT_CONFIG_TOML = """# TRACE Configuration File
# Threat Reconnaissance & Attack-path Correlation Engine

[project]
name = "default-project"
version = "1.0.0"
mode = "local"

[ai]
provider = "ollama"
model = "qwen2.5-coder:latest"
temperature = 0.1
endpoint = "http://127.0.0.1:11434"

[target]
url = "http://127.0.0.1:8000"
scope_mode = "local"
allowed_hosts = ["localhost", "127.0.0.1", "0.0.0.0", "::1"]
allowed_ports = [80, 443, 3000, 5000, 8000, 8080, 18080]

[runtime]
max_requests = 250
concurrency = 2
rate_limit_per_second = 5
timeout_seconds = 8
max_redirects = 3
destructive_tests = false

[analysis]
max_graph_hops = 3
max_source_context_lines = 120
enable_tree_sitter = true

[tests]
enabled = [
    "bola",
    "bfla",
    "authentication",
    "ssrf",
    "injection",
    "mass_assignment"
]

[tools]
enabled = ["schemathesis", "nuclei", "zap", "trufflehog"]
"""
