"""Specific adapters for open-source security tools."""

from trace_engine.tools.base import ToolAdapter


class SchemathesisAdapter(ToolAdapter):
    @property
    def name(self) -> str:
        return "Schemathesis"

    @property
    def command(self) -> str:
        return "schemathesis"

    @property
    def description(self) -> str:
        return "Specification-based API property fuzzing and contract validation."

    @property
    def category(self) -> str:
        return "API Fuzzing"


class NucleiAdapter(ToolAdapter):
    @property
    def name(self) -> str:
        return "Nuclei"

    @property
    def command(self) -> str:
        return "nuclei"

    @property
    def description(self) -> str:
        return "Fast and customizable vulnerability scanner based on simple YAML DSL."

    @property
    def category(self) -> str:
        return "DAST / Templates"


class ZapAdapter(ToolAdapter):
    @property
    def name(self) -> str:
        return "OWASP ZAP"

    @property
    def command(self) -> str:
        return "zap.sh"

    @property
    def description(self) -> str:
        return "Dynamic application security scanner for web applications."

    @property
    def category(self) -> str:
        return "DAST Scanner"


class TruffleHogAdapter(ToolAdapter):
    @property
    def name(self) -> str:
        return "TruffleHog"

    @property
    def command(self) -> str:
        return "trufflehog"

    @property
    def description(self) -> str:
        return "High-accuracy credentials and secrets scanner in git repositories."

    @property
    def category(self) -> str:
        return "Secret Detection"


class SqlmapAdapter(ToolAdapter):
    @property
    def name(self) -> str:
        return "sqlmap"

    @property
    def command(self) -> str:
        return "sqlmap"

    @property
    def description(self) -> str:
        return "Automatic SQL injection and database takeover tool."

    @property
    def category(self) -> str:
        return "Injection Testing"


class FfufAdapter(ToolAdapter):
    @property
    def name(self) -> str:
        return "ffuf"

    @property
    def command(self) -> str:
        return "ffuf"

    @property
    def description(self) -> str:
        return "Fast web fuzzer for parameter and endpoint discovery."

    @property
    def category(self) -> str:
        return "Web Fuzzing"
