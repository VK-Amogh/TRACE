"""Configuration loader for TRACE."""

import os
from pathlib import Path
from typing import Optional
import tomllib
import tomli_w

from trace_engine.config.settings import TraceConfig
from trace_engine.config.defaults import DEFAULT_CONFIG_TOML


def get_trace_dir(repo_path: Path) -> Path:
    """Get the .trace directory path within the given repository."""
    return repo_path.resolve() / ".trace"


def get_config_path(repo_path: Path) -> Path:
    """Get the path to config.toml in the .trace directory."""
    return get_trace_dir(repo_path) / "config.toml"


def init_trace_dir(repo_path: Path, project_name: Optional[str] = None) -> Path:
    """Initialize .trace directory structure in repository."""
    trace_dir = get_trace_dir(repo_path)
    trace_dir.mkdir(parents=True, exist_ok=True)
    
    (trace_dir / "cache").mkdir(exist_ok=True)
    (trace_dir / "runs").mkdir(exist_ok=True)
    (trace_dir / "reports").mkdir(exist_ok=True)
    
    config_file = trace_dir / "config.toml"
    if not config_file.exists():
        content = DEFAULT_CONFIG_TOML
        if project_name:
            content = content.replace('name = "default-project"', f'name = "{project_name}"')
        config_file.write_text(content, encoding="utf-8")
        
    return trace_dir


def load_config(repo_path: Path) -> TraceConfig:
    """Load configuration from .trace/config.toml or return default configuration."""
    config_file = get_config_path(repo_path)
    if not config_file.exists():
        return TraceConfig()
        
    try:
        with open(config_file, "rb") as f:
            data = tomllib.load(f)
        return TraceConfig.model_validate(data)
    except Exception:
        return TraceConfig()


def save_config(repo_path: Path, config: TraceConfig) -> None:
    """Save configuration to .trace/config.toml."""
    trace_dir = get_trace_dir(repo_path)
    trace_dir.mkdir(parents=True, exist_ok=True)
    config_file = trace_dir / "config.toml"
    
    data = config.model_dump()
    with open(config_file, "wb") as f:
        tomli_w.dump(data, f)
