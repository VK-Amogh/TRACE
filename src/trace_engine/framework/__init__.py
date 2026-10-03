"""Framework adapters for web frameworks and API route extraction."""

from typing import List
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.framework.fastapi import FastAPIFrameworkAdapter
from trace_engine.framework.flask import FlaskFrameworkAdapter
from trace_engine.framework.express import ExpressFrameworkAdapter

_ADAPTERS: List[FrameworkAdapter] = [
    FastAPIFrameworkAdapter(),
    FlaskFrameworkAdapter(),
    ExpressFrameworkAdapter(),
]


def get_adapters() -> List[FrameworkAdapter]:
    return _ADAPTERS


__all__ = [
    "FrameworkAdapter",
    "Endpoint",
    "EndpointParameter",
    "FastAPIFrameworkAdapter",
    "FlaskFrameworkAdapter",
    "ExpressFrameworkAdapter",
    "get_adapters",
]
