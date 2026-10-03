"""Framework adapters for web frameworks and API route extraction."""

from typing import List
from trace_engine.framework.base import FrameworkAdapter, Endpoint, EndpointParameter
from trace_engine.framework.fastapi import FastAPIFrameworkAdapter
from trace_engine.framework.flask import FlaskFrameworkAdapter
from trace_engine.framework.express import ExpressFrameworkAdapter
from trace_engine.framework.react_router import ReactRouterFrameworkAdapter
from trace_engine.framework.nextjs import NextJSFrameworkAdapter
from trace_engine.framework.dart import DartFrameworkAdapter
from trace_engine.framework.springboot import SpringBootFrameworkAdapter
from trace_engine.framework.go import GoFrameworkAdapter

_ADAPTERS: List[FrameworkAdapter] = [
    FastAPIFrameworkAdapter(),
    FlaskFrameworkAdapter(),
    ExpressFrameworkAdapter(),
    ReactRouterFrameworkAdapter(),
    NextJSFrameworkAdapter(),
    DartFrameworkAdapter(),
    SpringBootFrameworkAdapter(),
    GoFrameworkAdapter(),
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
    "ReactRouterFrameworkAdapter",
    "NextJSFrameworkAdapter",
    "DartFrameworkAdapter",
    "SpringBootFrameworkAdapter",
    "GoFrameworkAdapter",
    "get_adapters",
]
