"""Target policy and scope enforcement."""

from trace_engine.policy.scope import ScopeGuard, ScopeViolationError

__all__ = ["ScopeGuard", "ScopeViolationError"]
