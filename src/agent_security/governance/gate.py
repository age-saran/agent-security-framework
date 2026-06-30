"""``govern()`` — wrap any tool function with policy enforcement.

Every governed call runs: build context -> evaluate policy -> (optional audit)
-> ALLOW/MODIFY execute, DENY/STEP_UP/DEFER raise. Both sync and async callables
are supported; the wrapper mirrors the wrapped function's call style.
"""

from __future__ import annotations

import asyncio
import functools
import inspect
from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from agent_security.governance.exceptions import (
    GovernanceDeferred,
    GovernanceDenied,
    GovernanceStepUpRequired,
)
from agent_security.policy.engine import PolicyEvaluator
from agent_security.policy.loader import load_policy
from agent_security.policy.models import (
    PolicyAction,
    PolicyDecision,
    PolicyDocument,
)

PolicySpec = "str | PolicyDocument | list[PolicyDocument] | PolicyEvaluator"


@runtime_checkable
class AuditSink(Protocol):
    """Minimal audit hook. Phase 2 supplies a Merkle-chain implementation."""

    def log_decision(self, context: dict, decision: PolicyDecision) -> Any: ...


@runtime_checkable
class StepUpHandler(Protocol):
    """Human-approval handler. Phase 4 supplies Teams/Outlook implementations."""

    def request_approval(self, decision: PolicyDecision, context: dict) -> Any:
        """Return an object with a truthy ``.approved`` attribute (sync or awaitable)."""
        ...


def _build_evaluator(policy: Any) -> PolicyEvaluator:
    if isinstance(policy, PolicyEvaluator):
        return policy
    if isinstance(policy, str):
        return PolicyEvaluator([load_policy(policy)])
    if isinstance(policy, PolicyDocument):
        return PolicyEvaluator([policy])
    if isinstance(policy, list):
        return PolicyEvaluator(policy)
    raise TypeError(f"unsupported policy spec: {type(policy)!r}")


def _build_context(
    func: Callable[..., Any],
    args: tuple,
    kwargs: dict,
    agent_id: str,
    agent_ring: int,
) -> tuple[dict, dict]:
    """Return (context, bound_args) extracted from the call."""
    try:
        sig = inspect.signature(func)
        bound = sig.bind_partial(*args, **kwargs)
        bound.apply_defaults()
        call_args = dict(bound.arguments)
    except (TypeError, ValueError):
        call_args = {"args": args, "kwargs": kwargs}
    call_args.pop("self", None)
    call_args.pop("cls", None)

    evaluator_args = {k: v for k, v in call_args.items() if _yaml_safe(v)}
    return (
        {
            "tool_name": func.__name__,
            "args": evaluator_args,
            "agent": {"id": agent_id, "ring": agent_ring},
            "agent_id": agent_id,
            "_call_args": call_args,
        },
        call_args,
    )


def _yaml_safe(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool, type(None), list, dict))


def _decision_context(evaluator: PolicyEvaluator, ctx: dict) -> PolicyDecision:
    return evaluator.evaluate_tool_call(
        tool_name=ctx["tool_name"],
        args=ctx["args"],
        agent_id=ctx["agent_id"],
        agent_ring=ctx["agent"]["ring"],
        extra={k: v for k, v in ctx.items() if k not in ("_call_args",)},
    )


def govern(
    func: Callable[..., Any] | None = None,
    *,
    policy: Any,
    agent_id: str = "default",
    agent_ring: int = 3,
    audit_sink: AuditSink | None = None,
    step_up_handler: StepUpHandler | None = None,
) -> Callable[..., Any]:
    """Wrap ``func`` with governance. Usable directly or as a decorator factory.

    Direct:     ``safe = govern(my_tool, policy="prod.yaml")``
    Decorator:  ``@govern(policy="prod.yaml")`` above ``def my_tool(...)``
    """
    evaluator = _build_evaluator(policy)

    def _wrap(target: Callable[..., Any]) -> Callable[..., Any]:
        is_async = asyncio.iscoroutinefunction(target)

        def _decide(args: tuple, kwargs: dict) -> tuple[PolicyDecision, dict, dict]:
            ctx, call_args = _build_context(target, args, kwargs, agent_id, agent_ring)
            decision = _decision_context(evaluator, ctx)
            if audit_sink is not None:
                audit_sink.log_decision(ctx, decision)
            return decision, ctx, call_args

        def _apply_modify(call_args: dict, decision: PolicyDecision) -> dict:
            merged = dict(call_args)
            merged.update(decision.modify_params)
            return merged

        if is_async:

            @functools.wraps(target)
            async def _async_wrapper(*args: Any, **kwargs: Any) -> Any:
                decision, ctx, call_args = _decide(args, kwargs)
                action = decision.action
                if action is PolicyAction.ALLOW:
                    return await target(*args, **kwargs)
                if action is PolicyAction.MODIFY:
                    return await target(**_apply_modify(call_args, decision))
                if action is PolicyAction.STEP_UP:
                    if step_up_handler is None:
                        raise GovernanceStepUpRequired(decision)
                    result = step_up_handler.request_approval(decision, ctx)
                    if inspect.isawaitable(result):
                        result = await result
                    if getattr(result, "approved", False):
                        return await target(*args, **kwargs)
                    raise GovernanceDenied(decision)
                if action is PolicyAction.DEFER:
                    raise GovernanceDeferred(decision)
                raise GovernanceDenied(decision)

            return _async_wrapper

        @functools.wraps(target)
        def _sync_wrapper(*args: Any, **kwargs: Any) -> Any:
            decision, ctx, call_args = _decide(args, kwargs)
            action = decision.action
            if action is PolicyAction.ALLOW:
                return target(*args, **kwargs)
            if action is PolicyAction.MODIFY:
                return target(**_apply_modify(call_args, decision))
            if action is PolicyAction.STEP_UP:
                if step_up_handler is None:
                    raise GovernanceStepUpRequired(decision)
                result = step_up_handler.request_approval(decision, ctx)
                if inspect.isawaitable(result):
                    result = asyncio.run(result)
                if getattr(result, "approved", False):
                    return target(*args, **kwargs)
                raise GovernanceDenied(decision)
            if action is PolicyAction.DEFER:
                raise GovernanceDeferred(decision)
            raise GovernanceDenied(decision)

        return _sync_wrapper

    # Called as govern(func, policy=...) -> wrapped function.
    if func is not None:
        return _wrap(func)
    # Called as govern(policy=...) -> decorator.
    return _wrap
