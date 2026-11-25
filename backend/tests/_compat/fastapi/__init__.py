"""Minimal FastAPI-compatible TEST HARNESS built on Starlette.

Used ONLY by the test suite, and ONLY when the real ``fastapi`` package cannot be
imported (``backend/tests/conftest.py`` adds this directory to ``sys.path`` in
that case). Production always uses real FastAPI from requirements.txt.

It implements the subset Daggers uses: FastAPI/APIRouter route decorators,
path/query/body parameter binding with pydantic validation (422 on error),
HTTPException, Query(), lifespan, include_router, mount, middleware. It does
not generate OpenAPI. Results obtained through it must be re-confirmed with
real FastAPI (``make test`` after ``make bootstrap``).
"""
from __future__ import annotations

import inspect
import json
import re
import typing
from typing import Any, Callable, Literal, get_args, get_origin

from pydantic import BaseModel, ValidationError
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as _StarletteHTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

__all__ = ["FastAPI", "APIRouter", "HTTPException", "Query", "Request", "Body", "Depends"]
_HARNESS = True


class HTTPException(_StarletteHTTPException):
    def __init__(self, status_code: int, detail: Any = None, headers: dict | None = None) -> None:
        super().__init__(status_code=status_code, detail=detail, headers=headers)


class _QueryInfo:
    def __init__(self, default: Any = ..., **constraints: Any) -> None:
        self.default = default
        self.constraints = constraints


def Query(default: Any = ..., **constraints: Any) -> Any:  # noqa: N802 - FastAPI API
    return _QueryInfo(default, **constraints)


def Body(default: Any = ..., **_: Any) -> Any:  # noqa: N802
    return default


def Depends(dep: Callable | None = None) -> Any:  # noqa: N802 - unused by Daggers
    raise NotImplementedError("Depends is not supported by the test harness")


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump()
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return value


def _unwrap_optional(annotation: Any) -> Any:
    if get_origin(annotation) in (typing.Union, getattr(__import__("types"), "UnionType", None)):
        args = [a for a in get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return annotation


def _convert(name: str, raw: str, annotation: Any) -> Any:
    annotation = _unwrap_optional(annotation)
    if get_origin(annotation) is Literal:
        allowed = get_args(annotation)
        if raw not in allowed:
            raise ValueError(f"{name} must be one of {allowed}")
        return raw
    if annotation is int:
        return int(raw)
    if annotation is float:
        return float(raw)
    if annotation is bool:
        return raw.lower() in {"1", "true", "yes", "on"}
    return raw


def _check(name: str, value: Any, constraints: dict) -> None:
    if "ge" in constraints and value < constraints["ge"]:
        raise ValueError(f"{name} must be >= {constraints['ge']}")
    if "le" in constraints and value > constraints["le"]:
        raise ValueError(f"{name} must be <= {constraints['le']}")
    if "max_length" in constraints and len(value) > constraints["max_length"]:
        raise ValueError(f"{name} too long")


def _endpoint(func: Callable, path: str, status_code: int):
    signature = inspect.signature(func)
    hints = typing.get_type_hints(func)
    path_names = set(re.findall(r"\{(\w+)(?::\w+)?\}", path))

    async def handler(request: Request) -> Response:
        kwargs: dict[str, Any] = {}
        try:
            for name, param in signature.parameters.items():
                annotation = hints.get(name, param.annotation)
                if annotation is Request:
                    kwargs[name] = request
                elif name in path_names:
                    kwargs[name] = _convert(name, request.path_params[name], annotation)
                elif inspect.isclass(_unwrap_optional(annotation)) and issubclass(_unwrap_optional(annotation), BaseModel):
                    raw = await request.body()
                    try:
                        data = json.loads(raw or b"null")
                    except json.JSONDecodeError as exc:
                        raise ValueError("invalid JSON body") from exc
                    kwargs[name] = _unwrap_optional(annotation).model_validate(data)
                else:
                    info = param.default if isinstance(param.default, _QueryInfo) else _QueryInfo(param.default)
                    if name in request.query_params:
                        value = _convert(name, request.query_params[name], annotation)
                        _check(name, value, info.constraints)
                        kwargs[name] = value
                    elif info.default is ...:
                        raise ValueError(f"missing query parameter {name}")
                    else:
                        kwargs[name] = info.default
        except (ValueError, ValidationError, KeyError) as exc:
            detail = exc.errors() if isinstance(exc, ValidationError) else str(exc)
            return JSONResponse({"detail": json.loads(json.dumps(detail, default=str))}, status_code=422)
        if inspect.iscoroutinefunction(func):
            result = await func(**kwargs)
        else:
            result = await run_in_threadpool(func, **kwargs)
        if isinstance(result, Response):
            return result
        return JSONResponse(_jsonable(result), status_code=status_code)

    return handler


class APIRouter:
    def __init__(self, prefix: str = "", tags: list[str] | None = None, **_: Any) -> None:
        self.prefix = prefix
        self.routes: list[Route] = []

    def add_api_route(self, path: str, func: Callable, methods: list[str], status_code: int = 200, **_: Any) -> None:
        full = self.prefix + path
        self.routes.append(Route(full, _endpoint(func, full, status_code), methods=methods))

    def _method(self, method: str, path: str, status_code: int = 200, **kw: Any):
        def deco(func: Callable) -> Callable:
            self.add_api_route(path, func, [method], status_code=status_code)
            return func

        return deco

    def get(self, path: str, **kw: Any):
        return self._method("GET", path, **kw)

    def post(self, path: str, **kw: Any):
        return self._method("POST", path, **kw)

    def put(self, path: str, **kw: Any):
        return self._method("PUT", path, **kw)

    def delete(self, path: str, **kw: Any):
        return self._method("DELETE", path, **kw)


async def _http_exception(request: Request, exc: _StarletteHTTPException) -> Response:
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)


class FastAPI(Starlette):
    def __init__(self, *, title: str = "", version: str = "", description: str = "", lifespan=None, **_: Any) -> None:
        super().__init__(lifespan=lifespan, exception_handlers={_StarletteHTTPException: _http_exception})
        self.title = title
        self.version = version

    def include_router(self, router: APIRouter, **_: Any) -> None:
        for route in router.routes:
            self.router.routes.append(route)

    def add_api_route(self, path: str, func: Callable, methods: list[str] | None = None, **kw: Any) -> None:
        self.router.routes.append(Route(path, _endpoint(func, path, kw.get("status_code", 200)), methods=methods or ["GET"]))

    def get(self, path: str, **kw: Any):
        def deco(func):
            self.add_api_route(path, func, ["GET"], **kw)
            return func

        return deco

    def post(self, path: str, **kw: Any):
        def deco(func):
            self.add_api_route(path, func, ["POST"], **kw)
            return func

        return deco
