"""可观测性：用 OpenTelemetry SDK 记录每次调查的 span，命名遵循 GenAI 语义约定。

- 根 span：invoke_agent probewise
- 图节点：chain {节点名}
- 工具调用：execute_tool {工具名}，带 gen_ai.tool.name 等属性

默认用内存导出器收集后写进调查记录（前端画瀑布图）；设置 OTEL_EXPORTER_OTLP_ENDPOINT
并安装 opentelemetry-exporter-otlp 后，会同时发送到 Jaeger、Langfuse 等 OTLP 后端。
"""

from __future__ import annotations

import os
from contextlib import contextmanager

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

_exporter = InMemorySpanExporter()
_provider = TracerProvider(resource=Resource.create({"service.name": "probewise"}))
_provider.add_span_processor(SimpleSpanProcessor(_exporter))

if os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
    try:
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        _provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    except ImportError:
        pass

_tracer = _provider.get_tracer("probewise")


class RunTracer:
    """一次图调用对应一个根 span，节点和工具调用都挂在它下面。"""

    def __init__(self, run_id: str, operation: str = "invoke_agent"):
        self.run_id = run_id
        self._root = _tracer.start_span(
            f"{operation} probewise",
            attributes={"gen_ai.operation.name": operation, "gen_ai.agent.name": "probewise", "probewise.run_id": run_id},
        )
        self._ctx = trace.set_span_in_context(self._root)

    @contextmanager
    def span(self, name: str, **attributes):
        with _tracer.start_as_current_span(name, context=self._ctx, attributes=attributes) as s:
            yield s

    def finish(self) -> list[dict]:
        """结束根 span，取出这次调用产生的全部 span 并转成可序列化的字典。"""
        self._root.end()
        trace_id = self._root.get_span_context().trace_id
        mine = [s for s in _exporter.get_finished_spans() if s.context.trace_id == trace_id]
        # 只清理本次的 span，避免并发请求互相影响
        others = [s for s in _exporter.get_finished_spans() if s.context.trace_id != trace_id]
        _exporter.clear()
        for s in others:
            _exporter.export([s])
        start = min(s.start_time for s in mine) if mine else 0
        out = []
        for s in sorted(mine, key=lambda x: x.start_time):
            out.append(
                {
                    "name": s.name,
                    "span_id": format(s.context.span_id, "016x"),
                    "parent_id": format(s.parent.span_id, "016x") if s.parent else None,
                    "trace_id": format(trace_id, "032x"),
                    "start_ms": round((s.start_time - start) / 1e6, 3),
                    "duration_ms": round((s.end_time - s.start_time) / 1e6, 3),
                    "attributes": {k: v for k, v in (s.attributes or {}).items()},
                }
            )
        return out
