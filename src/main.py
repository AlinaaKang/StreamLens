import argparse
import asyncio
import json
import threading
import traceback
import logging
import uuid
from contextlib import asynccontextmanager
from typing import Any, Dict, Iterable, AsyncIterable, AsyncGenerator, Optional
import cozeloop
import uvicorn
import time
from fastapi import FastAPI, HTTPException, Query, Request, UploadFile, File
from fastapi.responses import StreamingResponse, JSONResponse
from langchain_core.runnables import RunnableConfig
from langgraph.graph import StateGraph, END
from langgraph.graph.state import CompiledStateGraph
from coze_coding_utils.runtime_ctx.context import new_context, Context
from coze_coding_utils.helper import graph_helper
from coze_coding_utils.log.node_log import LOG_FILE
from coze_coding_utils.log.write_log import setup_logging, request_context
from coze_coding_utils.log.config import LOG_LEVEL
from coze_coding_utils.error.classifier import ErrorClassifier, classify_error
from coze_coding_utils.helper.stream_runner import AgentStreamRunner, WorkflowStreamRunner,agent_stream_handler,workflow_stream_handler, RunOpt
from storage.database.db import get_session, get_engine
from storage.memory.memory_saver import get_memory_saver
from storage.database.shared.model import Base
from coze_coding_utils.async_tasks import (
    AsyncTaskRuntime,
    AsyncTaskStorageError,
    extract_biz_context,
    parse_deadline_sec,
)
from coze_coding_utils.async_tasks import config as async_task_config
from coze_coding_utils.async_tasks.headers import HEADER_X_RUN_ID as _ASYNC_HEADER_X_RUN_ID
from coze_coding_utils.runtime_ctx.context import new_context as _new_async_ctx
from sqlalchemy import event

setup_logging(
    log_file=LOG_FILE,
    max_bytes=100 * 1024 * 1024, # 100MB
    backup_count=5,
    log_level=LOG_LEVEL,
    use_json_format=True,
    console_output=True
)

logger = logging.getLogger(__name__)
from coze_coding_utils.helper.agent_helper import to_stream_input, to_client_message
from coze_coding_utils.openai.handler import OpenAIChatHandler
from coze_coding_utils.log.parser import LangGraphParser
from coze_coding_utils.log.err_trace import extract_core_stack
from coze_coding_utils.log.loop_trace import init_run_config, init_agent_config


# 超时配置常量
TIMEOUT_SECONDS = 900  # 15分钟

class GraphService:
    def __init__(self):
        # 用于跟踪正在运行的任务（使用asyncio.Task）
        self.running_tasks: Dict[str, asyncio.Task] = {}
        # 错误分类器
        self.error_classifier = ErrorClassifier()
        # stream runner
        self._agent_stream_runner = AgentStreamRunner()
        self._workflow_stream_runner = WorkflowStreamRunner()
        self._graph = None
        self._graph_lock = threading.Lock()

    def set_graph(self, graph) -> None:
        """Inject the compiled graph used by sync endpoints. Called once from
        lifespan with a no-checkpointer build, so /run /stream_run /node_run
        never hit the checkpoint DB."""
        self._graph = graph

    def _get_graph(self, ctx=Context):
        if self._graph is not None:
            return self._graph
        with self._graph_lock:
            if self._graph is not None:
                return self._graph
            if graph_helper.is_agent_proj():
                self._graph = graph_helper.get_agent_instance("agents.agent", ctx)
            else:
                self._graph = graph_helper.get_graph_instance("graphs.graph")
            return self._graph

    @staticmethod
    def _sse_event(data: Any, event_id: Any = None) -> str:
        id_line = f"id: {event_id}\n" if event_id else ""
        return f"{id_line}event: message\ndata: {json.dumps(data, ensure_ascii=False, default=str)}\n\n"

    def _get_stream_runner(self):
        if graph_helper.is_agent_proj():
            return self._agent_stream_runner
        else:
            return self._workflow_stream_runner

    # 流式运行（原始迭代器）：本地调用使用
    def stream(self, payload: Dict[str, Any], run_config: RunnableConfig, ctx=Context) -> Iterable[Any]:
        graph = self._get_graph(ctx)
        stream_runner = self._get_stream_runner()
        for chunk in stream_runner.stream(payload, graph, run_config, ctx):
            yield chunk

    # 同步运行：本地/HTTP 通用
    async def run(self, payload: Dict[str, Any], ctx=None) -> Dict[str, Any]:
        if ctx is None:
            ctx = new_context("run")

        run_id = ctx.run_id
        logger.info(f"Starting run with run_id: {run_id}")

        try:
            graph = self._get_graph(ctx)
            # custom tracer
            run_config = init_run_config(graph, ctx)
            run_config.setdefault("configurable", {})["thread_id"] = ctx.run_id

            # 直接调用，LangGraph会在当前任务上下文中执行
            # 如果当前任务被取消，LangGraph的执行也会被取消
            return await graph.ainvoke(payload, config=run_config, context=ctx)

        except asyncio.CancelledError:
            logger.info(f"Run {run_id} was cancelled")
            return {"status": "cancelled", "run_id": run_id, "message": "Execution was cancelled"}
        except Exception as e:
            # 使用错误分类器分类错误
            err = self.error_classifier.classify(e, {"node_name": "run", "run_id": run_id})
            # 记录详细的错误信息和堆栈跟踪
            logger.error(
                f"Error in GraphService.run: [{err.code}] {err.message}\n"
                f"Category: {err.category.name}\n"
                f"Traceback:\n{extract_core_stack()}"
            )
            # 保留原始异常堆栈，便于上层返回真正的报错位置
            raise
        finally:
            # 清理任务记录
            self.running_tasks.pop(run_id, None)

    # 流式运行（SSE 格式化）：HTTP 路由使用
    async def stream_sse(self, payload: Dict[str, Any], ctx=None, run_opt: Optional[RunOpt] = None) -> AsyncGenerator[str, None]:
        if ctx is None:
            ctx = new_context(method="stream_sse")
        if run_opt is None:
            run_opt = RunOpt()

        run_id = ctx.run_id
        logger.info(f"Starting stream with run_id: {run_id}")
        graph = self._get_graph(ctx)
        if graph_helper.is_agent_proj():
            run_config = init_agent_config(graph, ctx)
        else:
            run_config = init_run_config(graph, ctx)  # vibeflow

        is_workflow = not graph_helper.is_agent_proj()

        try:
            async for chunk in self.astream(payload, graph, run_config=run_config, ctx=ctx, run_opt=run_opt):
                if is_workflow and isinstance(chunk, tuple):
                    event_id, data = chunk
                    yield self._sse_event(data, event_id)
                else:
                    yield self._sse_event(chunk)
        finally:
            # 清理任务记录
            self.running_tasks.pop(run_id, None)
            cozeloop.flush()

    # 取消执行 - 使用asyncio的标准方式
    def cancel_run(self, run_id: str, ctx: Optional[Context] = None) -> Dict[str, Any]:
        """
        取消指定run_id的执行

        使用asyncio.Task.cancel()来取消任务,这是标准的Python异步取消机制。
        LangGraph会在节点之间检查CancelledError,实现优雅的取消。
        """
        logger.info(f"Attempting to cancel run_id: {run_id}")

        # 查找对应的任务
        if run_id in self.running_tasks:
            task = self.running_tasks[run_id]
            if not task.done():
                # 使用asyncio的标准取消机制
                # 这会在下一个await点抛出CancelledError
                task.cancel()
                logger.info(f"Cancellation requested for run_id: {run_id}")
                return {
                    "status": "success",
                    "run_id": run_id,
                    "message": "Cancellation signal sent, task will be cancelled at next await point"
                }
            else:
                logger.info(f"Task already completed for run_id: {run_id}")
                return {
                    "status": "already_completed",
                    "run_id": run_id,
                    "message": "Task has already completed"
                }
        else:
            logger.warning(f"No active task found for run_id: {run_id}")
            return {
                "status": "not_found",
                "run_id": run_id,
                "message": "No active task found with this run_id. Task may have already completed or run_id is invalid."
            }

    # 运行指定节点：本地/HTTP 通用
    async def run_node(self, node_id: str, payload: Dict[str, Any], ctx=None) -> Any:
        if ctx is None or Context.run_id == "":
            ctx = new_context(method="node_run")

        _graph = self._get_graph()
        node_func, input_cls, output_cls = graph_helper.get_graph_node_func_with_inout(_graph.get_graph(), node_id)
        if node_func is None or input_cls is None:
            raise KeyError(f"node_id '{node_id}' not found")

        parser = LangGraphParser(_graph)
        metadata = parser.get_node_metadata(node_id) or {}

        _g = StateGraph(input_cls, input_schema=input_cls, output_schema=output_cls)
        _g.add_node("sn", node_func, metadata=metadata)
        _g.set_entry_point("sn")
        _g.add_edge("sn", END)
        _graph = _g.compile()

        run_config = init_run_config(_graph, ctx)
        return await _graph.ainvoke(payload, config=run_config)

    def graph_inout_schema(self) -> Any:
        if graph_helper.is_agent_proj():
            return {"input_schema": {}, "output_schema": {}}
        builder = getattr(self._get_graph(), 'builder', None)
        if builder is not None:
            input_cls = getattr(builder, 'input_schema', None) or self.graph.get_input_schema()
            output_cls = getattr(builder, 'output_schema', None) or self.graph.get_output_schema()
        else:
            logger.warning(f"No builder input schema found for graph_inout_schema, using graph input schema instead")
            input_cls = self.graph.get_input_schema()
            output_cls = self.graph.get_output_schema()

        return {
            "input_schema": input_cls.model_json_schema(), 
            "output_schema": output_cls.model_json_schema(),
            "code":0,
            "msg":""
        }

    async def astream(self, payload: Dict[str, Any], graph: CompiledStateGraph, run_config: RunnableConfig, ctx=Context, run_opt: Optional[RunOpt] = None) -> AsyncIterable[Any]:
        stream_runner = self._get_stream_runner()
        async for chunk in stream_runner.astream(payload, graph, run_config, ctx, run_opt):
            yield chunk


service = GraphService()

async_runtime: Optional[AsyncTaskRuntime] = None
async_graph: Optional[CompiledStateGraph] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    engine = get_engine()
    @event.listens_for(engine, "connect")
    def _set_utc(dbapi_conn, _):
        with dbapi_conn.cursor() as cur:
            cur.execute("SET TIME ZONE 'UTC'")
    checkpointer = get_memory_saver()
    if graph_helper.is_agent_proj():
        base = graph_helper.get_agent_instance("agents.agent", None)
        sync_graph = base.builder.compile(checkpointer=checkpointer)
    else:
        base = graph_helper.get_graph_instance("graphs.graph")
        sync_graph = base.builder.compile()
    global async_graph, async_runtime
    async_graph = base.builder.compile(checkpointer=checkpointer)
    service.set_graph(sync_graph)
    async_runtime = AsyncTaskRuntime(
        session_factory=get_session, engine=engine,
        graph=async_graph, checkpointer=checkpointer,
    )
    yield
    if async_runtime is not None:
        await async_runtime.shutdown()

app = FastAPI(lifespan=lifespan)

# OpenAI 兼容接口处理器
openai_handler = OpenAIChatHandler(service)


@app.post("/async_run")
async def http_async_run(request: Request) -> dict:
    try:
        payload = await request.json()
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in http_async_run: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {extract_core_stack()}")
    try:
        deadline_sec = parse_deadline_sec(request.headers)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 一个 ID 走到底：task_id == run_id == thread_id == ctx.run_id == coze_run_id。
    # 优先用上游 x-run-id；没传就生成 UUID。
    run_id = request.headers.get(_ASYNC_HEADER_X_RUN_ID) or uuid.uuid4().hex

    # ctx 在 handler scope 构造，与同步 /run 路径一致；后面 new_context 默认会
    # 给 run_id 一个新 UUID，同步路径也是显式覆盖（main.py /run 处），这里同理。
    ctx = _new_async_ctx(method="async_run", headers=request.headers)
    ctx.run_id = run_id
    request_context.set(ctx)  # 与其他 HTTP endpoint 一致：让日志组件拿到 run_id 等信息
    run_config = init_run_config(async_graph, ctx)
    run_config["recursion_limit"] = async_task_config.RECURSION_LIMIT
    run_config.setdefault("configurable", {})["thread_id"] = run_id

    biz_context = extract_biz_context(request.headers) or {}
    if graph_helper.is_agent_proj() and not (isinstance(payload, dict) and payload.get("messages")):
        try:
            client_msg, _ = to_client_message(payload)
            payload = to_stream_input(client_msg)
        except Exception as e:
            error_response = service.error_classifier.get_error_response(
                e, {"node_name": "http_async_run", "run_id": run_id})
            logger.error(
                f"failed to convert agent payload in http_async_run: "
                f"[{error_response['error_code']}] {error_response['error_message']}, "
                f"traceback: {traceback.format_exc()}", exc_info=True
            )
            raise HTTPException(
                status_code=400,
                detail={
                    "error_code": error_response["error_code"],
                    "error_message": error_response["error_message"],
                    "stack_trace": extract_core_stack(),
                },
            )

    try:
        return await async_runtime.submit(
            task_id=run_id,
            payload=payload,
            biz_context=biz_context,
            deadline_sec=deadline_sec,
            run_config=run_config,
            ctx=ctx,
        )
    except AsyncTaskStorageError as e:
        raise HTTPException(status_code=503,
                            detail=f"async-task storage unavailable: {e}")


@app.get("/task/{task_id}")
async def http_get_task(task_id: str) -> dict:
    try:
        row = await async_runtime.get(task_id)
    except AsyncTaskStorageError as e:
        raise HTTPException(status_code=503,
                            detail=f"async-task storage unavailable: {e}")
    if row is None:
        raise HTTPException(status_code=404, detail="task not found")
    return row


HEADER_X_RUN_ID = "x-run-id"
@app.post("/run")
async def http_run(request: Request) -> Dict[str, Any]:
    global result
    raw_body = await request.body()
    try:
        body_text = raw_body.decode("utf-8")
    except Exception as e:
        body_text = str(raw_body)
        raise HTTPException(status_code=400,
                            detail=f"Invalid JSON format: {body_text}, traceback: {traceback.format_exc()}, error: {e}")

    ctx = new_context(method="run", headers=request.headers)
    # 优先使用上游指定的 run_id，保证 cancel 能精确匹配
    upstream_run_id = request.headers.get(HEADER_X_RUN_ID)
    if upstream_run_id:
        ctx.run_id = upstream_run_id
    run_id = ctx.run_id
    request_context.set(ctx)

    logger.info(
        f"Received request for /run: "
        f"run_id={run_id}, "
        f"query={dict(request.query_params)}, "
        f"body={body_text}"
    )

    try:
        payload = await request.json()

        # 创建任务并记录 - 这是关键，让我们可以通过run_id取消任务
        task = asyncio.create_task(service.run(payload, ctx))
        service.running_tasks[run_id] = task

        try:
            result = await asyncio.wait_for(task, timeout=float(TIMEOUT_SECONDS))
        except asyncio.TimeoutError:
            logger.error(f"Run execution timeout after {TIMEOUT_SECONDS}s for run_id: {run_id}")
            task.cancel()
            try:
                result = await task
            except asyncio.CancelledError:
                return {
                    "status": "timeout",
                    "run_id": run_id,
                    "message": f"Execution timeout: exceeded {TIMEOUT_SECONDS} seconds"
                }

        if not result:
            result = {}
        if isinstance(result, dict):
            result["run_id"] = run_id
        return result

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in http_run: {e}, traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON format, {extract_core_stack()}")

    except asyncio.CancelledError:
        logger.info(f"Request cancelled for run_id: {run_id}")
        result = {"status": "cancelled", "run_id": run_id, "message": "Execution was cancelled"}
        return result

    except Exception as e:
        # 使用错误分类器获取错误信息
        error_response = service.error_classifier.get_error_response(e, {"node_name": "http_run", "run_id": run_id})
        logger.error(
            f"Unexpected error in http_run: [{error_response['error_code']}] {error_response['error_message']}, "
            f"traceback: {traceback.format_exc()}", exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error_code": error_response["error_code"],
                "error_message": error_response["error_message"],
                "stack_trace": extract_core_stack(),
            }
        )
    finally:
        cozeloop.flush()


HEADER_X_WORKFLOW_STREAM_MODE = "x-workflow-stream-mode"


def _register_task(run_id: str, task: asyncio.Task):
    service.running_tasks[run_id] = task


@app.post("/stream_run")
async def http_stream_run(request: Request):
    ctx = new_context(method="stream_run", headers=request.headers)
    # 优先使用上游指定的 run_id，保证 cancel 能精确匹配
    upstream_run_id = request.headers.get(HEADER_X_RUN_ID)
    if upstream_run_id:
        ctx.run_id = upstream_run_id
    workflow_stream_mode = request.headers.get(HEADER_X_WORKFLOW_STREAM_MODE, "").lower()
    workflow_debug = workflow_stream_mode == "debug"
    request_context.set(ctx)
    raw_body = await request.body()
    try:
        body_text = raw_body.decode("utf-8")
    except Exception as e:
        body_text = str(raw_body)
        raise HTTPException(status_code=400,
                            detail=f"Invalid JSON format: {body_text}, traceback: {extract_core_stack()}, error: {e}")
    run_id = ctx.run_id
    is_agent = graph_helper.is_agent_proj()
    logger.info(
        f"Received request for /stream_run: "
        f"run_id={run_id}, "
        f"is_agent_project={is_agent}, "
        f"query={dict(request.query_params)}, "
        f"body={body_text}"
    )
    try:
        payload = await request.json()
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in http_stream_run: {e}, traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON format:{extract_core_stack()}")

    if is_agent:
        stream_generator = agent_stream_handler(
            payload=payload,
            ctx=ctx,
            run_id=run_id,
            stream_sse_func=service.stream_sse,
            sse_event_func=service._sse_event,
            error_classifier=service.error_classifier,
            register_task_func=_register_task,
        )
    else:
        stream_generator = workflow_stream_handler(
            payload=payload,
            ctx=ctx,
            run_id=run_id,
            stream_sse_func=service.stream_sse,
            sse_event_func=service._sse_event,
            error_classifier=service.error_classifier,
            register_task_func=_register_task,
            run_opt=RunOpt(workflow_debug=workflow_debug),
        )

    response = StreamingResponse(stream_generator, media_type="text/event-stream")
    return response

@app.post("/cancel/{run_id}")
async def http_cancel(run_id: str, request: Request):
    """
    取消指定run_id的执行

    使用asyncio.Task.cancel()实现取消,这是Python标准的异步任务取消机制。
    LangGraph会在节点之间的await点检查CancelledError,实现优雅取消。
    """
    ctx = new_context(method="cancel", headers=request.headers)
    request_context.set(ctx)
    logger.info(f"Received cancel request for run_id: {run_id}")
    result = service.cancel_run(run_id, ctx)
    return result


@app.post(path="/node_run/{node_id}")
async def http_node_run(node_id: str, request: Request):
    raw_body = await request.body()
    try:
        body_text = raw_body.decode("utf-8")
    except UnicodeDecodeError:
        body_text = str(raw_body)
        raise HTTPException(status_code=400, detail=f"Invalid JSON format: {body_text}")
    ctx = new_context(method="node_run", headers=request.headers)
    request_context.set(ctx)
    logger.info(
        f"Received request for /node_run/{node_id}: "
        f"query={dict(request.query_params)}, "
        f"body={body_text}",
    )

    try:
        payload = await request.json()
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in http_node_run: {e}, traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=400, detail=f"Invalid JSON format:{extract_core_stack()}")
    try:
        return await service.run_node(node_id, payload, ctx)
    except KeyError:
        raise HTTPException(status_code=404,
                            detail=f"node_id '{node_id}' not found or input miss required fields, traceback: {extract_core_stack()}")
    except Exception as e:
        # 使用错误分类器获取错误信息
        error_response = service.error_classifier.get_error_response(e, {"node_name": node_id})
        logger.error(
            f"Unexpected error in http_node_run: [{error_response['error_code']}] {error_response['error_message']}, "
            f"traceback: {traceback.format_exc()}", exc_info=True
        )
        raise HTTPException(
            status_code=500,
            detail={
                "error_code": error_response["error_code"],
                "error_message": error_response["error_message"],
                "stack_trace": extract_core_stack(),
            }
        )
    finally:
        cozeloop.flush()


@app.post("/v1/chat/completions")
async def openai_chat_completions(request: Request):
    """OpenAI Chat Completions API 兼容接口"""
    ctx = new_context(method="openai_chat", headers=request.headers)
    request_context.set(ctx)

    logger.info(f"Received request for /v1/chat/completions: run_id={ctx.run_id}")

    try:
        payload = await request.json()
        return await openai_handler.handle(payload, ctx)
    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in openai_chat_completions: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON format")
    finally:
        cozeloop.flush()


@app.get("/health")
async def health_check():
    try:
        # 这里可以添加更多的健康检查逻辑
        return {
            "status": "ok",
            "message": "Service is running",
        }
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get(path="/graph_parameter")
async def http_graph_inout_parameter(request: Request):
    return service.graph_inout_schema()

def parse_args():
    parser = argparse.ArgumentParser(description="Start FastAPI server")
    parser.add_argument("-m", type=str, default="http", help="Run mode, support http,flow,node")
    parser.add_argument("-n", type=str, default="", help="Node ID for single node run")
    parser.add_argument("-p", type=int, default=5000, help="HTTP server port")
    parser.add_argument("-i", type=str, default="", help="Input JSON string for flow/node mode")
    return parser.parse_args()


def parse_input(input_str: str) -> Dict[str, Any]:
    """Parse input string, support both JSON string and plain text"""
    if not input_str:
        return {"text": "你好"}

    # Try to parse as JSON first
    try:
        return json.loads(input_str)
    except json.JSONDecodeError:
        # If not valid JSON, treat as plain text
        return {"text": input_str}

def start_http_server(port):
    workers = 1
    reload = False
    if graph_helper.is_dev_env():
        reload = True

    logger.info(f"Start HTTP Server, Port: {port}, Workers: {workers}")
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=reload, workers=workers)

# ---------------- Web UI（新增增量，勿改上方逻辑） ----------------
import os as _os
from fastapi.staticfiles import StaticFiles as _StaticFiles
from fastapi.responses import FileResponse as _FileResponse

WEB_DIR = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "web")

@app.get("/web", include_in_schema=False)
async def web_ui_index():
    """StreamLens 明鉴 · Prompt 与流量双域安全检测平台页面"""
    return _FileResponse(_os.path.join(WEB_DIR, "index.html"), headers={"Cache-Control": "no-cache, no-store, must-revalidate"})

# ---- PCAP 文件上传（对话端检测用） ----
_PCAP_UPLOAD_DIR = "/tmp/ts_uploads"
_os.makedirs(_PCAP_UPLOAD_DIR, exist_ok=True)
_PCAP_MAX_BYTES = 300 * 1024 * 1024

@app.post("/web/api/pcap/upload", include_in_schema=False)
async def web_pcap_upload(file: UploadFile = File(...)):
    """接收前端上传的 PCAP 文件，保存到服务器临时目录，返回路径供检测任务使用"""
    name = _os.path.basename(file.filename or "upload.pcap")
    ext = _os.path.splitext(name)[1].lower()
    if ext not in (".pcap", ".pcapng", ".cap"):
        return {"ok": False, "error": "仅支持 .pcap / .pcapng / .cap 文件"}
    safe = f"up_{int(time.time())}_{_re.sub(r'[^A-Za-z0-9._-]', '_', name)}"
    dest = _os.path.join(_PCAP_UPLOAD_DIR, safe)
    size = 0
    try:
        with open(dest, "wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > _PCAP_MAX_BYTES:
                    f.close()
                    _os.remove(dest)
                    return {"ok": False, "error": "文件超过 300MB 限制"}
                f.write(chunk)
    finally:
        try:
            await file.close()
        except Exception:
            pass
    return {"ok": True, "path": dest, "size": size, "name": name}

if _os.path.isdir(WEB_DIR):
    app.mount("/web/static", _StaticFiles(directory=WEB_DIR), name="web")

# ---- Web 侧边栏最近任务 API（增量） ----
from fastapi.responses import JSONResponse as _JSONResponse
from tools import case_store as _web_case_store_mod
from tools.case_store import case_store as _web_case_store

@app.get("/web/api/tasks", include_in_schema=False)
async def web_api_tasks():
    """最近任务列表（侧边栏展示）——仅安全对话产生的调查任务（Prompt/PCAP）；
    专业工作区学习面板（origin=workspace）与挑战/实验/评测任务不进入侧边栏"""
    items = [t for t in _web_case_store.list_tasks(limit=30)
             if t.get("mode") in ("prompt", "pcap") and t.get("origin", "chat") == "chat"]
    return items[:12]

@app.post("/web/api/tasks/{task_id}/open", include_in_schema=False)
async def web_api_task_open(task_id: str):
    """打开任务：设为当前案件，后续调查续接该任务上下文"""
    if not _web_case_store.get_task(task_id):
        return _JSONResponse({"error": "task not found"}, status_code=404)
    _web_case_store.set_current(task_id)
    return {"ok": True, "task_id": task_id}

@app.delete("/web/api/tasks/{task_id}", include_in_schema=False)
async def web_api_task_delete(task_id: str):
    """删除任务案件文件"""
    return {"ok": _web_case_store.delete_task(task_id)}

@app.post("/web/api/tasks/{task_id}/messages", include_in_schema=False)
async def web_api_task_append_messages(task_id: str, request: Request):
    """任务对话消息归档：前端 send 完成后追加本轮 user/assistant 消息，
    用于点击侧边栏「最近任务」时恢复该任务的历史对话（最多保留 100 条）"""
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    if not _web_case_store.get_task(task_id):
        return _JSONResponse({"ok": False, "message": "task not found"}, status_code=404)
    items = body.get("items") if isinstance(body.get("items"), list) else []
    if not items and isinstance(body.get("role"), str):
        items = [{"role": body.get("role"), "md": body.get("md", "")}]
    clean = []
    for it in items[:2]:
        role = str(it.get("role") or "user")[:16]
        md = str(it.get("md") or "")[:20000]
        if not md.strip():
            continue
        clean.append({"role": role, "md": md, "ts": int(time.time())})
    if not clean:
        return {"ok": False, "message": "empty items"}
    data = _web_case_store.get_task(task_id) or {}
    msgs = (data.get("messages") or []) + clean
    _web_case_store.update_task(task_id, messages=msgs[-100:])
    return {"ok": True, "count": min(len(msgs), 100)}


def _rebuild_task_flow_messages(data: dict) -> list:
    """归档消息为空时，从案件库真实数据重建任务工作过程消息（完整回到任务现场）。
    只使用真实发生的调查数据（目标/计划/工具动作/证据/报告），不虚构对话。"""
    mode = data.get("mode") or "prompt"
    name = {"prompt": "Prompt 安全调查", "pcap": "PCAP 数据调查"}.get(mode, "安全调查")
    msgs = []
    goal = (data.get("original_prompt") or "").strip()
    if not goal:
        files = [f.get("name") or f.get("file") for f in (data.get("pcap_files") or []) if (f.get("name") or f.get("file"))]
        goal = (f"对 {files[0]} 做一次{name}。" if files else f"发起一次{name}。")
    msgs.append({"role": "user", "md": goal})
    plan = data.get("plan") or []
    if plan:
        if isinstance(plan, list):
            lines = "\n".join(f"{i+1}. {str(p)[:160]}" for i, p in enumerate(plan[:8]))
        else:
            lines = str(plan)[:800]
        msgs.append({"role": "assistant", "md": f"📋 **调查计划**\n\n{lines}"})
    acts = data.get("actions") or []
    if acts:
        lines = "\n".join(f"- `{a.get('tool','tool')}`：{a.get('summary','')}" for a in acts[-10:])
        msgs.append({"role": "assistant", "md": f"🛠 **执行过程**（累计 {len(acts)} 步）\n\n{lines}"})
    evs = data.get("evidence") or []
    if evs:
        lines = []
        for e in evs[:6]:
            st = {"real": "🟢", "derived": "🟡", "simulated": "🟠"}.get(e.get("status"), "⚪")
            loc = f"（{e['location']}）" if e.get("location") else ""
            lines.append(f"- {st} **{e.get('evidence_id')}** · {e.get('summary','')}{loc}（置信度 {e.get('confidence','-')}）")
        more = f"\n- … 共 {len(evs)} 条" if len(evs) > 6 else ""
        msgs.append({"role": "assistant", "md": f"🧾 **证据清单**（{len(evs)} 条）\n\n" + "\n".join(lines) + more})
    if data.get("report_url"):
        msgs.append({"role": "assistant", "md": f"📄 **正式报告已生成**：[下载报告]({data['report_url']})"})
    return msgs


def _supplement_archived_msgs(data: dict, existing_md: str = "") -> list:
    """归档半截时的补充段：从案件库真实记录重建执行过程/证据/报告链接（不虚构对话）。
    existing_md 用于去重：与已展示内容相同的段不再重复追加。"""
    msgs = []
    acts = data.get("actions") or []
    if acts:
        lines = "\n".join(f"- `{a.get('tool','tool')}`：{a.get('summary','')}" for a in acts[-10:])
        seg = f"🛠 **执行过程（补充档案，当时会话归档不完整）**（累计 {len(acts)} 步）\n\n{lines}"
        if (lines[:80] not in existing_md) or not existing_md:
            msgs.append({"role": "assistant", "md": seg})
    evs = data.get("evidence") or []
    if evs:
        lines = []
        for e in evs[:8]:
            st = {"real": "🟢", "derived": "🟡", "simulated": "🟠"}.get(e.get("status"), "⚪")
            loc = f"（{e['location']}）" if e.get("location") else ""
            lines.append(f"- {st} **{e.get('evidence_id')}** · {e.get('summary','')}{loc}（置信度 {e.get('confidence','-')}）")
        more = f"\n- … 共 {len(evs)} 条" if len(evs) > 8 else ""
        msgs.append({"role": "assistant", "md": f"🧾 **证据清单**（{len(evs)} 条）\n\n" + "\n".join(lines) + more})
    if data.get("report_url"):
        msgs.append({"role": "assistant", "md": f"📄 **正式报告**：[下载报告]({data['report_url']})"})
    return msgs


@app.get("/web/api/tasks/{task_id}/messages", include_in_schema=False)
async def web_api_task_messages(task_id: str):
    """读取任务归档的对话消息 + 任务上下文（证据/工具），用于完整回到任务现场"""
    data = _web_case_store.get_task(task_id)
    if not data:
        return {"ok": False, "messages": [], "evidence": [], "tools": []}
    msgs = data.get("messages") or []
    ev_out = [{
        "id": e.get("evidence_id") or f"E-{i+1:03d}",
        "status": e.get("status") or "real",
        "summary": e.get("summary") or "",
        "conf": e.get("confidence") if e.get("confidence") is not None else "-",
    } for i, e in enumerate(data.get("evidence") or [])]
    tools = [{"name": a.get("tool") or "tool", "detail": (a.get("summary") or "")[:140], "at": ""}
             for a in (data.get("actions") or [])][-8:]
    if not msgs:
        msgs = _rebuild_task_flow_messages(data)
    # 半截归档保护：无论归档/重建，最后一条 assistant 内容异常短时都追加案件库补充档案
    last_asst = next((m for m in reversed(msgs) if (m.get("role") == "assistant")), None)
    if last_asst and len(last_asst.get("md") or "") < 500:
        msgs = msgs + _supplement_archived_msgs(data, existing_md=last_asst.get("md") or "")
    return {"ok": True, "messages": msgs, "evidence": ev_out, "tools": tools}

# ---- Prompt 安全分析面板 API（增量） ----
import re as _re
from datetime import datetime as _dt
from tools.prompt_tools import run_prompt_analysis as _run_prompt_analysis
from tools.entropy_detector import compute_entropy_profile_adaptive as _entropy_profile, compute_window_nll_adaptive as _entropy_nll, WINDOW_SIZE as _ENTROPY_WINDOW
from tools.knowledge_tool import search_knowledge as _search_knowledge
from tools.report_tool import _build_report_for_task as _build_report

_SAMPLES_PATH = _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "assets", "challenge", "samples.json")

def _load_samples():
    with open(_SAMPLES_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else data.get("samples", [])

@app.get("/web/api/prompt/samples", include_in_schema=False)
async def web_api_prompt_samples():
    """冻结测试样本列表（仅元数据，原文不返回给前端）"""
    try:
        return [{"id": s.get("id"), "family": s.get("family"), "label": s.get("label"),
                 "length": len(s.get("text", ""))} for s in _load_samples()]
    except Exception as e:
        return _JSONResponse({"error": str(e)}, status_code=500)


def _parse_kb_chunk(content: str) -> dict:
    """把知识库返回的 markdown 片段解析为结构化证据条目（全部来自真实检索内容）"""
    lines = [l.rstrip() for l in (content or "").split("\n") if l.strip()]
    title, source, summary, points = "未命名知识条目", "内部知识", "", []
    body_lines = []
    for l in lines:
        st = l.strip()
        if st.startswith("#"):
            if title == "未命名知识条目":
                title = st.lstrip("#").strip()
            continue
        if st.startswith("-"):
            points.append(st.lstrip("- ").strip())
            continue
        body_lines.append(st)
    joined = " ".join(body_lines) + " " + title
    low = joined.lower()
    if "atlas" in low or "mitre" in low:
        source = "MITRE"
    elif "nist" in low:
        source = "NIST"
    elif "owasp" in low:
        source = "OWASP"
    elif "标识" in joined or "管理要求" in joined or "cac" in low:
        source = "CAC"
    if not points and len(body_lines) > 1:
        points = [l[:60] for l in body_lines[1:3]]
    summary = (body_lines[0] if body_lines else (points[0] if points else title))[:110]
    slug_map = {"MITRE": "mitre-atlas", "NIST": "nist-ai-rmf", "OWASP": "owasp-llm-top10", "CAC": "cac-genai", "内部知识": "internal-kb"}
    ref_slug = slug_map.get(source, "internal-kb")
    return {"source": source, "title": title, "ref": title, "summary": summary, "points": points[:4], "ref_slug": ref_slug}

@app.post("/web/api/prompt/analyze", include_in_schema=False)
async def web_api_prompt_analyze(payload: dict):
    """表单式 Prompt 安全分析：三路检测 + 熵轨道 + 知识增强（可选同时生成报告）"""
    payload = payload or {}
    text = (payload.get("prompt_text") or "").strip()
    sample_id = (payload.get("sample_id") or "").strip()
    knowledge_mode = payload.get("knowledge_mode") or "off"  # off | evidence | evidence_report
    sample_meta = None
    used_sample = False
    if sample_id:
        try:
            match = [s for s in _load_samples() if s.get("id") == sample_id]
        except Exception as e:
            return _JSONResponse({"error": str(e)}, status_code=500)
        if not match:
            return _JSONResponse({"error": f"sample {sample_id} not found"}, status_code=404)
        s = match[0]
        sample_meta = {"id": s.get("id"), "family": s.get("family"), "label": s.get("label")}
        if not text:
            text = (s.get("text") or "").strip()
            used_sample = True
    if not text:
        return _JSONResponse({"error": "prompt_text is required"}, status_code=400)
    if len(text) > 32768:
        return _JSONResponse({"error": "prompt too long (max 32768 chars)"}, status_code=400)

    task_id = _web_case_store.create_task("prompt", title="Prompt 安全分析", origin="workspace")
    try:
        result = _run_prompt_analysis(text, task_id, add_evidence=True, scene="analysis")  # 面板=analysis 场景: 语义安全+CPD 告警→人工复核（纯统计异常不拦截）
    except Exception as e:
        logger.error(f"web prompt analyze failed: {e}")
        return _JSONResponse({"error": f"analysis failed: {e}"}, status_code=500)
    _web_case_store.update_task(task_id, original_prompt=text)
    try:
        _cpd_top_ev = (result.get("cpd_candidates") or [{}])[0]
        _audit_events.record_event(
            text=text, risk_level=result.get("risk_level"),
            action=result.get("action") or "放行",
            cpd_onset=_cpd_top_ev.get("position"),
            cpd_conf=_cpd_top_ev.get("confidence"),
            mode=knowledge_mode, model_version=result.get("semantic_model"),
            latency_ms=result.get("detect_latency_ms"), source="panel",
            tokens=len(text), task_id=task_id,
        )
    except Exception as _ev_err:
        logger.warning(f"audit event failed: {_ev_err}")
    _web_case_store.log_action(task_id, "web_prompt_analyze", f"面板三路检测完成，判级 {result.get('risk_level')}")
    _web_case_store.update_task(task_id, last_risk_level=result.get("risk_level") or "none")

    profile = _entropy_profile(text)
    nll_points = _entropy_nll(text)

    knowledge = None
    knowledge_struct = []
    if knowledge_mode in ("evidence", "evidence_report") and result.get("risk_level") not in (None, "none"):
        q_types = sorted({str(e.get("risk_type") or "") for e in result.get("evidence", []) if e.get("source") == "semantic_scan" and e.get("risk_type")})
        query = " ".join(q_types) or "prompt injection 防御与处置"
        try:
            chunks = _kb_search_struct(query, top_k=2, min_score=0.25)
            try:
                gov = _kb_search_struct("NIST AI RMF OWASP ATLAS 风险处置 事件响应 合规框架", top_k=3, min_score=0.3)
            except Exception:
                gov = []
            seen, merged = set(), []
            for c in chunks + gov:
                key = c["content"][:60]
                if key in seen:
                    continue
                seen.add(key)
                merged.append(c)
            chunks = merged[:4]
            knowledge_struct = [_parse_kb_chunk(c["content"]) for c in chunks]
            knowledge = "\n\n".join(f"[知识{i}] (相关度 {c['score']:.2f})\n{c['content']}" for i, c in enumerate(chunks, 1))
        except Exception as e:
            logger.warning(f"web kb search failed: {e}")

    report_url = None
    report_msg = None
    if knowledge_mode == "evidence_report":
        rep = _build_report(task_id)
        m = _re.search(r"https?://\S+", rep or "")
        report_url = m.group(0).rstrip("）)。") if m else None
        report_msg = (rep or "").split("\n")[0]

    # ---- 处置动作（固定策略融合，真实判定结果） ----
    lv = result.get("risk_level") or "none"
    cpd_top = (result.get("cpd_candidates") or [{}])[0]
    action = result.get("action") or "放行"
    # 融合风险分：语义三档基础分 + alarm 加成（与权威 risk_score 口径一致，不再取证据置信度最大值）
    _sev = result.get("semantic_severity") or "unavailable"
    _alarm = result.get("detector_status") == "token_anomaly_candidate"
    risk_score = round(min(1.0, (0.0 if _sev == "safe" else 0.45 if _sev == "controversial"
                                 else 0.5 if _sev == "unavailable" else 0.8)
                           + (0.2 if _alarm else 0.0)), 2)

    ent = profile
    trace = [
        {"key": "mask", "label": "脱敏接收", "ok": True,
         "detail": f"输入 {len(text)} 字符" + ("（冻结样本，仅传 ID）" if used_sample else "") + "；已写入案件审计日志"},
        {"key": "semantic", "label": "语义检测", "ok": result.get("semantic_status") == "real",
         "detail": f"状态 {result.get('semantic_status')} · 模型 {result.get('semantic_model')}"
                   + (f" · 延迟 {result.get('semantic_latency_ms')} ms" if result.get("semantic_latency_ms") else "")},
        {"key": "token", "label": "Token 观测", "ok": bool(ent.get("valid")),
         "detail": f"滑窗熵基线 均值 {ent.get('mean')} / 标准差 {ent.get('std')}" if ent.get("valid") else "文本短于滑窗，熵观测不可用"},
        {"key": "cpd", "label": "CPD 判断", "ok": bool(result.get("cpd_valid")),
         "detail": (f"{len(result.get('cpd_candidates') or [])} 个候选（{_alarm and 'alarm 级' or '观察级，未触发 alarm'}）· 算法 {_CPD_ALGO_VERSION}") if result.get("cpd_valid") else "无候选"},
        {"key": "fuse", "label": "证据融合", "ok": True,
         "detail": f"融合规则 {result.get('fusion_reason') or 'all_clear'} · 共 {len(result.get('evidence') or [])} 条证据（real=真实检测，derived=数学推导）"},
        {"key": "action", "label": "处置决策", "ok": True,
         "detail": f"最终处置：{action}" + (f" · 风险分数 {risk_score} / 1.0" if risk_score else "") + " · 处置来自固定策略融合"},
    ]

    meta = {
        "action": action,
        "raw_score": risk_score,
        "semantic_model": result.get("semantic_model"),
        "semantic_latency_ms": result.get("semantic_latency_ms"),
        "onset": (f"字符 {cpd_top.get('position')}" if _alarm else "--"),
        "detector_status": result.get("detector_status"),
        "semantic_severity": _sev,
        "fusion_reason": result.get("fusion_reason"),
        "mask_audit": "已写入案件审计",
        "detect_latency_ms": result.get("detect_latency_ms"),
        "calib_version": _CPD_ALGO_VERSION,
        "entropy_k_h": f"{ent.get('mean', 0)} / {ent.get('std', 0)}",
    }

    # ---- 模板降级报告（真实拼接检测结果与知识证据摘要，无固定话术伪造） ----
    template_report = None
    if knowledge_mode == "evidence_report":
        level_cn = {"high": "高风险", "medium": "中风险", "low": "低风险", "none": "未发现风险"}.get(lv, lv)
        ev_summ = "；".join(f"《{k['title']}》：{k['summary'][:60]}" for k in knowledge_struct if k.get("summary")) or "未命中结构化证据"
        action_steps = {
            "拦截": "阻断该输入进入下游执行链；记录完整证据链与命中模式；将确认失败转化为检测规则与回归用例。",
            "人工复核": "转人工复核队列并标注风险类别；复核通过后放行，未通过则拦截并沉淀规则；记录残余风险与后续复测计划。",
            "放行": "按常规流程放行；记录本次检测结论；持续监测后续交互中的分布漂移。",
            "待授权复核": "输出疑似结论与证据链；处置类动作（封禁/隔离）待用户明确授权后执行；复核期间按中高风险持续监测。",
        }
        action_detail = action_steps.get(action) or action_steps.get("人工复核") or action_steps["放行"]
        template_report = {
            "body": f"基础检测判定：{level_cn}。本地知识证据：{ev_summ}。",
            "steps": action_detail,
            "refs": sorted({k["ref_slug"] for k in knowledge_struct if k.get("ref_slug")}),
            "limits": "知识证据不改变基础判定动作。",
        }

    return {
        "task_id": task_id,
        "risk_level": result.get("risk_level"),
        "semantic_status": result.get("semantic_status"),
        "semantic_severity": _sev,
        "semantic_categories": result.get("semantic_categories", []),
        "detector_status": result.get("detector_status"),
        "fusion_reason": result.get("fusion_reason"),
        "decision": result.get("decision"),
        "cpd_top_confidence": result.get("cpd_top_confidence"),
        "cpd_status": result.get("cpd_status"),
        "cpd_candidates": result.get("cpd_candidates", []),
        "cpd_limitations": result.get("cpd_limitations", []),
        "marker_hits": result.get("marker_hits", []),
        "evidence": result.get("evidence", []),
        "knowledge": knowledge,
        "report_url": report_url,
        "report_msg": report_msg,
        "entropy": {
            "series": [[pos, round(v, 4)] for pos, v in profile.get("series", [])],
            "nll": [[pos, round(v, 4)] for pos, v in nll_points],
            "mean": round(profile.get("mean", 0.0), 4),
            "std": round(profile.get("std", 0.0), 4),
            "length": profile.get("length", 0),
            "valid": profile.get("valid", False),
            "window": _ENTROPY_WINDOW,
            "window_used": profile.get("window_used", _ENTROPY_WINDOW),
            "degraded": profile.get("degraded", False),
        },
        "length": len(text),
        "source": "sample" if used_sample else "custom",
        "sample_id": sample_id or None,
        "sample_meta": sample_meta,
        "action": action,
        "risk_score": risk_score,
        "decision_trace": trace,
        "meta": meta,
        "knowledge_struct": knowledge_struct,
        "template_report": template_report,
    }

from tools.knowledge_tool import search_knowledge_struct as _kb_search_struct
from tools.entropy_detector import ALGO_VERSION as _CPD_ALGO_VERSION
from tools import audit_events as _audit_events


# ---- 安全事件（脱敏审计） ----
@app.get("/web/api/events", include_in_schema=False)
async def web_api_events(limit: int = 80):
    evs = _audit_events.read_events(limit=min(max(limit, 1), 200))
    return {"events": evs, "summary": _audit_events.summarize(evs)}

@app.post("/web/api/kb/search", include_in_schema=False)
async def web_api_kb_search(payload: dict):
    """安全知识库语义检索（知识库页内联展示，无对话框）"""
    query = str((payload or {}).get("query") or "").strip()
    if not query:
        return _JSONResponse({"error": "query is required"}, status_code=400)
    try:
        results = _kb_search_struct(query, top_k=5, min_score=0.3)
    except Exception as e:
        logger.error(f"kb search failed: {e}")
        return _JSONResponse({"error": f"kb search failed: {e}"}, status_code=500)
    return {"ok": True, "query": query, "results": results}


# ---- 评测中心 / PCAP 画像 / PCAP 数据调查工作区 ----
from tools import pcap_eval_service as _pcap_eval_service
from tools import pcap_profile as _pcap_profile
from tools import superagent_service as _superagent

# ---- 红蓝攻防实验（回合制对抗，真实检测裁决）----
from tools import adversary_service as _adversary


def _adv_body(awaitable):
    try:
        return awaitable
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/web/api/adversary/prompt/state", include_in_schema=False)
async def web_api_adv_prompt_state():
    return _adversary.prompt_state()


@app.post("/web/api/adversary/prompt/red", include_in_schema=False)
async def web_api_adv_prompt_red(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    payload = str(body.get("payload") or "").strip()
    if not payload:
        raise HTTPException(status_code=400, detail="payload 不能为空")
    if len(payload) > 8000:
        raise HTTPException(status_code=400, detail="payload 过长（上限 8000 字符）")
    return _adversary.prompt_red_turn(payload)


@app.post("/web/api/adversary/prompt/blue/start", include_in_schema=False)
async def web_api_adv_prompt_blue_start():
    return _adversary.prompt_blue_start()


@app.post("/web/api/adversary/prompt/blue", include_in_schema=False)
async def web_api_adv_prompt_blue(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    guess = str(body.get("guess") or "").strip()
    level = str(body.get("level") or "").strip()
    if guess not in ("attack", "normal"):
        raise HTTPException(status_code=400, detail="guess 必须为 attack / normal")
    if level not in ("high", "medium", "low", "none"):
        raise HTTPException(status_code=400, detail="level 必须为 high / medium / low / none")
    return _adversary.prompt_blue_turn(guess, level)


@app.post("/web/api/adversary/prompt/reset", include_in_schema=False)
async def web_api_adv_prompt_reset():
    return _adversary.prompt_reset()


@app.get("/web/api/adversary/pcap/state", include_in_schema=False)
async def web_api_adv_pcap_state():
    return _adversary.pcap_state()


@app.post("/web/api/adversary/pcap/red", include_in_schema=False)
async def web_api_adv_pcap_red(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    kind = str(body.get("kind") or "").strip()
    params = body.get("params") if isinstance(body.get("params"), dict) else {}
    return _adversary.pcap_red_turn(kind, params)


@app.post("/web/api/adversary/pcap/blue/start", include_in_schema=False)
async def web_api_adv_pcap_blue_start():
    return _adversary.pcap_blue_start()


@app.post("/web/api/adversary/pcap/blue", include_in_schema=False)
async def web_api_adv_pcap_blue(request: Request):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON")
    guess = str(body.get("guess") or "").strip()
    if guess not in ("port_scan", "bruteforce", "c2", "sql_injection", "normal"):
        raise HTTPException(status_code=400, detail="guess 取值: port_scan / bruteforce / c2 / sql_injection / normal")
    return _adversary.pcap_blue_turn(guess)


@app.post("/web/api/adversary/pcap/reset", include_in_schema=False)
async def web_api_adv_pcap_reset():
    return _adversary.pcap_reset()


async def web_api_eval_summary():
    return _eval_service.get_summary()


@app.post("/web/api/pcap/eval/run", include_in_schema=False)
async def web_api_pcap_eval_run():
    r = _pcap_eval_service.run_async()
    return _JSONResponse(r, status_code=200 if r.get("ok") else 409)


@app.get("/web/api/pcap/eval/summary", include_in_schema=False)
async def web_api_pcap_eval_summary():
    return _pcap_eval_service.get_summary()


@app.get("/web/api/pcap/profile", include_in_schema=False)
async def web_api_pcap_profile(force: int = 0):
    return _pcap_profile.profile_all(force=bool(force))


@app.post("/web/api/pcap/superagent/prepare", include_in_schema=False)
async def web_api_superagent_prepare(payload: dict):
    limit = (payload or {}).get("limit") or 10
    r = _superagent.prepare(limit)
    return _JSONResponse(r, status_code=200 if r.get("ok") else 400)


@app.post("/web/api/pcap/superagent/run", include_in_schema=False)
async def web_api_superagent_run(payload: dict):
    batch_id = str((payload or {}).get("batch_id") or "")
    token = str((payload or {}).get("confirm_token") or "")
    r = _superagent.authorize_and_run(batch_id, token)
    return _JSONResponse(r, status_code=200 if r.get("ok") else 400)


@app.post("/web/api/pcap/superagent/retry", include_in_schema=False)
async def web_api_superagent_retry(payload: dict):
    batch_id = str((payload or {}).get("batch_id") or "")
    anon_id = str((payload or {}).get("anon_id") or "")
    r = _superagent.retry(batch_id, anon_id)
    return _JSONResponse(r, status_code=200 if r.get("ok") else 400)


@app.get("/web/api/pcap/superagent/batch", include_in_schema=False)
async def web_api_superagent_batch(batch_id: str = ""):
    if not batch_id:
        return _superagent.list_batches()
    return _superagent.get_batch(batch_id)


# ---- 侦探挑战面板 API（Token 侦探挑战：关卡选择 + 互动/自动演示） ----
from tools.challenge_tools import _challenge_start_core as _ch_start_core
from tools.challenge_tools import _challenge_answer_core as _ch_answer_core
from tools.challenge_tools import challenge_report_view as _ch_report_view


@app.post("/web/api/challenge/start", include_in_schema=False)
async def web_api_challenge_start(payload: dict):
    """开始/继续挑战：rounds=3（三关速战）或 5（五关完整挑战）。

    - 携带 task_id 且该局有进行中的轮次 → 续局（返回当前轮，修复"只有第一轮"）
    - 不带 task_id → 新建一局
    取证报告在后台线程预计算（真实三路检测），避免 LLM 阻塞事件循环。
    """
    body = payload or {}
    rounds = int(body.get("rounds") or 0)
    rounds = max(0, min(5, rounds))
    group = str(body.get("group") or "")
    task_id = str(body.get("task_id") or "")
    if not task_id or not _web_case_store.get_task(task_id):
        task_id = _web_case_store.create_task("challenge", title="Token 侦探挑战", origin="workspace")
    try:
        data = _ch_start_core(task_id, group, rounds)
    except Exception as e:
        logger.error(f"challenge start failed: {e}")
        return _JSONResponse({"error": f"challenge start failed: {e}"}, status_code=500)
    return data


@app.post("/web/api/challenge/answer", include_in_schema=False)
async def web_api_challenge_answer(payload: dict):
    """提交本轮研判；auto=true 时由三路检测引擎自动作答（自动演示）。

    判分优先使用预计算报告（毫秒级）；兜底路径放线程执行避免阻塞事件循环。
    """
    body = payload or {}
    task_id = str(body.get("task_id") or "")
    if not task_id or not _web_case_store.get_task(task_id):
        return _JSONResponse({"error": "task not found"}, status_code=404)
    try:
        # 注意：必须用关键字参数——core 签名为 (task_id, decision, relation,
        # onset_token, onset_char, auto)，位置传参会导致 auto 误落到 onset_char。
        # onset_token 仅 agent 工具链使用；web 端只传 onset_char（字符位置，
        # 由 core 内 _to_token 走 signals 映射成 token）。
        out = await asyncio.to_thread(
            _ch_answer_core,
            task_id,
            decision=str(body.get("decision") or ""),
            relation=str(body.get("relation") or ""),
            onset_token=body.get("onset_token"),
            onset_char=body.get("onset_char"),
            auto=bool(body.get("auto")),
        )
    except Exception as e:
        logger.error(f"challenge answer failed: {e}")
        return _JSONResponse({"error": f"challenge answer failed: {e}"}, status_code=500)
    if out.get("error"):
        return _JSONResponse(out, status_code=400)
    return out


@app.get("/web/api/challenge/report", include_in_schema=False)
async def web_api_challenge_report(task_id: str = ""):
    """侦探回放数据：status=preparing 时前端轮询；done 时返回三位侦探公开汇报与曲线序列"""
    if not task_id or not _web_case_store.get_task(task_id):
        return _JSONResponse({"error": "task not found"}, status_code=404)
    try:
        return _ch_report_view(task_id)
    except Exception as e:
        logger.error(f"challenge report failed: {e}")
        return _JSONResponse({"error": f"challenge report failed: {e}"}, status_code=500)


@app.get("/web/api/challenge/state", include_in_schema=False)
async def web_api_challenge_state(task_id: str = ""):
    """查询挑战进度（历史轮次与累计得分）"""
    data = _web_case_store.get_task(task_id) or {}
    history = data.get("challenge_history", [])
    return {
        "task_id": task_id,
        "order": data.get("challenge_order") or [],
        "history": history,
        "current": bool(data.get("challenge_current")),
        "total_score": sum(int(h.get("score", 0)) for h in history),
    }


from tools.knowledge_tool import search_knowledge_struct as _kb_search_struct


@app.post("/web/api/kb/search", include_in_schema=False)
async def web_api_kb_search(payload: dict):
    """安全知识库语义检索（知识库页内联展示，无对话框）"""
    query = str((payload or {}).get("query") or "").strip()
    if not query:
        return _JSONResponse({"error": "query is required"}, status_code=400)
    try:
        results = _kb_search_struct(query, top_k=5, min_score=0.3)
    except Exception as e:
        logger.error(f"kb search failed: {e}")
        return _JSONResponse({"error": f"kb search failed: {e}"}, status_code=500)
    return {"ok": True, "query": query, "results": results}


# ---- PCAP 侦探挑战（内置脱敏关卡）----
from tools.pcap_challenge_data import get_level as _pc_get_level, judge as _pc_judge

@app.get("/web/api/pcap-challenge/level", include_in_schema=False)
async def web_api_pc_level(level_id: str = "", exclude: str = ""):
    """默认第一关；exclude 用于“换一关”随机去重（不含答案），组装前端渲染结构"""
    d = _pc_get_level(level_id or None, exclude or None)
    if d.get("error"):
        return _JSONResponse(d, status_code=404)
    groups = list(dict.fromkeys(p.get("group", "") for p in d.get("packets", [])))
    d["options"] = {
        "packet_groups": groups,
        "attack_types": d.pop("attack_types", []),
        "attack_goals": d.pop("attack_goals", []),
    }
    d["order_tip"] = "按 Packet 分组研判：先看每组方向与载荷变化，再对照底部小队线索逐组排查。"
    return d

@app.post("/web/api/pcap-challenge/submit", include_in_schema=False)
async def web_api_pc_submit(payload: dict):
    """提交研判并展露预设答案"""
    p = payload or {}
    try:
        return _pc_judge(str(p.get("level_id") or ""), str(p.get("packet_group") or ""),
                         str(p.get("attack_type") or ""), str(p.get("attack_goal") or ""))
    except Exception as e:
        logger.error(f"pcap challenge submit failed: {e}")
        return _JSONResponse({"error": str(e)}, status_code=500)





@app.post("/web/api/session/bind", include_in_schema=False)
async def web_api_session_bind(request: Request):
    """前端会话绑定：session_id（web-xxx / task-XXX）——同一会话内检测共用同一案件"""
    try:
        data = await request.json()
    except Exception:
        data = {}
    if data.get("task_id"):
        _web_case_store_mod.bind_session(task_id=str(data["task_id"]))
        return _JSONResponse({"ok": True, "task_id": str(data["task_id"])})
    if data.get("session_id"):
        sk = str(data["session_id"])
        _web_case_store_mod.bind_session(session_key=sk)
        m = _web_case_store_mod._load_session_map()
        return _JSONResponse({"ok": True, "task_id": m.get(sk, "") or ""})
    return _JSONResponse({"ok": True, "task_id": ""})


@app.get("/web/api/session/task", include_in_schema=False)
async def web_api_session_task(request: Request):
    """查询会话绑定的案件 id（供前端跨轮归档对话；未绑定返回空串）"""
    sid = str(request.query_params.get("session_id", "") or "")
    m = _web_case_store_mod._load_session_map()
    return _JSONResponse({"task_id": m.get(sid, "") or ""})


@app.post("/web/api/report/{task_id}", include_in_schema=False)
async def web_api_report(task_id: str):
    """为指定案件生成正式 PDF 报告"""
    if not _web_case_store.get_task(task_id):
        return _JSONResponse({"error": "task not found"}, status_code=404)
    rep = _build_report(task_id)
    m = _re.search(r"https?://\S+", rep or "")
    url = m.group(0).rstrip("）)。") if m else None
    if url:
        try:
            _web_case_store.update_task(task_id, report_url=url,
                                        report_generated_at=_dt.now().isoformat(timespec="seconds"))
        except Exception as e:
            logger.warning(f"report record writeback failed: {e}")
    return {"task_id": task_id, "ok": bool(m),
            "report_url": url,
            "message": (rep or "").split("\n")[0]}


def _report_buckets():
    """扫描全部案件，按调查类型分组：Prompt 调查 / PCAP 调查（组内按生成时间倒序）"""
    from datetime import datetime as _dtm
    groups = {"prompt": [], "pcap": []}
    labels = {"prompt": "Prompt 调查报告", "pcap": "PCAP 调查报告"}
    try:
        import glob as _glob
        import os as _os
        for path in sorted(_glob.glob(_os.path.join(_web_case_store_mod.CASES_DIR, "*.json")),
                           key=lambda p: -_os.path.getmtime(p)):
            try:
                d = json.load(open(path, encoding="utf-8"))
            except Exception:
                continue
            url = d.get("report_url")
            if not url:
                continue
            gen = d.get("report_generated_at") or ""
            mode_v = (d.get("mode") or "")
            title_v = d.get("title") or ""
            key = "pcap" if (mode_v == "pcap" or "PCAP" in title_v.upper()) else "prompt"
            groups[key].append({
                "task_id": d.get("task_id"),
                "title": (d.get("title") or "安全调查任务")[:60],
                "mode": d.get("mode") or "",
                "report_url": url,
                "generated_at": gen.replace("T", " ")[:19] or _dtm.fromtimestamp(_os.path.getmtime(path)).strftime("%Y-%m-%d %H:%M"),
                "status": d.get("status") or "",
            })
    except Exception as e:
        logger.error(f"report list failed: {e}")
    out = [{"key": k, "label": labels[k], "items": groups[k]} for k in ("prompt", "pcap") if groups[k]]
    return {"ok": True, "total": sum(len(g["items"]) for g in out), "groups": out}


@app.get("/web/api/reports", include_in_schema=False)
async def web_api_reports():
    """调查报告列表（按生成时间分组）"""
    return _report_buckets()


@app.delete("/web/api/reports/{task_id}", include_in_schema=False)
async def web_api_report_delete(task_id: str):
    """从报告列表移除（仅清除报告记录，不删除案件）"""
    d = _web_case_store.get_task(task_id)
    if not d:
        return _JSONResponse({"error": "task not found"}, status_code=404)
    _web_case_store.update_task(task_id, report_url=None, report_generated_at=None)
    return {"ok": True, "task_id": task_id}


@app.post("/web/api/reports/{task_id}/export", include_in_schema=False)
async def web_api_report_export(task_id: str):
    """导出/重新生成报告：生成新的 24h 有效对象存储链接"""
    if not _web_case_store.get_task(task_id):
        return _JSONResponse({"error": "task not found"}, status_code=404)
    rep = _build_report(task_id)
    m = _re.search(r"https?://\S+", rep or "")
    url = m.group(0).rstrip("）)。") if m else None
    if url:
        try:
            _web_case_store.update_task(task_id, report_url=url,
                                        report_generated_at=_dt.now().isoformat(timespec="seconds"))
        except Exception as e:
            logger.warning(f"report export writeback failed: {e}")
        return {"ok": True, "task_id": task_id, "report_url": url}
    return _JSONResponse({"error": (rep or "report generation failed")[:200]}, status_code=500)

if __name__ == "__main__":
    args = parse_args()
    if args.m == "http":
        start_http_server(args.p)
    elif args.m == "flow":
        payload = parse_input(args.i)
        result = asyncio.run(service.run(payload))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.m == "node" and args.n:
        payload = parse_input(args.i)
        result = asyncio.run(service.run_node(args.n, payload))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    elif args.m == "agent":
        agent_ctx = new_context(method="agent")
        for chunk in service.stream(
                {
                    "type": "query",
                    "session_id": "1",
                    "message": "你好",
                    "content": {
                        "query": {
                            "prompt": [
                                {
                                    "type": "text",
                                    "content": {"text": "现在几点了？请调用工具获取当前时间"},
                                }
                            ]
                        }
                    },
                },
                run_config={"configurable": {"session_id": "1"}},
                ctx=agent_ctx,
        ):
            print(chunk)
