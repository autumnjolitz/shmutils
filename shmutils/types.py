from contextlib import suppress
import asyncio
import inspect
import weakref
import functools
import asyncio
import concurrent.futures
from contextlib import AsyncExitStack
import logging
import threading
from typing import Self, Tuple, IO, Callable, Awaitable, Any
from multiprocessing import get_context as _get_context, Process as _Process
from multiprocessing.connection import Connection
from concurrent.futures import _base
from types import SimpleNamespace as _SimpleNamespace
import multiprocessing.context

from .typing import Span, WrittenByteCount, WorkerLifecycleCallable, T, P
from .utils import dispatch_event

from intervaltree import IntervalTree

mixins = _SimpleNamespace()

logger = logging.getLogger(__name__)


class SpanMergeError(ValueError):
    ...


class WriteTooLarge(ValueError):
    def __init__(self, *args):
        msg = None
        with suppress(ValueError):
            msg, heap, span, values = args
            super().__init__(msg, heap, span, values)
            return
        with suppress(ValueError):
            heap, span, values = args
            overrun_length = len(values) - span.length
            msg = (
                f"Unable to write remaining {overrun_length:,d} "
                f"bytes to Span of {span.length:,d} bytes"
            )
            super().__init__(msg, heap, span, values)
            return
        raise TypeError("Must be either `heap, span, values` or `msg, heap, span, values`")

    def __str__(self):
        msg, *_ = self.args
        return f"{type(self).__name__}({msg}, ...)"


class SpanMixin:
    __slots__ = ()

    def load(self, heap, length=-1) -> memoryview:
        if length < 0:
            length = self.length
        if length > self.length:
            raise ValueError
        return heap[self.start : self.start + length]

    def bisect(self: Self) -> Tuple[Self, Self]:
        size, rem = divmod(self.size, 2)
        size += rem
        cls = type(self)
        left = cls.new(self.start, size)
        right = cls.new(self.start + size, self.length - size)
        return left, right

    def join(self: Self, other: Self) -> Self:
        cls = type(self)
        if self.start + self.length == other.start:
            return cls.new(self.start, self.length + other.length)
        if other.start + other.length == self.start:
            return cls.new(other.start, other.length + self.length)
        raise SpanMergeError("Unable to merge non-contiguous spans!")


class MutableSpanMixin:
    __slots__ = ()

    def store(
        self: Self, heap, memory: memoryview | bytes | bytearray | IO[bytes]
    ) -> WrittenByteCount:
        if hasattr(memory, "readinto"):
            return memory.readinto(heap[self.start : self.start + self.size])
        if hasattr(memory, "read"):
            memory = memory.read(self.size)
        length = len(memory)
        span = slice(self.start, self.start + length)
        heap[span] = memory
        return WrittenByteCount(length)


class MutableSpan(Span, MutableSpanMixin):
    __slots__ = ()


class ImmutableSpan(Span, SpanMixin):
    __slots__ = ()


def _call_func_after(stage, func):
    func()


def run_thread_on_fd_ready(fd: int, future: asyncio.Future, /, func, *args, **kwargs):
    loop = asyncio.get_running_loop()
    loop.remove_reader(fd)
    if kwargs:
        func = functools.partial(func, **kwargs)
    try:
        task = loop.run_in_executor(None, func, *args)
    except Exception as e:
        future.set_exception(e)
    else:

        def _on_future_done(fut):
            if fut.exception() is not None:
                future.set_exception(fut.exception())
                return
            future.set_result(fut.result())

        task.add_done_callback(_on_future_done)


def asyncify(
    func: Callable[P, T] | None = None,
    /,
    *,
    fd: int,
    done_callback: Callable[[], None] | None = None,
    lock: asyncio.Lock | None = None,
    futures: set[asyncio.Future] | None = None,
) -> Callable[P, Awaitable[T]]:
    def wrapper(func: Callable[P, T]) -> Callable[P, Awaitable[T]]:
        @functools.wraps(func)
        def wrapped(*args: P.args, **kwargs: P.kwargs) -> Awaitable[T]:
            loop = asyncio.get_running_loop()
            f = loop.create_future()
            if futures is not None:
                futures.add(f)
            if callable(done_callback):
                f.add_done_callback(done_callback)
            thunk = func
            if kwargs:
                thunk = functools.partial(func, **kwargs)
            loop.add_reader(fd, run_thread_on_fd_ready, fd, f, thunk, *args)
            AsyncPipe.ALL_TASKS.add(f)
            return f

        return wrapped

    if callable(func):
        return wrapper(func)
    return wrapper


async def lock_value_with(lock, func, /, *args, **kwargs):
    async with lock:
        value = func(*args, **kwargs)
        if inspect.isawaitable(value):
            value = await value
    return value


class AsyncPipe:
    def __init__(self, read: Connection, write: Connection):
        self._initialized = False
        self.read = read
        self.write = write
        self._stack = None
        self.read_lock = None
        self.write_lock = None
        self._loop = None
        self._tasks = weakref.WeakSet()

    async def initialize(self):
        if any((self.closed, self.closing)):
            raise ValueError
        if self._initialized:
            return self
        self._stack = AsyncExitStack()
        self.read_lock = asyncio.Lock()
        self.write_lock = asyncio.Lock()
        self._initialized = True
        self._loop = asyncio.get_running_loop()
        return self

    async def __aenter__(self):
        await self.initialize()
        self._stack_ctx = await self._stack.__aenter__()
        self._stack_ctx.enter_context(self.read)
        self._stack_ctx.enter_context(self.write)
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self._stack.__aexit__(exc_type, exc_value, traceback)
        self._stack_ctx = None
        self._stack = None
        self.read = None
        self.write = None
        self.close()

    def close(self):
        if any((self.closed, self.closing)):
            return
        self.closing = True
        if self.read:
            self.read.close()
            self.read = None
        if self.write:
            self.write.close()
            self.write = None

        for task in self._tasks:
            if not task.done():
                task.cancel(msg=f"Parent {self!r} was closed!")

        if self._loop:
            self._loop = None

        self.read_lock = None
        self.write_lock = None
        self.closed = True
        self.closing = False
        self._initialized = False

    def __getattr__(self, name):
        if name.startswith(("recv", "send")):
            if name.startswith("recv"):
                func = getattr(self.read, name)
                if callable(func) and not inspect.iscoroutinefunction(func):
                    if not self._initialized:
                        raise TypeError("initialize not run yet!")
                    thunk = functools.partial(
                        lock_value_with,
                        self.read_lock,
                        asyncify(func, futures=self._tasks, fd=self.read.fileno()),
                    )
                    setattr(self, name, thunk)
                    return thunk
                return func
            elif name.startswith("send"):
                func = getattr(self.write, name)
                if callable(func) and not inspect.iscoroutinefunction(func):
                    if not self._initialized:
                        raise TypeError("initialize not run yet!")
                    thunk = functools.partial(
                        lock_value_with,
                        self.write_lock,
                        asyncify(func, futures=self._tasks, fd=self.write.fileno()),
                    )
                    setattr(self, name, thunk)
                    return thunk
                return func
        raise AttributeError(name)


class AbstractWorkerLifecycleMixin:
    default_initializer = None
    default_deinitializer = None
    initargs = deinitargs = ()
    mp_context: multiprocessing.context.BaseContext

    def __init__(
        self,
        *args,
        initializer: WorkerLifecycleCallable | None = None,
        initargs=(),
        deinitializer: WorkerLifecycleCallable | None = None,
        deinitargs=(),
        mp_context: multiprocessing.context.BaseContext | None = None,
        **kwargs,
    ):
        assert initializer is None or callable(initializer)
        assert deinitializer is None or callable(deinitializer)
        assert isinstance(deinitargs, tuple)
        assert isinstance(initargs, tuple)
        self.mp_context = get_context(mp_context)
        cls = type(self)
        if initializer is None:
            initializer = cls.default_initializer
            initargs = cls.default_initializer_args
        self.initializer = initializer
        self.initargs = initargs
        if deinitializer is None:
            deinitializer = cls.default_deinitializer
            deinitargs = cls.default_deinitializer_args

        self.deinitargs = deinitargs
        self.deinitializer = deinitializer
        super().__init__(*args, **kwargs)

    def on_process_started(self):
        if self.initializer is not None:
            try:
                self.initializer(*self.initargs)
            except BaseException:
                _base.LOGGER.critical("Exception in initializer:", exc_info=True)

    def on_process_stopped(self):
        if self.deinitializer is not None:
            try:
                self.deinitializer(*self.deinitargs)
            except BaseException:
                _base.LOGGER.critical("Exception in deinitializer:", exc_info=True)

    def run(self):
        self.on_process_started()
        try:
            return super().run()
        finally:
            self.on_process_stopped()

    @classmethod
    def set_default_initializer(cls, initializer=None, initargs=()):
        cls.default_initializer = initializer
        cls.default_initializer_args = initargs
        return cls

    @classmethod
    def set_default_deinitializer(cls, deinitializer=None, deinitargs=()):
        cls.default_deinitializer = deinitializer
        cls.default_deinitializer_args = deinitargs
        return cls

    @classmethod
    def wraps(cls: type[T], base: type[_Process]) -> type[_Process | T]:
        new_module_path = f"{__module__}.mixins"
        new_name = f"SharedMemoryWorker{base.__name__}"
        if base.__module__:
            new_module_path = f"{new_module_path}.{base.__module__}"

        with suppress(AttributeError):
            target = mixins
            for step in new_module_path.split("."):
                target = getattr(target, step)
            new_cls = getattr(target, new_name)
            assert new_cls is not None
            return new_cls

        attrs = {"__name__": new_name, "__module__": new_module_path}
        target = mixins

        for step in base.__module__.split("."):
            prev_target = target
            target = getattr(target, step, None)
            if target is None:
                target = _SimpleNamespace()
                setattr(prev_target, step, target)
        new_cls = type(attrs["__name__"], (base, cls), attrs)
        new_cls._Process = base
        setattr(target, attrs["__name__"], new_cls)
        return new_cls


class Process(_Process, AbstractWorkerLifecycleMixin):
    """
    A Process subclass that can call in the extra keyword arguments:
        initializer: Callable[[], None] | None - to be called on process start
        initargs: tuple[Any] - any params to pass to the initializer
        deinitializer: Callable[[], None] | None - to be called on process ending
        deinitargs: tuple[Any] - any params to pass to the initializer


    The class can be inherited and the functions "on_process_started", "on_process_stopped"
        can be overridden. Defaults to calling the initializer and deinitializer.
    """


async def _new_event():
    return asyncio.Event()


class AbstractAsyncioProcessMixin(AbstractWorkerLifecycleMixin):
    channel: AsyncPipe

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        context = self.mp_context
        self._pending_pipes = (context.Pipe(False), context.Pipe(False))
        server, _ = self._pending_pipes
        self.channel = AsyncPipe(*server)

    async def recv(self):
        return await self.channel.recv()

    async def send(self, obj):
        return await self.channel.send(obj)

    def on_process_started(self):
        _, client = self._pending_pipes
        self.channel = AsyncPipe(*client)
        del self._pending_pipes

        self._event_loop_thread_is_stopped = threading.Event()
        self._loop = loop = asyncio.new_event_loop()
        self._event_loop_should_stop = loop.run_until_complete(_new_event())
        self._async_main_task = None
        self._loop_thread = loop_thread = threading.Thread(
            target=self._run_event_loop, name=f"EventLoopThread-{self.native_id}"
        )
        self._tasks = set()
        loop_thread.daemon = True
        loop_thread.start()
        super().on_process_started()

    def _stop(self):
        if self._async_main_task:
            if not self._async_main_task.done():
                self._async_main_task.cancel()
            with suppress(asyncio.CancelledError):
                logger.info("calling into other threads looop to stop after sending a cancellation")

                async def _wait():
                    return await self._async_main_task

                future = asyncio.run_coroutine_threadsafe(_wait(), self._loop)
                logger.info("waiting for result")
                result = future.result()
                result
            assert self._async_main_task.done(), "wtf"
            self._async_main_task = None

        if self._event_loop_should_stop:
            self._event_loop_should_stop.set()

    async def on_event_loop_started(self, loop):
        return loop

    async def _autovacuum_background_task_queue(self):
        with suppress(asyncio.CancelledError):
            seen = set()
            while True:
                for task in self._tasks:
                    if task.done():
                        seen.add(task)
                if seen:
                    self._tasks -= seen
                await asyncio.sleep(10)
                seen.clear()
        seen.clear()

    def add_background_task(self, task, *args, **kwargs) -> asyncio.Task:
        if callable(task):
            task = task(*args, **kwargs)
        if inspect.isawaitable(task):
            if not isinstance(task, asyncio.Task):
                task = asyncio.create_task(task)
            self._tasks.add(task)
        return task

    async def main(self, loop):
        self._async_main_task = me = asyncio.current_task(loop)
        me.set_name("AsyncioProcessMainEventLoop")
        await self.channel.initialize()
        self.add_background_task(self._autovacuum_background_task_queue())
        with suppress(Exception):
            await self.on_event_loop_started(loop)

        try:
            await self._event_loop_should_stop.wait()
        finally:
            await self.shutdown_tasks()

    async def shutdown_tasks(self, timeout=0.5):
        done, pending = await asyncio.wait(
            self._tasks, return_when=asyncio.ALL_COMPLETED, timeout=timeout
        )
        if done:
            self._tasks -= frozenset(done)
        if pending:
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            self._tasks -= frozenset(pending)
        tasks = []
        for task in self._tasks:
            if not task.done():
                task.cancel()
                tasks.append(task)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    def _run_event_loop(self):
        asyncio.set_event_loop(self._loop)
        with suppress(asyncio.CancelledError):
            with asyncio.Runner(loop_factory=lambda: self._loop) as runner:
                runner.run(self.main(self._loop))
        self._event_loop_thread_is_stopped.set()

    def stop(self):
        if self._event_loop and self._event_loop.is_running():
            self._stop()

    @property
    def loop(self):
        return self._event_loop

    def on_process_stopped(self):
        # call the deinitializers first:
        self.stop()
        super().on_process_stopped()
        if self._event_loop.is_running():
            self._stop()
            logger.info("waiting for event loop threads logical function to end")
            self._event_loop_thread_is_stopped.wait()
        logger.info("closing loop explicitly")
        self._loop.close()  # reentrant closes okay?
        self._loop = None
        if self._loop_thread is not None and self._loop_thread.is_alive():
            logger.info("waiting for loop thread to end (this means background items)")
            self._loop_thread.join()
        self._loop_thread = None
        self._event_loop_should_stop = None
        self._event_loop_thread_is_stopped = None


class AsyncioProcess(_Process, AbstractAsyncioProcessMixin):
    ...


def async_process_pool_executor_async_trampoline(
    coro: Callable[P, Awaitable[T]] | Awaitable[T], *args: P.args, **kwargs: P.kwargs
):
    process = Process.current_process()

    if callable(coro):
        coro = coro(*args, **kwargs)

    async def _trampoline():
        nonlocal coro
        if inspect.isawaitable(coro):
            coro = await coro
        return coro

    future = asyncio.run_coroutine_threadsafe(_trampoline(), process.loop)
    return future.result()


class AsyncProcessPoolExecutor(concurrent.futures.ProcessPoolExecutor):
    def __init__(self, *args, mp_context=None, initializer=None, initargs=(), **kwargs):
        mp_context = get_context(mp_context)
        process_cls = mp_context.Process
        if hasattr(process_cls, "_Process"):
            process_cls = process_cls._Process
        cls = AbstractAsyncioProcessMixin.wraps(process_cls)
        mp_context.Process = cls
        super().__init__(*args, mp_context=mp_context, **kwargs)

    def submit(self, fn, /, *args, **kwargs):
        if inspect.iscoroutinefunction(fn) or inspect.isawaitable(fn):
            coro_fn = fn
            fn = async_process_pool_executor_async_trampoline
            args = (coro_fn, *args)
        return super().submit(fn, *args, **kwargs)


class NonEvictingIntervalTree(IntervalTree):
    def add(self, interval):
        if not self[interval.begin : interval.end]:
            return super().add(interval)
        raise ValueError("in use!")

    def addi(self, begin, end, data):
        if not self[begin:end]:
            return super().addi(begin, end, data)
        raise ValueError("in use!")

    def __setitem__(self, index_or_slice, value):
        if not self.__getitem__(index_or_slice):
            return super().__setitem__(index_or_slice, value)
        raise ValueError("in use!")


def get_context(method: str | None | multiprocessing.context.BaseContext = None):
    """
    Get the multiprocessing context and if passed an existing context, ensure the
    context.Process class inherits AbstractWorkerLifecycleMixin, which means
    there is
    """
    if not hasattr(method, "Process"):
        mp_context = _get_context(method)
    if not issubclass(mp_context.Process, AbstractWorkerLifecycleMixin):
        cls = mp_context.Process
        mp_context.Process = AbstractWorkerLifecycleMixin.wraps(cls)
    return mp_context
