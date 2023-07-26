"""
All Shared Memory pools will execute this bootstrap at ``initialize_worker``.
"""
from contextlib import suppress
import asyncio
import os
import atexit
import multiprocessing.context

import logging
import threading
from multiprocessing import Event, Process
from typing import Callable, Any

from .types import get_context

from .typing import AbstractWorkerContext, WorkerInitializer

logger = logging.getLogger(__name__)


def call_thunks(funcs, *args, **kwargs):
    for func in funcs:
        if callable(func):
            func(*args, **kwargs)


class WorkerContext(AbstractWorkerContext):
    def __init__(
        self,
        mp_context: None | multiprocessing.context.BaseContext = None,
        mapping: dict[str, Any] | None = None,
    ):
        mp_context = get_context(mp_context)
        self._initialized: Event = mp_context.Event()
        self.initargs = ()
        self.state = "uninitialized"
        if mapping is None:
            mapping = {}
        self.mapping = mapping

    def keys(self):
        return self.mapping.keys()

    def items(self):
        return self.mapping.items()

    def values(self):
        return self.mapping.values()

    def __iter__(self):
        yield "state"
        yield from self.mapping

    def __getitem__(self, key):
        with suppress(KeyError):
            return self.mapping[key]
        if key == "state":
            return self.state
        raise KeyError(key)

    def __setitem__(self, key, value):
        if key == "state":
            if key in self.mapping:
                self.mapping[key] = value
                return
            raise KeyError(key)
        self.mapping[key] = value

    def __delitem__(self, key):
        del self.mapping[key]

    def __enter__(self):
        if self.state == "initialized":
            return self
        if self.state != "uninitialized":
            raise ValueError
        self.state = "initializing"
        self._start_event_loop()
        if self.daemon:
            atexit.register(self._stop_event_loop)
            self.state = "initialized"
        self._worker_initialized.set()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if self.daemon:
            atexit.unregister(self._stop_event_loop)
        self._stop_event_loop()


def on_worker_bootstrap(context_cls: type[WorkerContext] = None, *args, **kwargs):
    ctx = context_cls(*args, **kwargs)
    ctx.__enter__()
    Process.current_process().context = ctx


def on_worker_exit():
    ctx = Process.current_process().context
    ctx.__exit__(None, None, None)
