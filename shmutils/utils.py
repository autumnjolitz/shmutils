from __future__ import annotations

import functools
import asyncio
import inspect
import string
import logging
import weakref
from contextlib import suppress
from typing import Union, Type, Any, Callable, List, Awaitable

from ._shmutils import ffi

from .exceptions import DispatchError
from .typing import void_ptr, T

TYPE_NAME_OVERRIDES = {
    type(None): "null-equivalent type",
    complex: "complex number",
    int: "integer",
    float: "floating point number",
}

TestFunc = Callable[[Any, Type[Any]], bool]

logger = logging.getLogger(__name__)


def conditional_dispatch(base_case_func):
    @functools.wraps(base_case_func)
    def wrapper(base_case_func: Callable) -> Callable:
        def wrapped(*args, **kwargs):
            for test_func, func in wrapped.__funcs__.items():
                if test_func(*args, **kwargs):
                    try:
                        return func(*args, **kwargs)
                    except DispatchError:
                        continue
            return base_case_func(*args, **kwargs)

    wrapper.__funcs__ = {}

    def register(test_func: TestFunc):
        assert callable(test_func)

        def register_wrapper(func):
            wrapper.__funcs__[test_func] = func
            return func

        return register_wrapper

    wrapper.register = register
    return wrapper


def is_cffi(value: Any) -> bool:
    with suppress(AttributeError):
        return value.__module__ == "_cffi_backend"
    return False


def contains(key, collection) -> bool:
    return key in collection


_uppercase_space = {ord(char): f" {char}" for char in string.ascii_uppercase}


@conditional_dispatch
def humanize_type(value: Type[Any]) -> str:
    if not isinstance(value, type):
        value = type(value)
    value = value.__name__.translate(_uppercase_space)
    return value.strip()


@humanize_type.register(functools.partial(contains, collection=TYPE_NAME_OVERRIDES))
def _(value):
    return TYPE_NAME_OVERRIDES[value]


@humanize_type.register(is_cffi)
def _(value) -> str:
    with suppress(TypeError):
        return ffi.typeof(value).cname
    raise DispatchError


def reattach_cffi(c_name, memory, index, endex):
    ptr = ffi.cast(c_name, memory._raw.address + index)
    if memory._used[index:endex]:
        (i,) = memory._used[index:endex]
        assert i.begin == index and i.end == endex
        return cffiwrapper(ptr, memory)
    else:
        memory._register_allocation((index, endex), endex - index)


class cffiwrapper:
    """
    cdatas are not pickleable, except in this case we can restore it
    with a terrible cast because we've made the memory pool pickleable/unpickleable on
    the same system.
    """

    def __getitem__(self, *args, **kwargs):
        return self.cdata.__getitem__(*args, **kwargs)

    def __setitem__(self, *args, **kwargs):
        self.cdata.__setitem__(*args, **kwargs)

    def __init__(self, cdata, memory):
        self.cdata = cdata
        self.memory = memory

    def __reduce__(self):
        start_offset = int(ffi.cast("void*", self.cdata) - self.memory._raw.address)
        return reattach_cffi, (
            ffi.typeof(self.cdata).cname,
            self.memory,
            start_offset,
            start_offset + ffi.sizeof(self.cdata),
        )


class RelativeToAbsoluteAddress:
    def __init__(
        self,
        mapping,
    ):
        self.base_address = mapping._raw.as_absolute_offset()
        self.size = len(mapping)

    def __getitem__(self, relative_address: Union[void_ptr, int]):
        if not isinstance(relative_address, int):
            relative_address = ffi.cast("uintptr_t", relative_address)
        relative_address = int(relative_address)
        assert relative_address >= 0
        if relative_address <= self.size:
            return self.base_address + relative_address
        raise IndexError(relative_address)


class AbsoluteToRelativeAddress:
    def __init__(self, mapping):
        self.base_address = mapping._raw.as_absolute_offset()
        self.size = len(mapping)
        self.high_address = self.base_address + self.size

    def __getitem__(self, addr_or_slice: Union[int, void_ptr, slice]) -> Union[int, range]:
        if isinstance(addr_or_slice, slice):
            abs_start, abs_end = (addr_or_slice.start, addr_or_slice.stop)
            if abs_start is None:
                abs_start = self.base_address
            if abs_end is None:
                abs_end = self.high_address
            if abs_start < self.base_address:
                raise IndexError(f"{abs_start} is lower than lowest address {self.base_address}")
            if abs_start > self.high_address:
                raise IndexError(f"{abs_start} is higher than highest address {self.high_address}")
            return range(abs_start - self.base_address, abs_end - self.base_address)

        absolute_address = addr_or_slice
        if not isinstance(absolute_address, int):
            absolute_address = ffi.cast("uintptr_t", absolute_address)
        absolute_address = int(absolute_address)
        if not (self.base_address <= absolute_address < self.high_address):
            raise IndexError(
                f"{absolute_address} must be in range [{self.base_address}, {self.high_address})"
            )
        return absolute_address - self.base_address


class AbsoluteView:
    def __init__(
        self,
        mapping,
    ):
        self.base_address = mapping._raw.as_absolute_offset()
        self.mapping = mapping

    def __getitem__(self, index_or_slice: Union[int, void_ptr, slice]) -> Union[memoryview, int]:
        if isinstance(index_or_slice, slice):
            start, stop = index_or_slice.start, index_or_slice.stop
            if start is None:
                start = self.base_address
            length = len(self.mapping)
            if stop is not None:
                length = stop - start
            if length > len(self.mapping):
                raise IndexError
            return self.mapping.getbuffer(start - self.base_address, length)

        if not isinstance(index_or_slice, int):
            absolute_address = ffi.cast("uintptr_t", index_or_slice)
        absolute_address = int(index_or_slice)
        relative_address = absolute_address - self.base_address
        return self.mapping._raw.buffer[relative_address]

    def __setitem__(self, index_or_slice, value) -> Union[memoryview, int]:
        if isinstance(index_or_slice, slice):
            start, stop = index_or_slice.start, index_or_slice.stop
            if start is None:
                start = self.base_address
            if stop is None:
                stop = self.base_address + len(self)
            length = stop - start
            if length > len(self.mapping):
                raise IndexError
            with self.mapping.getbuffer(start - self.base_address, length) as buf:
                buf[0:length] = value
            return
        if not isinstance(index_or_slice, int):
            absolute_address = ffi.cast("uintptr_t", index_or_slice)
        absolute_address = int(index_or_slice)
        relative_address = absolute_address - self.base_address
        return self.mapping._raw.buffer.__setitem__(relative_address, value)


class RelativeView:
    def __init__(self, mapping):
        self.mapping = mapping

    def __getitem__(self, index_or_slice):
        return self.mapping._raw.buffer.__getitem__(index_or_slice)

    def __setitem__(self, index_or_slice, value):
        return self.mapping._raw.buffer.__setitem__(index_or_slice, value)


pool = weakref.WeakKeyDictionary()


class ListenerContext:
    listeners: List[
        Callable[
            [
                str,
            ]
        ]
    ]

    def __init__(self, event_name: str):
        self.listeners = []
        self.event_name = event_name

    async def dispatch_event(self, value):
        tasks = []
        task_funcs = []
        for listener_func in self.listeners:
            try:
                result = listener_func(self.event_name, value)
            except BaseException:
                logger.critical(f"{listener_func.__name__} threw an uncaught error!", exc_info=True)
            else:
                if inspect.isawaitable(result):
                    if inspect.iscoroutine(result):
                        result = loop.create_task(result)
                    task_funcs.append(listener_func)
                    tasks.append(result)
        await asyncio.gather(*tasks, return_exceptions=True)
        for listener_func, task in zip(task_funcs, tasks):
            if task.exception() is not None:
                if task.cancelled():
                    continue
                logger.critical(
                    f"{listener_func.__name__} threw an uncaught error!", exc_info=task.exception()
                )


def add_event_listener(target, event_name, func, context=None):
    if context is not None:
        if context.event_name != event_name:
            raise KeyError(event_name)
        context.listeners.append(func)
        return
    if callable(target):
        context = pool[target]


def remove_event_listener(target, event_name, func, context=None):
    if context is not None:
        if context.event_name != event_name:
            raise KeyError(event_name)
        context.listeners.remove(func)
        return


def dispatch_event(func_or_event_name: str | Callable[..., T]):
    event_name = None
    if isinstance(func_or_event_name, str):
        event_name = func_or_event_name

    def wrapper(func: Callable[..., T]):
        nonlocal event_name
        assert callable(func)
        assert inspect.iscoroutinefunction(func)
        params = inspect.signature(func)
        first, *rest = (params[key] for key in params)

        bottom_func = get_bottom(func)
        if event_name is None:
            event_name = bottom_func.__name__
            if bottom_func.__name__ == "<lambda>":
                raise TypeError("wtf")
        event_names = getattr(func, "event_names", ())
        if event_name in event_names:
            return func

        default_context = ListenerContext(event_name)
        self = None
        if hasattr(func, "__self__"):
            self = func.__self__
            func = func.__func__
        pool[(func, event_name)] = default_context

        @functools.wraps(func)
        def wrapped_simple(*args, **kwargs) -> Awaitable[T]:
            context = None
            if self is not None:
                try:
                    context = pool[(self, event_name)]
                except KeyError:
                    context = pool[(self, event_name)] = pool[(func, event_name)].copy()
            if context is None:
                context = pool[(func, event_name)]
            value = func(*args, **kwargs)

            async def _wrapped():
                if inspect.isawaitable(value):
                    value = await value
                try:
                    await context.dispatch_event(event_name, value)
                except Exception as e:
                    logger.exception(f"Unable to dispatch event {event_name!r}")
                return value

            return _wrapped()

        wrapped = wrapped_simple

        if first == "self":

            @functools.wraps(func)
            def wrapped_instance(self, *args, **kwargs) -> Awaitable[T]:
                context = None
                with suppress(TypeError):
                    try:
                        context = pool[(self, event_name)]
                    except KeyError:
                        context = pool[(self, event_name)] = pool[(func, event_name)].copy()
                if context is None:
                    context = pool[(func, event_name)]

                value = func(self, *args, **kwargs)

                async def _wrapped(value):
                    if inspect.isawaitable(value):
                        value = await value
                    try:
                        await context.dispatch_event(event_name, value)
                    except Exception:
                        logger.exception(f"Unable to dispatch event {event_name!r}")
                    return value

                return _wrapped(value)

            wrapped = wrapped_instance

        wrapped.add_event_listener = functools.partial(add_event_listener, context=default_context)
        wrapped.remove_event_listener = functools.partial(
            remove_event_listener, context=default_context
        )
        bottom_func.event_names = tuple(event_name, *event_names)

        if self is not None:
            return functools.partial(wrapped, self)

        return wrapped

    if callable(func_or_event_name):
        return wrapper(func_or_event_name)
    return wrapper


def get_bottom(func):
    for key in ("__wrapped__", "__func__"):
        next_func = getattr(func, key, None)
        if next_func is not None:
            break
    while next_func is not None:
        func = next_func
        for key in ("__wrapped__", "__func__"):
            next_func = getattr(func, key, None)
            if next_func is not None:
                break
    return func
