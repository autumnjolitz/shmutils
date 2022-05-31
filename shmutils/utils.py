from __future__ import annotations

import functools
import mmap
import string
from contextlib import suppress
from typing import Union, Type, Any, Callable

from _shmutils import ffi

from .exceptions import DispatchError

TYPE_NAME_OVERRIDES = {
    type(None): "null-equivalent type",
    complex: "complex number",
    int: "integer",
    float: "floating point number",
}

TestFunc = Callable[[Any, Type[Any]], bool]


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


class RelativeView:
    __slots__ = (
        "_released",
        "buffer",
        "buffer_view",
        "index",
        "length",
        "_relative_view",
    )

    def __init__(
        self,
        buffer: Union[memoryview, bytearray, RelativeView],
        index: int,
        length: int,
    ):
        assert index > -1
        assert length > 0
        self._released = False
        self.buffer = buffer
        if isinstance(buffer, RelativeView):
            buffer = buffer._relative_view
            assert isinstance(buffer, memoryview)
        self.buffer_view = memoryview(buffer)
        self.index = index
        self._relative_view = self.buffer_view[index : index + length]
        self.length = len(self._relative_view)

    def relative_view(self, index, length):
        return type(self)(self, index, length)

    def __len__(self):
        return self.length

    def absolute_view(self) -> memoryview:
        buffer = self.buffer
        while isinstance(buffer, RelativeView):
            buffer = buffer.buffer
        return memoryview(buffer)

    # ARJ: All sets/gets on it are done by relative
    def __setitem__(
        self,
        slice_or_index: Union[slice, int],
        value: Union[bytes, memoryview, bytearray, mmap.mmap],
    ):
        if isinstance(slice_or_index, slice):
            start = slice_or_index.start or 0
            end = slice_or_index.stop or (len(value) + start)
            available_length = len(self._relative_view[start:])
            write_length = end - start
            print("write ", write_length, available_length)
            if write_length > available_length:
                raise IndexError(
                    f"Attempted to write {write_length} but only {available_length} available"
                )
        return self._relative_view.__setitem__(slice_or_index, value)

    def __getitem__(self, slice_or_index: Union[slice, int]) -> Union[int, memoryview]:
        return self._relative_view.__getitem__(slice_or_index)

    def __enter__(self) -> RelativeView:
        if self._released:
            raise ValueError
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()

    def __del__(self):
        if self._released is not None:
            self.release()
            self._released = None
        self.index = None
        self.length = None

    def release(self, _skip_set=False):
        if self._relative_view is not None:
            self._relative_view.release()
            self._relative_view = None
        if self.buffer_view is not None:
            self.buffer_view.release()
            self.buffer_view = None
        self.buffer = None
