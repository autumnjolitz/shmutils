from __future__ import annotations

import mmap
from typing import Union

from _shmutils import ffi


def reattach_cffi(c_name, memory, index, endex):
    return cffiwrapper(ffi.cast(c_name, memory.c_buf[index:endex]), memory)


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
        _, (index, endex) = self.memory.ptrs[self.cdata]
        return reattach_cffi, (ffi.typeof(self.cdata).cname, self.memory, index, endex)


class RelativeView:
    __slots__ = (
        "_released",
        "buffer",
        "buffer_view",
        "index",
        "length",
        "relative_view",
    )

    def __init__(
        self,
        buffer: Union[memoryview, bytes, bytearray, mmap.mmap, RelativeView],
        index: int,
        length: int,
    ):
        assert index > -1
        assert length > 0
        self._released = False
        self.buffer = buffer
        if isinstance(buffer, RelativeView):
            self.buffer_view = buffer.relative_view
        else:
            self.buffer_view = memoryview(buffer)
        self.index = index
        self.relative_view = self.buffer_view[index : index + length]
        self.length = len(self.relative_view)

    def __len__(self):
        return self.length

    def absolute_view(self) -> memoryview:
        return self.buffer_view

    # ARJ: All sets/gets on it are done by relative
    def __setitem__(
        self,
        slice_or_index: Union[slice, int],
        value: Union[bytes, memoryview, bytearray, mmap.mmap],
    ):
        if isinstance(slice_or_index, slice):
            start = slice_or_index.start or 0
            end = slice_or_index.stop or (len(value) + start)
            available_length = len(self.relative_view[start:])
            write_length = end - start
            print("write ", write_length, available_length)
            if write_length > available_length:
                raise IndexError(
                    f"Attempted to write {write_length} but only {available_length} available"
                )
        return self.relative_view.__setitem__(slice_or_index, value)

    def __getitem__(self, slice_or_index: Union[slice, int]) -> Union[int, memoryview]:
        return self.relative_view.__getitem__(slice_or_index)

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
        if self.relative_view is not None:
            self.relative_view.release()
            self.relative_view = None
        if self.buffer_view is not None:
            self.buffer_view.release()
            self.buffer_view = None
        self.buffer = None
