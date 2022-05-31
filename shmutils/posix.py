from __future__ import annotations

import os
import errno
import io
from typing import Union, Type, Optional

from .utils import RelativeView
from .shm import (
    Flags as SHMFlags,
    shm_open as raw_shm_open,
    SharedMemoryHandle,
    shm_unlink,
)
from . import mmap
from .mmap import Protections as MapProtections, Flags as MapFlags


def reattach_shared_memory(cls, name, mode, size, mapping):
    return cls(name, "r+b", size, mapping=mapping)


class PosixSharedMemory(io.RawIOBase):
    __slots__ = ("name", "mode", "flags", "size", "_should_free", "_mmap", "closed")

    def fileno(self):
        return self._mmap.fileno()

    def seek(self, offset, whence):
        return self._mmap.seek(offset, whence)

    def tell(self):
        return self._mmap.tell()

    def truncate(self, size):
        raise io.UnsupportedOperation

    def readinto(self, buffer):
        return self._mmap.readinto(buffer)

    def write(self, b):
        return self._mmap.write(b)

    def __init__(
        self,
        name: Union[str, bytes, int],
        mode: Union[SHMFlags, str],
        size: int,
        *,
        mapping: Optional[mmap.MappedMemory] = None,
    ):
        assert size > 0
        size = mmap.round_to_page_size(size)
        if isinstance(mode, str):
            self.flags = SHMFlags.from_mode(mode)
            self.mode = mode
        elif isinstance(mode, (int, SHMFlags)):
            if isinstance(mode, int):
                mode = SHMFlags(mode)
            self.flags = mode
            self.mode = mode.to_mode()
        else:
            raise TypeError(f"unknown type {type(mode)}")
        self._handle = handle = raw_shm_open(name, self.flags, 0o600)
        if handle.size() != size:
            new_size = handle.truncate(size)
            assert new_size == size
        if mapping is None:
            mapping = mmap.MappedMemory(
                None, size, MapProtections.READ_WRITE, MapFlags.SHARED, handle
            )
        self._mmap = mapping
        self.closed = False
        self.name = name
        self.size = size
        self._depth = 0
        # process that made the shm file should be the one to close it.
        self._should_free = handle.flags & SHMFlags.EXCLUSIVE_CREATION

    def as_handle(self) -> SharedMemoryHandle:
        return self._handle

    def __reduce__(self):
        return reattach_shared_memory, (type(self), self.name, self.mode, self.size, self._mmap)

    def relative_view(self, index: int, length: int = -1) -> RelativeView:
        if length == -1:
            length = self.size - index
        if index + length > self.size:
            raise IOError(
                f"Unable to grab from {index}:{index+length} (overrun by {index + length - self.size} bytes)"
            )
        return RelativeView(self._mmap._view, index, length)

    def __getitem__(self, *args, **kwargs):
        return self._mmap.__getitem__(*args, **kwargs)

    def __setitem__(self, *args, **kwargs):
        self._mmap.__setitem__(*args, **kwargs)

    def __enter__(self):
        self._depth += 1
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self._depth -= 1
        if self._depth == 0:
            self.close()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        try:
            os.close(int(self._handle))
        except OSError as e:
            if e.errno == errno.EBADF:
                pass
            else:
                raise
        if self._handle is not None:
            if self._should_free:
                shm_unlink(self._handle)
            self._handle = None

    @classmethod
    def open(
        cls: Type[PosixSharedMemory], name: Union[str, bytes], mode: Union[SHMFlags, str], size: int
    ) -> PosixSharedMemory:
        flags = SHMFlags.from_mode(mode)
        try:
            return cls(name, flags, size)
        except FileExistsError:
            flags ^= SHMFlags.CREATE | SHMFlags.EXCLUSIVE_CREATION
        return cls(name, flags, size)


shm_open = PosixSharedMemory.open


@shm_unlink.register
def _(page: PosixSharedMemory):
    page.close()


__all__ = [
    "SHMFlags",
    "PosixSharedMemory",
    "shm_unlink",
    "shm_open",
    "raw_shm_open",
]
