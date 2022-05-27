from __future__ import annotations

import os
import errno
import mmap
from enum import IntFlag
from typing import NamedTuple, Union, Optional, NewType

from _shmutils import lib, ffi
from .exceptions import exception_from_shm_calls


class SHMFlags(IntFlag):
    READ_ONLY = os.O_RDONLY
    READ_WRITE = os.O_RDWR
    CREATE = os.O_CREAT
    EXCLUSIVE_CREATION = os.O_EXCL
    TRUNCATE_ON_OPEN = os.O_TRUNC

    def validate(self):
        if self & self.READ_ONLY and self & self.READ_WRITE:
            raise ValueError("Cannot be both readonly and readwrite")
        if self & self.EXCLUSIVE_CREATION and not self & self.CREATE:
            raise ValueError("EXCLUSIVE_CREATION only makes sense if CREATE is specified")
        if self & self.READ_ONLY == self.READ_ONLY or self & self.READ_WRITE == self.READ_WRITE:
            return self
        raise ValueError("READ_ONLY or READ_WRITE must be specified")

    @classmethod
    def from_mode(cls, mode: str) -> SHMFlags:
        if mode.endswith("b"):
            mode = mode[:-1]
        mode_special = ""
        if len(mode) == 2:
            mode, mode_special = mode[0], mode[1]

        if mode not in ("r", "w", "a", "x"):
            raise ValueError(
                "Must have exactly one of create/read/write/append mode and at most one plus"
            )
        if mode_special not in ("", "+"):
            raise ValueError(
                "Must have exactly one of create/read/write/append mode and at most one plus"
            )
        if mode == "r":
            flags = cls.READ_ONLY
            if mode_special:
                flags = cls.READ_WRITE
        elif mode == "w":
            flags = cls.CREATE | cls.READ_WRITE
            if not mode_special:
                flags |= cls.TRUNCATE_ON_OPEN
        elif mode == "x":
            flags = cls.CREATE | cls.EXCLUSIVE_CREATION | cls.READ_WRITE
        elif mode == "a":
            raise NotImplementedError("appending to shared memory not implemented")
        return flags

    def to_mode(self) -> str:
        self.validate()
        mode = "r"
        if self & self.CREATE:
            mode = "w"
            if self & self.EXCLUSIVE_CREATION:
                mode = "x"
        if self & self.TRUNCATE_ON_OPEN:
            mode = "w"
        if self & self.READ_WRITE:
            mode = f"{mode}+"
        return mode


def reattach_shmpage(name, mode, size, skip_to, should_free):
    page = SHMPage(name, "r+b", size, should_free)
    if skip_to:
        page.seek(skip_to)
    return page


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


class SHMPage:
    MAX_SIZE_BYTES = 4 * 1024 * 1024
    MIN_SIZE_BYTES = 1

    def __init__(
        self,
        name: Union[str, bytes, int],
        mode: Union[SHMFlags, str],
        size: Optional[int] = None,
        should_free: bool = True,
        *,
        fd=None,
    ):
        if size is None:
            size = self.MAX_SIZE_BYTES
        assert self.MIN_SIZE_BYTES <= size <= self.MAX_SIZE_BYTES
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
        if fd is None:
            fd = alloc(name, self.flags, 0o600)

        self._handle = fd
        if fd.size() != size:
            os.ftruncate(fd.fileno(), size)

        self._mmap = mmap.mmap(fd.fileno(), size)
        self.closed = False
        self.name = name
        self.size = size
        self._depth = 0
        self.c_buffer = ffi.from_buffer(
            "char[]", self._mmap, require_writable=self.flags & SHMFlags.READ_WRITE
        )
        self.should_free = should_free

    def as_handle(self) -> SHMHandle:
        return self._handle

    def fileno(self) -> int:
        return self._mmap.fileno()

    def __reduce__(self):
        return reattach_shmpage, (self.name, self.mode, self.size, self.tell(), False)

    def relative_view(self, index: int, length: int = -1) -> RelativeView:
        if length == -1:
            length = self.size - index
        if index + length > self.size:
            raise IOError(
                f"Unable to grab from {index}:{index+length} (overrun by {index + length - self.size} bytes)"
            )
        return RelativeView(self._mmap, index, length)

    def __getitem__(self, *args, **kwargs):
        return self._mmap.__getitem__(*args, **kwargs)

    def __setitem__(self, *args, **kwargs):
        self._mmap.__setitem__(*args, **kwargs)

    def tell(self) -> int:
        return self._mmap.tell()

    def seek(self, *args, **kwargs) -> int:
        return self._mmap.seek(*args, **kwargs)

    def write(self, *args, **kwargs) -> int:
        return self._mmap.write(*args, **kwargs)

    def read(self, *args, **kwargs) -> bytes:
        return self._mmap.read(*args, **kwargs)

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

        ffi.release(self.c_buffer)
        self._mmap.close()
        os.close(self._handle)

        self.c_buffer = None
        self._mmap = None
        self._handle = None

        if self.should_free:
            free(self.name)


DEFAULT_PERMISSIONS = 0o600


class _SHMHandle(NamedTuple):
    fd: FileDescriptor
    name: bytes


class SHMHandle(_SHMHandle):
    def __new__(cls, fd, name):
        if isinstance(name, str):
            name = name.encode()
        return super().__new__(cls, fd, name)

    def size(self) -> int:
        return os.fstat(self.fd).st_size

    def stat(self) -> Optional[os.stat_result]:
        try:
            return os.fstat(self.fd)
        except OSError as e:
            if e.errno == 9:
                return None
            raise

    def valid(self) -> bool:
        try:
            os.fstat(self.fd)
        except OSError as e:
            if e.errno == 9:
                return False
            raise
        return True

    def fileno(self) -> int:
        return int(self.fd)

    def __len__(self) -> int:
        return self.stat().st_size

    def __int__(self) -> int:
        return self.fd

    def __bytes__(self) -> bytes:
        return self.name

    def __str__(self) -> str:
        return repr(self.name)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.fd}, {self.name!r})"


FileDescriptor = NewType("FileDescriptor", int)


def alloc(
    name: Union[str, bytes],
    flags: SHMFlags = SHMFlags.CREATE | SHMFlags.READ_WRITE,
    permissions: int = DEFAULT_PERMISSIONS,
) -> SHMHandle:
    if isinstance(name, str):
        name = name.encode()
    flags = flags.validate()
    with ffi.new("char[]", name) as c_name:
        fd = lib.shm_open(c_name, int(flags), permissions)
    if fd == -1:
        try:
            err_name = errno.errorcode[ffi.errno]
        except KeyError:
            raise ValueError(f"Unrecognized error code {ffi.errno}")
        if err_name == "EACCES":
            raise PermissionError(ffi.errno, err_name, name)
        elif err_name == "ENAMETOOLONG":
            raise ValueError(f"too many characters in {name!r}")
        elif err_name == "EEXIST":
            raise FileExistsError(f"[Errno {ffi.errno}]: File already exists: {name!r}")
        elif err_name == "ENOENT":
            raise FileNotFoundError(f"[Errno {ffi.errno}] No such file or directory: {name!r}")
        raise ValueError("Unable to open shm file due to %s" % err_name)
    return SHMHandle(FileDescriptor(fd), name)


def free(fd: SHMHandle) -> int:
    """
    returns freed memory byte count.
    """
    assert fd.name, "fd must have a name"
    size = fd.stat().st_size

    with ffi.new("char []", fd.name) as c_name:
        errored = lib.shm_unlink(c_name)
    if not errored:
        return size
    exc_type, err_code, err_name = exception_from_shm_calls(ffi.errno)
    raise exc_type(err_code, err_name, fd.name)


__all__ = ["SHMFlags", "SHMPage", "free"]


if __name__ == "__main__":
    import doctest

    doctest.testmod(verbose=True)
