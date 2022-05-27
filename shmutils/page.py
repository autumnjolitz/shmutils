from __future__ import annotations

import os
import errno
import mmap
import platform
from enum import IntFlag
from typing import NamedTuple, Union, Optional, NewType

from _shmutils import lib, ffi
from .exceptions import exception_from_shm_calls
from .utils import RelativeView


class PageFlags(IntFlag):
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
    def from_mode(cls, mode: str) -> PageFlags:
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

        MODES = {
            "w": cls.CREATE | cls.READ_WRITE | cls.TRUNCATE_ON_OPEN,
            "x": cls.CREATE | cls.EXCLUSIVE_CREATION | cls.READ_WRITE,
            "a": None,
            "r": cls.READ_ONLY,
        }
        flags = MODES[mode]
        if flags is None:
            # ARJ: to do an append requires a synchronized seek() offset.
            raise NotImplementedError("appends not supported")
        if mode_special:
            if cls.READ_ONLY & flags == cls.READ_ONLY:
                flags ^= cls.READ_ONLY
            if cls.TRUNCATE_ON_OPEN & flags == cls.TRUNCATE_ON_OPEN:
                flags ^= cls.TRUNCATE_ON_OPEN
            flags |= cls.READ_WRITE
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
        elif self & self.READ_WRITE:
            mode = f"{mode}+"
        return mode


def reattach_shmpage(name, mode, size, skip_to, should_free):
    page = SharedPage(name, "r+b", size, should_free)
    if skip_to:
        page.seek(skip_to)
    return page


class SharedPage:
    MAX_SIZE_BYTES = 4 * 1024 * 1024 if platform.system() == "Darwin" else float("inf")
    MIN_SIZE_BYTES = 1

    def __init__(
        self,
        name: Union[str, bytes, int],
        mode: Union[PageFlags, str],
        size: int,
        should_free: bool = True,
        *,
        fd: Optional[SharedMemoryHandle] = None,
    ):
        assert self.MIN_SIZE_BYTES <= size <= self.MAX_SIZE_BYTES
        if isinstance(mode, str):
            self.flags = PageFlags.from_mode(mode)
            self.mode = mode
        elif isinstance(mode, (int, PageFlags)):
            if isinstance(mode, int):
                mode = PageFlags(mode)
            self.flags = mode
            self.mode = mode.to_mode()
        else:
            raise TypeError(f"unknown type {type(mode)}")
        if fd is None:
            fd = raw_shm_malloc(name, self.flags, 0o600)

        self._handle = fd
        if fd.size() != size:
            truncate(fd, size)

        self._mmap = mmap.mmap(fd.fileno(), size)
        self.closed = False
        self.name = name
        self.size = size
        self._depth = 0
        self.c_buffer = ffi.from_buffer(
            "char[]", self._mmap, require_writable=self.flags & PageFlags.READ_WRITE
        )
        self.should_free = should_free

    def as_handle(self) -> SharedMemoryHandle:
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
        if self.should_free and self._handle is not None:
            raw_free(self._fd)
        self._fd = None


DEFAULT_PERMISSIONS = 0o600


class _SharedMemoryHandle(NamedTuple):
    fd: FileDescriptor
    name: bytes


class SharedMemoryHandle(_SharedMemoryHandle):
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


def raw_shm_malloc(
    name: Union[str, bytes],
    flags: PageFlags = PageFlags.CREATE | PageFlags.READ_WRITE,
    permissions: int = DEFAULT_PERMISSIONS,
) -> SharedMemoryHandle:
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
    return SharedMemoryHandle(FileDescriptor(fd), name)


def shm_malloc(name: Union[str, bytes], mode: Union[PageFlags, str], size: int) -> SharedPage:
    flags = PageFlags.from_mode(mode)
    should_free = flags & PageFlags.EXCLUSIVE_CREATION == PageFlags.EXCLUSIVE_CREATION
    try:
        fd = raw_shm_malloc(name, flags)
    except FileExistsError:
        flags ^= PageFlags.CREATE | PageFlags.EXCLUSIVE_CREATION
        fd = raw_shm_malloc(name, PageFlags.READ_WRITE)
    return SharedPage(name, flags, size, fd=fd, should_free=should_free)


def free(page: Union[SharedPage, SharedMemoryHandle, str, bytes]):
    if isinstance(page, (str, bytes)):
        return remove(page)
    if isinstance(page, SharedMemoryHandle):
        return raw_free(page)
    page.close()


def truncate(fd: SharedMemoryHandle, size: int):
    return os.ftruncate(fd.fileno(), size)


def raw_free(fd: SharedMemoryHandle) -> int:
    """
    returns freed memory byte count.
    """
    assert fd.name, "fd must have a name"
    size = fd.stat().st_size
    remove(fd.name)
    return size


def remove(name: Union[str, bytes]):
    """
    Deletes the SHM handle name from the kernel.

    When everyone is closed, it'll be collected.
    """
    if isinstance(name, str):
        name = name.encode()
    with ffi.new("char []", name) as c_name:
        errored = lib.shm_unlink(c_name)
    if not errored:
        return
    exc_type, err_code, err_name = exception_from_shm_calls(ffi.errno)
    raise exc_type(err_code, err_name, name)


__all__ = [
    "PageFlags",
    "SharedPage",
    "free",
    "shm_malloc",
    "truncate",
    "raw_shm_malloc",
    "raw_free",
    "remove",
]


if __name__ == "__main__":
    import doctest

    doctest.testmod(verbose=True)
