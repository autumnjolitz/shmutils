from __future__ import annotations

import errno
import os
import stat
import functools
from typing import NewType, NamedTuple, Optional, Union, Type, Dict
from enum import IntFlag

from _shmutils import lib, ffi

from . import errors


DEFAULT_PERMISSIONS: int = stat.S_IRUSR | stat.S_IWUSR
SHM_ERRCODES: Dict[int, Type[Exception]] = {
    errno.EACCES: PermissionError,
    errno.ENOENT: FileNotFoundError,
    errno.ENAMETOOLONG: ValueError,
}


FileDescriptor = NewType("FileDescriptor", int)


class Flags(IntFlag):
    NONE = 0
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
    def from_mode(cls, mode: str) -> Flags:
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


class _SharedMemoryHandle(NamedTuple):
    fd: FileDescriptor
    name: bytes
    flags: Flags


class SharedMemoryHandle(_SharedMemoryHandle):
    def __new__(cls, fd, name, flags=Flags.NONE):
        if isinstance(name, str):
            name = name.encode()
        return super().__new__(cls, fd, name, flags)

    def truncate(self, size):
        os.ftruncate(int(self.fd), size)
        return self.size()

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
        stat = self.stat()
        if stat is not None:
            return stat.st_size
        return -1

    def __int__(self) -> int:
        return self.fd

    def __bytes__(self) -> bytes:
        return self.name

    def __str__(self) -> str:
        return repr(self.name)

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.fd}, {self.name!r})"


def shm_open(
    name: Union[str, bytes],
    flags: Union[Flags, str] = Flags.CREATE | Flags.READ_WRITE,
    permissions: int = DEFAULT_PERMISSIONS,
) -> SharedMemoryHandle:
    if isinstance(name, str):
        name = name.encode()
    if isinstance(flags, str):
        flags = Flags.from_mode(flags)
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
    return SharedMemoryHandle(FileDescriptor(fd), name, flags)


def truncate(fd: SharedMemoryHandle, size: int) -> int:
    if not isinstance(fd, SharedMemoryHandle):
        fd = SharedMemoryHandle(b"", fd)
    return fd.truncate(size)


@functools.singledispatch
def shm_unlink(name: Union[str, bytes]) -> None:
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
    try:
        exc_type = SHM_ERRCODES[ffi.errno]
    except KeyError:
        exc_type = OSError
    raise errors.format_exception(
        exc_type, errors.GENERIC_C_ERROR, ffi.errno, errno.errorcode.get(ffi.errno, "")
    )


@shm_unlink.register
def _(fd: SharedMemoryHandle) -> None:
    assert fd.name, "fd must have a name"
    size = len(fd)
    if size > -1:
        shm_unlink(fd.name)
        return size
    raise OSError(errno.EBADF, "File does not have a size, already closed")
