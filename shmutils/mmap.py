import io
import typing
import errno
import os
from typing import Union, NewType, Type, NamedTuple, Dict, Optional
from enum import IntFlag
from mmap import PROT_EXEC, PROT_READ, PROT_WRITE, PAGESIZE, MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS

if typing.TYPE_CHECKING:
    from typing import Literal
else:
    try:
        from typing import Literal
    except ImportError:
        from typing_extensions import Literal

from _shmutils import lib, ffi

from . import errors

from .shm import SharedMemoryHandle

Size = NewType("Size", int)


class Protections(IntFlag):
    NONE = 0
    EXEC = PROT_EXEC
    READ = PROT_READ
    WRITE = PROT_WRITE
    READ_WRITE = PROT_READ | PROT_WRITE
    READ_WRITE_EXECUTE = PROT_READ | PROT_WRITE | PROT_EXEC
    WRITE_EXECUTE = PROT_EXEC | PROT_WRITE
    READ_EXECUTE = PROT_READ | PROT_EXEC


class Flags(IntFlag):
    NONE = 0
    SHARED = MAP_SHARED
    PRIVATE = MAP_PRIVATE
    FIXED = lib.MAP_FIXED
    ANONYMOUS = MAP_ANONYMOUS


del PROT_EXEC
del PROT_READ
del PROT_WRITE
del MAP_SHARED
del MAP_PRIVATE
del MAP_ANONYMOUS

MMAP_NEW_ERRCODES: Dict[int, Type[Exception]] = {
    errno.EINVAL: OSError,
    errno.EACCES: PermissionError,
    errno.EBADF: (OSError, errors.MMAP_NEW_EBADF),
    errno.ENODEV: (OSError, errors.MMAP_NEW_ENODEV),
    errno.ENOMEM: MemoryError,
    errno.ENXIO: (OSError, errors.MMAP_NEW_ENXIO),
    errno.EOVERFLOW: (OSError, errors.MMAP_NEW_EOVERFLOW),
}


def round_to_page_size(size: Size) -> Size:
    assert size > -1
    pages, unallocated_bytes = divmod(size, PAGESIZE)
    if unallocated_bytes:
        pages += 1
    return Size(pages * PAGESIZE)


ssize_t = NewType("ssize_t", type(ffi.cast("ssize_t", -1)))
void_ptr = NewType("void*", type(ffi.cast("void*", -1)))
buffer_t = NewType("buffer_t", ffi.buffer)


class _RawMMap(NamedTuple):
    buffer: buffer_t

    address: void_ptr
    size: Size

    protection: Protections
    flags: Flags
    fd: int
    offset: int


class RawMMap(_RawMMap):
    def __new__(
        cls,
        address: Union[int, void_ptr, None],
        size: Size,
        protection: Protections,
        flags: Flags = Flags.NONE,
        fd: int = -1,
        offset: int = 0,
    ):
        if address is None:
            address = ffi.NULL
        elif isinstance(address, int):
            address = ffi.cast("void *", address)
        address_type = ffi.typeof(address)

        assert isinstance(size, int) and size > 0
        assert isinstance(protection, Protections)
        assert isinstance(flags, Flags)
        assert isinstance(fd, int) and fd >= -1
        assert isinstance(offset, int) and offset > -1
        assert address_type.kind == "pointer"
        assert address_type.item.kind == "void"

        if not (Flags.SHARED & flags == Flags.SHARED) and not (flags & Flags.PRIVATE):
            flags |= Flags.PRIVATE

        if fd == -1:
            if flags & Flags.PRIVATE:
                flags |= Flags.ANONYMOUS
            elif flags & Flags.SHARED:
                flags |= Flags.ANONYMOUS

        size = round_to_page_size(size)

        if offset > 0:
            offset = round_to_page_size(offset)
        ptr = lib.mmap(
            ffi.cast("void *", address),
            ffi.cast("size_t", size),
            int(protection),
            int(flags),
            int(fd),
            ffi.cast("off_t", offset),
        )
        if ptr == MMAP_FAILED:
            if ffi.errno == errno.EINVAL:
                template = "flags includes bits that are not part of any valid flags value."
                if flags & Flags.FIXED == Flags.FIXED:
                    template = errors.MMAP_NEW_EINVAL_FIXED
            elif ffi.errno == errno.EACCES:
                if protection & Protections.READ == Protections.READ:
                    template = errors.MMAP_NEW_EACCESS_READ_ASKED
                elif Protections & Protections.WRITE == Protections.WRITE:
                    template = errors.MMAP_NEW_EACCESS_WRITE_SHARED_ASKED
            elif ffi.errno == errno.ENOMEM:
                if flags & Flags.FIXED == Flags.FIXED:
                    template = errors.MMAP_NEW_ENOMEM_MAP_FIXED
                elif flags & Flags.ANONYMOUS:
                    template = errors.MMAP_NEW_ENOMEM_MAP_ANON
            raise mmap_error(ffi.errno, template)
        return super().__new__(cls, ffi.buffer(ptr, size), ptr, size, protection, flags, fd, offset)

    def __reduce__(self):
        return type(self), (
            int(self),
            len(self),
            self.protection,
            self.flags,
            self.fd,
            self.offset,
        )

    def __int__(self) -> int:
        start_address = ffi.cast("ssize_t", self.address)
        return start_address

    def __len__(self) -> int:
        return self.size


def mmap_error(error_code, template: Optional[str] = errors.GENERIC_C_ERROR, **kwargs):
    try:
        err_name: str = errno.errorcode[error_code]
    except KeyError:
        err_name = ""

    try:
        exc_type = MMAP_NEW_ERRCODES[error_code]
        if isinstance(exc_type, tuple):
            exc_type, template = exc_type
    except KeyError:
        exc_type = OSError
    if err_name:
        return errors.format_exception(exc_type, template, error_code, err_name, **kwargs)
    return errors.format_exception(exc_type, template, error_code, **kwargs)


MMAP_FAILED = ffi.cast("void*", -1)


class MappedMemory(io.RawIOBase):
    __slots__ = (
        "_raw",
        "_closed",
        "_view",
        "_index",
    )

    def __new__(
        cls,
        *args,
        **kwargs,
    ):
        has_flags = False
        try:
            flags = kwargs["flags"]
        except KeyError:
            try:
                flags = args[3]
            except IndexError:
                pass
            else:
                has_flags = True
        else:
            has_flags = True
        if has_flags:
            if flags & Flags.SHARED:
                cls = SharedMemory
            elif flags & Flags.PRIVATE:
                cls = PrivateMemory
                if flags & Flags.FIXED:
                    cls = FixedPrivateMemory
        return super().__new__(cls, *args, **kwargs)

    def __init__(
        self,
        address: Union[int, void_ptr, None],
        size: Size,
        protection: Protections = Protections.READ_WRITE,
        flags: Flags = Flags.NONE,
        fd: Union[int, SharedMemoryHandle] = -1,
        offset: int = 0,
    ):
        self._closed = False
        self._fd = fd
        self._index = 0
        self._raw = RawMMap(address, size, protection, flags, int(fd), offset)
        self._view = memoryview(self._raw.buffer)

    def __reduce__(self):
        address = int(self._raw)
        size = len(self._raw)
        protection = self._raw.protection
        flags = self._raw.flags
        offset = self._raw.offset
        index = self.tell()
        if flags & Flags.ANONYMOUS:
            raise TypeError("Anonymous Mappings may only be inherited through fork!")
        return unpickle_mmap, (address, size, protection, flags, self._fd, offset, index)

    def close(self):
        if self._closed:
            return
        if self._fd:
            self._fd = None
        if self._view is not None:
            self._view.release()
            self._view = None
        if self._raw is not None:
            _, address, size, *_ = self._raw
            unmap(address, size)
            self._raw = None
        self._closed = True

    def __len__(self) -> int:
        if self._raw is not None:
            return len(self._raw)
        return -1

    def getbuffer(self, start_index: int = 0, length: int = -1) -> memoryview:
        if (start_index, length) == (0, -1):
            return self._view
        if length == -1:
            length = len(self)
        if start_index + length > len(self):
            length = len(self) - start_index
        return self._view[start_index : start_index + length]

    def fileno(self) -> int:
        fd = int(self._fd)
        if fd == -1:
            raise io.UnsupportedOperation
        return fd

    def seek(self, offset: int, whence: Literal[os.SEEK_SET, os.SEEK_CUR, os.SEEK_END]):
        if whence == os.SEEK_SET:
            assert offset >= 0
            new_index = offset
        elif whence == os.SEEK_CUR:
            new_index = self._index + offset
        elif whence == os.SEEK_END:
            assert offset <= 0
            new_index = self._index + offset
        else:
            raise io.UnsupportedOperation
        if new_index >= len(self):
            new_index = len(self) - 1
        elif new_index < 0:
            new_index = 0
        self._index = new_index
        return self._index

    def tell(self) -> int:
        return self._index

    def __getitem__(self, slice_or_index: Union[int, slice]):
        return self._view.__getitem__(slice_or_index)

    def __setitem__(self, slice_or_index: Union[int, slice], value):
        return self._view.__setitem__(slice_or_index, value)

    @property
    def remainder(self) -> int:
        return len(self) - self._index

    @property
    def pages(self) -> int:
        return len(self) // PAGESIZE

    @property
    def flags(self) -> Flags:
        return self._raw.flags

    def readinto(self, buffer) -> int:
        index = self._index
        length = len(buffer)
        if length > self.remainder:
            length = self.remainder
        buffer[0:length] = self._view[index : index + length]
        self._index = index + length
        return length

    def write(self, b: bytes) -> int:
        index = self._index
        size = len(b)
        if index + size >= len(self):
            size = len(self) - index
        self._view[index : index + size] = b[0:size]
        self._index = index + size
        return size

    def truncate(self, size) -> int:
        raise io.UnsupportedOperation


def unpickle_mmap(address, size, protection, flags, fd, offset, seek_to) -> MappedMemory:
    m = MappedMemory(address, size, protection, flags, fd, offset)
    m.seek(seek_to)
    return m


class SharedMemory(MappedMemory):
    def __init__(
        self,
        address: Union[int, void_ptr, None],
        size: Size,
        protection: Protections = Protections.READ_WRITE,
        flags: Flags = Flags.NONE,
        fd: Union[int, SharedMemoryHandle] = -1,
        offset: int = 0,
    ):
        if not flags:
            flags = Flags.SHARED
        if not (flags & Flags.SHARED):
            raise ValueError(f"Unable to initialize {type(self).__name__} without SHARED flags")
        super().__init__(address, size, protection, flags, fd, offset)

    def __reduce__(self):
        """
        pickling a relative shared memory always becomes Absolute.
        """
        address = int(self._raw)
        size = len(self._raw)
        return unpickle_mmap, (
            address,
            size,
            self._raw.protection,
            self.raw.flags | Flags.FIXED,
            self._fd,
            self._raw.offset,
        )


class PrivateMemory(MappedMemory):
    def __init__(
        self,
        address: Union[int, void_ptr, None],
        size: Size,
        protection: Protections = Protections.READ_WRITE,
        flags: Flags = Flags.NONE,
        fd: Union[int, SharedMemoryHandle] = -1,
        offset: int = 0,
    ):
        if not flags:
            flags = Flags.PRIVATE
        if not (flags & Flags.PRIVATE):
            raise ValueError(f"Unable to initialize {type(self).__name__} without PRIVATE flags")
        super().__init__(address, size, protection, flags, fd, offset)


class FixedPrivateMemory(PrivateMemory):
    def __init__(
        self,
        address: Union[int, void_ptr, None],
        size: Size,
        protection: Protections = Protections.READ_WRITE,
        flags: Flags = Flags.NONE,
        fd: Union[int, SharedMemoryHandle] = -1,
        offset: int = 0,
    ):
        if not flags:
            flags = Flags.PRIVATE | Flags.FIXED
        if not (flags & Flags.FIXED):
            raise ValueError(f"Unable to initialize {type(self).__name__} without FIXED flags")
        super().__init__(address, size, protection, flags, fd, offset)


def unmap(address: void_ptr, size: int):
    result = lib.munmap(address, ffi.cast("size_t", size))
    if result == 0:
        return
    raise mmap_error(ffi.errno)
