import io
import errno
import functools
import logging
from typing import Union, Type, Dict, Optional, Generic, overload
from enum import IntFlag
from mmap import PROT_EXEC, PROT_READ, PROT_WRITE, PAGESIZE, MAP_SHARED, MAP_PRIVATE, MAP_ANONYMOUS

from ._shmutils import lib, ffi
from . import errors
from .errors import libc_error
from .typing import void_ptr, Size, T
from .typing import MAP_FAILED, AbsoluteAddress
from .types import ImmutableSpan


logger = logging.getLogger(__name__)


@ffi.def_extern()
def mmap_fork_callback():
    global has_forked
    has_forked = True


code = lib.pthread_atfork(ffi.NULL, ffi.NULL, lib.mmap_fork_callback)
if code:
    raise libc_error(error_code=code)
del code


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
    NORESERVE = lib.MAP_NORESERVE


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
    errno.ENOMEM: OSError,
    errno.ENXIO: (OSError, errors.MMAP_NEW_ENXIO),
    errno.EOVERFLOW: (OSError, errors.MMAP_NEW_EOVERFLOW),
}
MUNMAP_CODES: Dict[int, Type[Exception]] = {errno.EINVAL: OSError}

mmap_new_error = functools.partial(libc_error, codes=MMAP_NEW_ERRCODES)
munmap_error = functools.partial(libc_error, codes=MUNMAP_CODES)


def round_to_page_size(size: Size) -> Size:
    assert size > -1
    pages, unallocated_bytes = divmod(size, PAGESIZE)
    if unallocated_bytes:
        pages += 1
    return Size(pages * PAGESIZE)


MPROTECT_ERRS = {
    errno.EACCES: (
        PermissionError,
        "The requested protection conflicts with the access permissions of the process on the specified address range.",
    ),
    errno.EINVAL: (
        ValueError,
        "addr is not a multiple of the page size (i.e.  addr is not page-aligned).",
    ),
    errno.ENOMEM: (
        OSError,
        "The specified address range is outside of the address range of the process or includes an unmapped page.",
    ),
    errno.ENOTSUP: (
        io.UnsupportedOperation,
        "The combination of accesses requested in prot is not supported.",
    ),
}


# def mprotect(map: MappedMemory, offset: int, size: int, protection: Protections = Protections.NONE):
#     address = ffi.cast("void*", map._raw.address + offset)
#     if lib.mprotect(address, size, int(protection)):
#         raise errors.libc_error(codes=MPROTECT_ERRS)


class rawmmap(Generic[T]):
    __slots__ = ("_span", "_state", "__weakref__")

    def __init__(self, span: ImmutableSpan[T]):
        self._span = span
        self._state = "open"

    def __repr__(self):
        return f"{type(self).__name__}({self._span!r}, state={self._state!r})"

    @property
    def span(self):
        return self._span

    @property
    def state(self):
        return self._state

    @property
    def address(self) -> Optional[T]:
        if self._span is not None:
            return self._span.start

    def __len__(self):
        if self._span is not None:
            return self._span.length
        return 0

    def __enter__(self):
        if self._state in ("closing", "closed"):
            raise ValueError("Unable to operate on closed mmap!")
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self._state == "closed":
            return
        self._state = "closing"
        munmap(self.address, len(self))
        self._span = None
        self._state = "closed"


def mmap(
    address: Optional[Union[int, void_ptr]] = None,
    size: int = PAGESIZE * 32,
    protection: Union[Protections, int] = Protections.READ_WRITE,
    flags: Union[Flags, int] = Flags.NONE,
    fd: int = -1,
    offset: int = 0,
) -> void_ptr:
    if isinstance(flags, int):
        flags = Flags(flags)
    if isinstance(protection, int):
        protection = Protections(protection)
    if not isinstance(fd, int):
        fd = int(fd)
    if address is None or address == ffi.NULL:
        address = 0
    if not (Flags.SHARED & flags == Flags.SHARED) and not (flags & Flags.PRIVATE):
        flags |= Flags.PRIVATE

    if fd == -1:
        if flags & Flags.PRIVATE:
            flags |= Flags.ANONYMOUS
        elif flags & Flags.SHARED:
            flags |= Flags.ANONYMOUS
    assert offset >= 0
    assert fd >= -1
    assert size > 0
    assert round_to_page_size(size) == size, "size is not a multiple of PAGE_SIZE"
    assert isinstance(flags, Flags)
    assert address >= 0
    assert isinstance(protection, Protections)
    assert isinstance(flags, Flags)

    ptr = lib.mmap(
        ffi.cast("void *", address),
        ffi.cast("size_t", size),
        int(protection),
        int(flags),
        fd,
        ffi.cast("off_t", offset),
    )
    if ptr == MAP_FAILED:
        template = None
        if ffi.errno == errno.EINVAL:
            template = "flags ({flags!r}) includes bits that are not part of any valid flags value."
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
        raise libc_error(errors=MMAP_NEW_ERRCODES, flags=flags).with_template(template)
    as_uint_ptr = ffi.cast("uintptr_t", ptr)
    span = ImmutableSpan[AbsoluteAddress]
    return rawmmap(span(AbsoluteAddress(int(as_uint_ptr)), Size(size)))


@overload
def munmap(raw: rawmmap) -> None:
    ...


@overload
def munmap(address: int | ffi.CData, size: int) -> None:
    ...


def munmap(*args: tuple[int, int] | tuple[ffi.CData, int] | rawmmap) -> None:
    try:
        (raw,) = args
    except ValueError:
        address, size = args
    else:
        if raw.is_closed:
            raise ValueError("Unable to munmap a freed mmap")
        return munmap(raw.address, len(raw))
    assert size > 0 and size == round_to_page_size(size)
    try:
        addr_type = ffi.typeof(address)
    except TypeError:
        address = ffi.cast("void*", address)
    else:
        if addr_type.kind != "pointer":
            raise TypeError(f"{address!r} is not a pointer, but a {address.cname!r}")
        if addr_type.cname != "void *":
            address = ffi.cast("void*", address)
    result = lib.munmap(address, ffi.cast("size_t", size))
    if result == 0:
        return
    raise munmap_error(template=errors.MUNMAP_EINVAL_MAP_STOMPED_BY_FIXED)
