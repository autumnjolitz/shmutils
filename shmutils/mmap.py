import io
import typing
import errno
import os
import functools
import logging
import weakref
from typing import Union, NewType, Type, NamedTuple, Dict, Tuple
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
from intervaltree import IntervalTree, Interval
from . import errors
from .errors import libc_error
from .typing import void_ptr, buffer_t
from .utils import (
    AbsoluteView,
    RelativeView,
    RelativeToAbsoluteAddress,
    AbsoluteToRelativeAddress,
    is_cffi,
)

from .shm import SharedMemoryHandle

logger = logging.getLogger(__name__)
Size = NewType("Size", int)

has_forked: bool = False

_all_mmaps = weakref.WeakValueDictionary()


@ffi.def_extern()
def mmap_fork_callback():
    global has_forked
    has_forked = True


code = lib.pthread_atfork(ffi.NULL, ffi.NULL, lib.mmap_fork_callback)
if code:
    raise libc_error(error_code=code)
del code


class NonEvictingIntervalTree(IntervalTree):
    def add(self, interval):
        if not self[interval.begin : interval.end]:
            return super().add(interval)
        raise ValueError("in use!")

    def addi(self, begin, end, data):
        if not self[begin:end]:
            return super().addi(begin, end, data)
        raise ValueError("in use!")

    def __setitem__(self, index_or_slice, value):
        if not self.__getitem__(index_or_slice):
            return super().__setitem__(index_or_slice, value)
        raise ValueError("in use!")


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
        address_type = None
        if address is None or address == ffi.NULL:
            address = 0
        else:
            if not isinstance(address, int):
                address_type = ffi.typeof(address)

        assert isinstance(size, int) and size > 0
        assert address > -1
        assert isinstance(protection, Protections)
        assert isinstance(flags, Flags)
        assert isinstance(fd, int) and fd >= -1
        assert isinstance(offset, int) and offset > -1
        assert address_type is None or (address_type.kind, address_type.item.kind) == (
            "pointer",
            "void",
        )

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
        ptr = raw_mmap(address, size, protection, flags, fd, offset)
        unaligned = int(ffi.cast("uintptr_t", ptr)) % PAGESIZE
        assert not unaligned, "unalighned page!"
        return super().__new__(cls, ffi.buffer(ptr, size), ptr, size, protection, flags, fd, offset)

    def __reduce__(self):
        raise TypeError

    def as_absolute_offset(self) -> int:
        return int(ffi.cast("uintptr_t", self.address))

    def as_relative_offset(self, cdata) -> int:
        void_ptr = ffi.cast("void*", cdata)
        offset = int(void_ptr - self.address)
        assert offset <= self.size
        return offset

    def __len__(self) -> int:
        return self.size


def raw_mmap(
    address: int,
    size: int,
    protection: Protections,
    flags: Flags,
    fd: Union[SharedMemoryHandle, int],
    offset: int,
) -> void_ptr:
    ptr = lib.mmap(
        ffi.cast("void *", address),
        ffi.cast("size_t", size),
        int(protection),
        int(flags),
        int(fd),
        ffi.cast("off_t", offset),
    )
    if ptr == MMAP_FAILED:
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
    return ptr


MMAP_FAILED = ffi.cast("void*", -1)


class MappedMemory(io.RawIOBase):
    __slots__ = (
        "_raw",
        "_closed",
        "_view",
        "_index",
        "_used",
        "_freelist",
        "_allocator",
        "address",
    )

    def __new__(
        cls,
        address,
        *args,
        **kwargs,
    ):
        if address in (0, ffi.NULL, None):
            address = 0
        if not isinstance(address, int) and is_cffi(address):
            address = int(ffi.cast("uintptr_t", address))
        if address and address in _all_mmaps:
            return _all_mmaps[address]
        has_flags = False
        try:
            flags = kwargs["flags"]
        except KeyError:
            try:
                flags = args[2]
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
        return super().__new__(cls, address, *args, **kwargs)

    def __init__(
        self,
        address: Union[int, void_ptr, None],
        size: Size,
        protection: Protections = Protections.READ_WRITE,
        flags: Flags = Flags.PRIVATE | Flags.ANONYMOUS,
        fd: Union[int, SharedMemoryHandle] = -1,
        offset: int = 0,
    ):
        assert isinstance(fd, (int, SharedMemoryHandle))
        self._closed = False
        self._fd = fd
        self._index = 0
        self._raw = RawMMap(address, size, protection, flags, int(fd), offset)
        self.address = self._raw.as_absolute_offset()
        self._view = memoryview(self._raw.buffer)
        self._used = NonEvictingIntervalTree()
        self._freelist = NonEvictingIntervalTree()
        self.new = ffi.new_allocator(alloc=self.malloc, free=self.free)

        # maps an absolute pointer to a value in the heap
        self.absolute_at = AbsoluteView(self)
        # maps an relative pointer to a value in the heap
        self.at = RelativeView(self)
        # maps a absolute address to a relative address
        self.abs_address_at = RelativeToAbsoluteAddress(self)
        # maps a relative addrress to one that can be ``ffi.cast('void*', ...)`` and have
        # it work.
        self.relative_address_at = AbsoluteToRelativeAddress(self)
        _all_mmaps[self._raw.as_absolute_offset()] = self

    def __reduce__(self):
        address = self.abs_address_at[0]
        size = len(self._raw)
        protection = self._raw.protection
        flags = self._raw.flags
        offset = self._raw.offset
        index = self.tell()
        return unpickle_mmap, (
            address,
            size,
            protection,
            flags,
            self._fd,
            offset,
            index,
            self._freelist,
            self._used,
        )

    def detach(self) -> Tuple[void_ptr, Size]:
        """
        disconnect from this object the pointer, size
        """
        if self._closed:
            raise io.UnsupportedOperation
        raw = self._raw
        self._raw = None
        self.close()
        return (raw.address, raw.size)

    def close(self):
        if self._closed:
            return
        if self.address is not None:
            self.address = None
        if self._used is not None:
            self._used.clear()
            self._used = None
        if self._freelist is not None:
            self._freelist.clear()
            self._freelist = None
        if self.new is not None:
            self.new = None
        if self.absolute_at is not None:
            self.absolute_at = None

        if self.at is not None:
            self.at = None
        if self.abs_address_at is not None:
            self.abs_address_at = None
        if self.relative_address_at is not None:
            self.relative_address_at = None

        if self._fd:
            self._fd = None
        if self._view is not None:
            self._view.release()
            self._view = None
        if self._raw is not None:
            _, address, size, *_ = self._raw
            munmap(address, size)
            self._raw = None
        self._closed = True

    def __len__(self) -> int:
        return len(self._raw)

    def get_cbuffer(self) -> buffer_t:
        if self._raw is not None:
            return self._raw.buffer
        raise OSError(errno.EBADF, "operation on closed mmap")

    def getbuffer(self, start_index: int = 0, length: int = -1) -> memoryview:
        if (start_index, length) == (0, -1):
            return memoryview(self._view)
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

    def seek(
        self, offset: int, whence: Literal[os.SEEK_SET, os.SEEK_CUR, os.SEEK_END] = os.SEEK_SET
    ):
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
            new_index = len(self)
        elif new_index < 0:
            new_index = 0
        self._index = new_index
        return self._index

    def tell(self) -> int:
        return self._index

    def __getitem__(self, slice_or_index: Union[int, slice]):
        """
        Access at the relative offsets
        """
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

    def _merge_intervals_near(self, span: Interval, tree: IntervalTree) -> Interval:
        data = span.data
        size = span.end - span.begin
        assert not tree.at(span.begin)
        assert not tree[span.begin : span.end]
        while tree.at(span.begin + size):
            (next_freed,) = tree.at(span.begin + size)
            tree.remove(next_freed)
            assert next_freed != span
            span = Interval(span.begin, next_freed.end)
        if span.begin > 0:
            while tree.at(span.begin - 1):
                (prev_freed,) = tree.at(span.begin - 1)
                tree.remove(prev_freed)
                span = Interval(prev_freed.begin, span.end)
        assert not tree[span.begin : span.end]
        return span._replace(data=data)

    def _register_allocation(self, span: Interval, size: int):
        """
        mark a region as used in our feal for a size.
        """
        if not isinstance(span, Interval) and isinstance(span, tuple):
            span = Interval(*span)
        assert not self._used[span.begin : span.end], "double registration!"
        unused_bytes_in_range = span.end - (span.begin + size)
        assert unused_bytes_in_range > -1
        if unused_bytes_in_range:
            # release this range to the freelist again
            self._freelist.add(
                self._merge_intervals_near(
                    Interval(span.begin + size, span.end, span.data), self._freelist
                )
            )
        self._used[span.begin : span.begin + size] = (span.begin, size)
        return span

    def malloc(self, size: int) -> Union[void_ptr, Literal[ffi.NULL]]:
        for candidate in self._freelist.items():
            if candidate.begin + size <= candidate.end:
                break
        else:
            # No freelist entries available. :(
            # so let's just move our in used boundary forwards...
            if self.remainder < size:
                logger.error("out of space")
                return ffi.NULL
            obj_start = self.tell()
            next_obj_start = self.seek(obj_start + size)
            self[obj_start:next_obj_start] = b"\x00" * size
            self._used[obj_start:next_obj_start] = (obj_start, size)
            return ffi.cast("void*", self._raw.address + obj_start)
        # Take out of circulation
        self._freelist.remove(candidate)
        self._register_allocation(candidate, size)
        return ffi.cast("void*", self._raw.address + candidate.begin)

    def free(self, ptr: void_ptr):
        if self._raw is None:
            return
        offset = ptr - self._raw.address
        try:
            (interval,) = self._used.at(offset)
        except ValueError:
            logger.error(f"double free at address {ptr} ({offset:=})")
            return
        self._used.remove(interval)
        size = interval.end - interval.begin

        self[offset : offset + size] = b"\x00" * size
        freed_interval = self._merge_intervals_near(
            Interval(offset, offset + size, None), self._freelist
        )
        self._freelist.add(freed_interval)
        if len(self._freelist) == 1:
            (i,) = self._freelist.items()
            if not self._used[i.end : len(self)]:
                self[i.begin : i.end] = b"\x00" * (i.end - i.begin)
                self.seek(i.begin)
                self._freelist.remove(i)


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


def mprotect(map: MappedMemory, offset: int, size: int, protection: Protections = Protections.NONE):
    address = ffi.cast("void*", map._raw.address + offset)
    if lib.mprotect(address, size, int(protection)):
        raise errors.libc_error(codes=MPROTECT_ERRS)


def unpickle_mmap(
    desired_address: int,
    size: int,
    protection,
    flags: Flags,
    fd: int,
    offset: int,
    seek_to: int,
    freelist: NonEvictingIntervalTree,
    usedlist: NonEvictingIntervalTree,
) -> MappedMemory:
    assert fd == -1 or os.fstat(fd).st_size > 0
    if has_forked:
        # Fixed is mandatory in a forked process as we've already the range claimed
        flags |= Flags.FIXED
    else:
        # we want to explode if we're not already claimed
        flags ^= Flags.FIXED
    m = MappedMemory(desired_address, size, protection, flags, fd, offset)
    if m._raw.as_absolute_offset() != desired_address:
        direction = "lower"
        if m._raw.as_absolute_offset() > desired_address:
            direction = "higher"
        raise ValueError(
            f"0x{desired_address:02x} is marked as already used by this process, relocated to 0x{m._raw.as_absolute_offset():02x} ({direction}, {(m._raw.as_absolute_offset() - desired_address) // 1024 // 1024:,d} mb offset)"
        )
    m.seek(seek_to)
    m._freelist = freelist
    m._used = usedlist
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
        address = self.abs_address_at[0]
        size = len(self._raw)
        protection = self._raw.protection
        flags = self._raw.flags
        offset = self._raw.offset
        index = self.tell()
        return unpickle_mmap, (
            address,
            size,
            protection,
            flags | Flags.FIXED,
            self._fd,
            offset,
            index,
            self._freelist,
            self._used,
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


def munmap(address: void_ptr, size: int):
    assert size > 0 and size == round_to_page_size(size)
    raw_address = int(ffi.cast("uintptr_t", address))
    _, remainder = divmod(raw_address, PAGESIZE)
    assert not remainder
    result = lib.munmap(address, ffi.cast("size_t", size))
    if result == 0:
        return
    raise munmap_error(template=errors.MUNMAP_EINVAL_MAP_STOMPED_BY_FIXED)
