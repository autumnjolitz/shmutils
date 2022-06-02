import io
import typing
import errno
import os
import functools
import logging
import weakref
from contextlib import contextmanager
import collections.abc
from typing import Union, NewType, Type, NamedTuple, Dict, Tuple, Optional, Mapping, Any
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
from .typing import void_ptr, buffer_t, AddressRange
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
Address = NewType("Address", int)

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


class Alloc:
    __slots__ = ("start", "size", "ptr_type")

    def __init__(self, start, size, ptr_type: str = "void*"):
        self.start = start
        self.size = size
        self.ptr_type = ptr_type

    def keys(self):
        return self.__slots__

    def __iter__(self):
        yield self.start
        yield self.size
        yield self.ptr_type


PageRange = NewType("PageRange", range)


class AddressToPageMapping:
    def __init__(self, mapping):
        self.mapping = mapping

    def __len__(self):
        return self.mapping.size

    def __getitem__(self, address) -> Union[int, range]:
        if isinstance(address, slice):
            return range(
                self[address.start or self.mapping.address],
                self[address.end or self.mapping.address + self.mapping.size],
                PAGESIZE,
            )
        index = self.mapping.relative_address_at[address] // PAGESIZE
        return index


class PageMapping(collections.abc.Mapping):
    def __init__(self, mapping):
        self.length = len(mapping) // PAGESIZE
        self.mapping = mapping
        self.by_address = AddressToPageMapping(mapping)

    def __contains__(self, address):
        return self.mapping.address <= address < self.mapping.address + self.mapping.size

    def __len__(self) -> int:
        return self.length

    def __iter__(self):
        for key in self.keys():
            yield key, self[key]

    def __getitem__(self, page_index: Union[int, slice]) -> Union[Address, AddressRange]:
        """
        Map a page index to an absolute address
        or a page_start:end to a range(absolute_address + page_start, ...)
        """
        if isinstance(page_index, slice):
            start_index, stop = page_index.start, page_index.stop
            if start_index is None:
                start_index = 0
            if stop is None:
                stop = self.length
            return AddressRange(range(self[start_index], (self[stop] - 1) + PAGESIZE, PAGESIZE))
        if 0 <= page_index < self.length:
            return self.mapping.abs_address_at[PAGESIZE * page_index]
        raise KeyError(page_index)

    def keys(self) -> PageRange:
        return PageRange(range(0, self.length))

    def __repr__(self):
        return f"PageMapping({self.length - 1})"


class RelativeMemory:
    at: Mapping[Union[int, slice], Union[int, bytes]]
    relative_address_at: Mapping[Union[Address, ffi.CData, slice], Union[int, range]]
    page: Mapping[Union[int, slice], Union[Address, AddressRange]]

    def __init__(self, *args, **kwargs):
        # maps an relative pointer to a value in the heap
        self.at = RelativeView(self)
        # maps a relative addrress to one that can be ``ffi.cast('void*', ...)`` and have
        # it work.
        self.relative_address_at = AbsoluteToRelativeAddress(self)

        # maps page index to address like `.pages[0]` -> absolute_address of page 0,
        #   `.pages[0:4]`` -> range(pages[0], pages[3], PAGESIZE)
        self.pages = PageMapping(self)
        super().__init__(*args, **kwargs)

    def close(self):
        if not self.closed:
            if self.page is not None:
                self.page = None
            if self.at is not None:
                self.at = None
            if self.relative_address_at is not None:
                self.relative_address_at = None
        super().close()


class AbsoluteMemory:
    absolute_at: Mapping[Union[int, ffi.CData], int]
    abs_address_at: Mapping[Union[int, ffi.CData], int]

    def __init__(self, *args, **kwargs):
        # maps an absolute pointer to a value in the heap
        self.absolute_at = AbsoluteView(self)
        # maps a relative address to a absolute address
        self.abs_address_at = RelativeToAbsoluteAddress(self)
        super().__init__(*args, **kwargs)

    def close(self):
        if not self.closed:
            if self.absolute_at is not None:
                self.absolute_at = None
            if self.abs_address_at is not None:
                self.abs_address_at = None
        super().close()


class Heap:
    def __init__(self, *args, **kwargs):
        self._used = NonEvictingIntervalTree()
        self._freelist = NonEvictingIntervalTree()
        self._new = ffi.new_allocator(alloc=self.malloc, free=self.free)
        super().__init__()

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

    def _register_allocation(
        self, span: Union[Interval, Tuple[int, int], Tuple[int, int, Any]], size: int
    ) -> Interval:
        """
        mark a region as used in our feal for a size.
        """
        if not isinstance(span, Interval) and isinstance(span, tuple) and len(span) in (2, 3):
            span = Interval(*span)
        assert isinstance(span, Interval)
        assert not self._used[span.begin : span.end], "double registration!"
        unused_bytes_in_range = span.end - (span.begin + size)
        assert unused_bytes_in_range > -1
        if unused_bytes_in_range:
            # release this range to the freelist again
            self._freelist.add(
                self._merge_intervals_near(
                    Interval(span.begin + size, span.end, None), self._freelist
                )
            )
        self._used[span.begin : span.begin + size] = Alloc(span.begin, size, span.data)
        return span

    def malloc(self, size: int, ptr_type: str = "void*") -> Union[void_ptr, Literal[ffi.NULL]]:
        for candidate in self._freelist.items():
            if candidate.begin + size <= candidate.end:
                break
        else:
            # No freelist entries available. :(
            # so let's just move our in used boundary forwards...
            offset: int = self.tell()  # relative address
            written_size = self.write(b"\x00" * size)
            if written_size < size:
                logger.error("out of space")
                return ffi.NULL
            assert self.tell() - offset == size
            self._used[offset : offset + size] = Alloc(offset, size, ptr_type)
            return ffi.cast("void*", self.abs_address_at[offset])
        # Take out of circulation
        self._freelist.remove(candidate)
        used = self._register_allocation(candidate, size)
        used.data.ptr_type = ptr_type
        return ffi.cast("void*", self.abs_address_at[used.begin])

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

        data: Alloc = interval.data
        assert data.start == self.relative_address_at[ptr]
        assert data.size == size

        self.at[offset : offset + size] = b"\x00" * size
        freed_interval = self._merge_intervals_near(
            Interval(offset, offset + size, None), self._freelist
        )
        self._freelist.add(freed_interval)
        if len(self._freelist) == 1:
            (i,) = self._freelist.items()
            if not self._used[i.end : len(self)]:
                self.at[i.begin : i.end] = b"\x00" * (i.end - i.begin)
                self.seek(i.begin)
                self._freelist.remove(i)

    def new(self, cdecl: str, init=None) -> ffi.CData:
        """
        See ``ffi.new(...)```
        """
        ptr: void_ptr = self._new(cdecl, init)
        index = self.relative_address_at[ptr]
        (i,) = self._used.at(index)
        i.data.ptr_type = cdecl
        return ptr

    def dumpheap(self) -> Dict[Tuple[int, int], str]:
        """
        print out the allocated ranges and c_types of the owners.
        """
        heap = {}
        for used in self._used.items():
            heap[(used.begin, used.end)] = used.data.ptr_type
        return dict(sorted(heap.items(), key=lambda item: item[0][0]))

    def close(self):
        if self.closed:
            return
        if self._used is not None:
            self._used.clear()
            self._used = None
        if self._freelist is not None:
            self._freelist.clear()
            self._freelist = None
        if self.new is not None:
            self.new = None
        super().close()


class MemoryFile(io.RawIOBase):
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
        self._fd = fd
        self._index = 0
        size = round_to_page_size(size)
        self._ptr = ptr = mmap(address, size, protection, flags, fd, offset)
        # record the address from a uintptr_t of the mmap (might be different from prior address)
        self.address = address = int(ffi.cast("uintptr_t", ptr))
        self._raw = RawMMap(ffi.buffer(ptr, size), ptr, size, protection, flags, int(fd), offset)

        super().__init__(address, size, protection, flags, fd, offset)

        _all_mmaps[address] = self

    @property
    def size(self):
        return self._raw.size

    def __len__(self) -> int:
        return self._raw.size

    def __reduce__(self):
        address = self.address
        size = len(self)
        protection = self._raw.protection
        flags = self._raw.flags
        offset = self._raw.offset
        index = self.tell()
        return unpickle_mmap, (
            type(self),
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

    def detach(self) -> RawMMap:
        """
        disconnect from this object the pointer, size
        """
        if self.closed:
            raise io.UnsupportedOperation("already detached the buffer!")
        raw = self._raw
        self._raw = None
        self.close()
        return raw

    def close(self):
        if self.closed:
            return
        if self.address is not None:
            self.address = None
        if self._fd is not None:
            self._fd = None
        if self._ptr is not None:
            self._ptr = None
        if self._raw is not None:
            _, address, size, *_ = self._raw
            munmap(address, size)
            self._raw = None
        super().close()

    def getbuffer(self, start_index: int = 0, length: int = -1) -> memoryview:
        if self.closed:
            raise io.UnsupportedOperation
        buf = memoryview(self._raw.buffer)
        if (start_index, length) == (0, -1):
            return buf
        if length == -1:
            length = len(self)
        if start_index + length > len(self):
            length = len(self) - start_index
        return buf[start_index : start_index + length]

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

    def readinto(self, buffer) -> int:
        index = self._index
        length = len(buffer)
        if length > self.remainder:
            length = self.remainder
        buffer[0:length] = self._raw.buffer[index : index + length]
        self._index = index + length
        return length

    def write(self, b: bytes) -> int:
        index = self._index
        size = len(b)
        if index + size >= len(self):
            size = len(self) - index
        self._raw.buffer[index : index + size] = b[0:size]
        self._index = index + size
        return size

    def truncate(self, size) -> int:
        raise io.UnsupportedOperation


class MappedMemory(MemoryFile, RelativeMemory, AbsoluteMemory, Heap):
    @property
    def remainder(self) -> int:
        return len(self) - self._index

    @property
    def flags(self) -> Flags:
        return self._raw.flags


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
    cls,
    desired_address: int,
    size: int,
    protection,
    flags: Flags,
    fd: Union[int, SharedMemoryHandle],
    offset: int,
    seek_to: int,
    freelist: NonEvictingIntervalTree,
    usedlist: NonEvictingIntervalTree,
) -> MappedMemory:
    assert fd == -1 or os.fstat(int(fd)).st_size > 0
    if has_forked:
        # Fixed is mandatory in a forked process as we've already the range claimed
        flags |= Flags.FIXED
    else:
        # we want to explode if we're not already claimed
        flags ^= Flags.FIXED
    m = cls(desired_address, size, protection, flags, fd, offset)
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


MMAP_FAILED: void_ptr = ffi.cast("void*", -1)


def mmap(
    address: Optional[Union[int, Literal[ffi.NULL]]] = None,
    size: int = PAGESIZE,
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


def munmap(address: void_ptr, size: int):
    assert size > 0 and size == round_to_page_size(size)
    raw_address = int(ffi.cast("uintptr_t", address))
    _, remainder = divmod(raw_address, PAGESIZE)
    assert not remainder
    result = lib.munmap(address, ffi.cast("size_t", size))
    if result == 0:
        return
    raise munmap_error(template=errors.MUNMAP_EINVAL_MAP_STOMPED_BY_FIXED)
