import abc
from contextlib import suppress
from typing import (
    NewType,
    NamedTuple,
    overload,
    TypeVar,
    Generic,
    cast as cast_type,
    Tuple,
    Optional,
    List,
    Callable,
    TypeAlias,
)
from enum import IntEnum

try:
    from typing import Protocol
except ImportError:
    from typing_extensions import Protocol
try:
    from typing import Self
except ImportError:
    from typing_extensions import Self

try:
    from typing import ParamSpec, Concatenate
except ImportError:
    from typing_extensions import ParamSpec, Concatenate


from ._shmutils import ffi

CData = ffi.CData
ssize_t = NewType("ssize_t", ffi.CData)
void_ptr = NewType("void*", ffi.CData)

MAP_FAILED = ffi.cast("void*", -1)


class AbstractWorkerContext(Protocol):
    def initialize_worker(self):
        ...


P = ParamSpec("P")


WorkerLifecycleCallable: TypeAlias = Callable[P, None]


buffer_t = NewType("buffer_t", ffi.buffer)
AddressRange = NewType("AddessRange", range)

RelativeAddress = NewType("RelativeAddress", int)
AbsoluteAddress = NewType("AbsoluteAddress", int)

Address = TypeVar("Address", RelativeAddress, AbsoluteAddress)

WrittenByteCount = NewType("WrittenByteCount", int)
Size = NewType("Size", int)

T = TypeVar("T")
U = TypeVar("U")
V = TypeVar("V")
S = TypeVar("S")


StartT = TypeVar("StartT")
StopT = TypeVar("StopT")
StepT = TypeVar("StepT")


class Slice(NamedTuple):
    start: StartT
    stop: StopT
    step: StepT


class Span(NamedTuple):
    """
    Interval format type is ``[,)``

    A Span is a lowest common denominator of an allocation in a
    single threaded environment.
    """

    start: Address
    length: Size

    @classmethod
    def new(cls, start, length):
        assert start >= 0
        assert length >= 0
        return cls(start, length)

    def __sizeof__(self) -> int:
        return self.length

    def __repr__(self):
        size = f"{self.length:,d}".replace(",", "_")
        return f"{type(self).__name__}({self.start:X}, {size})"

    def __str__(self):
        return f"Span[{self.start:10X}, {self.length:,d} bytes]"

    def last_valid_address(self):
        """
        Any value above this return is outside the span, period.
        """
        return self.start + self.length - 1

    def slice(self) -> Slice[Address, Address, Size]:
        """
        Returns a slice that returns just this span when fed to a mapping
        """
        return cast_type(Slice[Address, Address, Size], slice(self.start, self.start + self.length))


class TranslationMapping(Generic[T, U]):
    """
    Transform:
        self[address_start:address_end] -> Span(translated_start, size)
        self[address_start::size]       -> Span(translated_start, size)
        self[Span(address_start, size)] -> Span(translated_start, size)
        self[address_start]               -> translated_end
    """

    @overload
    def __getitem__(self, range: Slice[T, T, None]) -> Span[U]:
        ...

    @overload
    def __getitem__(self, range: Slice[T, None, Size]) -> Span[U]:
        ...

    @overload
    def __getitem__(self, range: Span[T]) -> Span[U]:
        ...

    @overload
    def __getitem__(self, address: T) -> U:
        ...

    def __getitem__(self, range_or_address):
        size = None
        if hasattr(range_or_address, "slice") or isinstance(range_or_address, slice):
            range = range_or_address
            if hasattr(range, "slice"):
                range = range.slice()
            range_start = range.begin
            if range.end is not None:
                size = range.end - range.start + 1
            elif range.step is not None:
                size = range.step
            if size is not None:
                return self.translate_range(range_start, size)
            raise ValueError("Incomplete range request!")
        return self.translate_address(range_start)


class AbsoluteToRelative(TranslationMapping[AbsoluteAddress, RelativeAddress]):
    __slots__ = ("_base_address",)

    def __init__(self, base_address):
        self._base_address = base_address

    def translate_range(self, start: AbsoluteAddress, size: Size) -> Span[RelativeAddress]:
        return Span[RelativeAddress](self.translate_address(start), size)

    def translate_address(self, address: RelativeAddress) -> AbsoluteAddress:
        return RelativeAddress(address - self._base_address)


class RelativeToAbsolute(TranslationMapping[RelativeAddress, AbsoluteAddress]):
    __slots__ = ("_base_address",)

    def __init__(self, base_address):
        self._base_address = base_address

    def translate_range(self, start: RelativeAddress, size: Size) -> Span[AbsoluteAddress]:
        return Span[AbsoluteAddress](self.translate_address(start), size)

    def translate_address(self, address) -> AbsoluteAddress:
        return AbsoluteAddress(self._base_address + address)


class AbstractHeap(Protocol[Address]):
    base_address: Address
    size: Size

    @classmethod
    async def open(*args, **kwargs):
        ...

    async def close():
        ...


class AbstractTranslatedHeap(Generic[T, U]):
    at: TranslationMapping[T, U]
    rev_at: TranslationMapping[U, T]


class AbstractSlab(AbstractHeap[T], AbstractTranslatedHeap[T, U]):
    pages: Span[T]
    num_free: int
    next_free: Optional[Span[T]]
    first_object: Optional[Span[T]]

    previous: Optional["AbstractSlab"]
    next: Optional["AbstractSlab"]

    @property
    def state(self):
        if self.num_free == 0:
            return "full"
        if self.first_object is None:
            return "empty"
        return "partial"

    async def alloc(self, size: V) -> Span[T, V]:
        ...

    async def free(self, address: T) -> Span[T, V]:
        ...


class AbstractSlabAllocator(Generic[T, U]):
    slabs: List[AbstractSlab[T, U]]

    async def alloc(self, size: Size) -> Span[T]:
        ...

    async def free(self, address: T) -> Span[T]:
        ...


class TypeCacheFlags(IntEnum):
    TYPE_CACHE_ON_OTHER: int = 0  # our type cache is allocated on another slab
    TYPE_CACHE_ON_SELF: int = 1  # our type cache is on this slab


class AbstractSlabTypeCache(Generic[T, U]):
    type_size: Size  # What sizeof are we servicing?
    size: Size  # What is the complete size of this?
    flags: TypeCacheFlags

    slab: AbstractSlab[T, U]

    pages_per_slab: int
    page_size: Size
    slab_size: Size

    wasted_memory_per_page: Size
    wasted_memory_per_slab: Size

    free_objs_count: int
    used_objs_count: int

    slab_count: int
    free_slabs_count: int
    partial_slabs_count: int
    full_slabs_count: int

    free_slabs: T
    partial_slabs: T
    full_slabs: T


# class SharedAbsoluteSlabAllocator(AbstractSlabAllocator[RelativeAddress, AbsoluteAddress]):
#     @classmethod
#     async def open(cls, filename: Optional[str] = None):
#         ...

#     async def close(self):
#         ...
