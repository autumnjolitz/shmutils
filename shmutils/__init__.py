"Shared memory utils in python"
__version__ = "0.0.0"

from .posix import PosixSharedMemory, shm_open, shm_unlink
from .mmap import MappedMemory, Flags as MapFlags, Protections as MapProtections
from .utils import RelativeView


__all__ = [
    "PosixSharedMemory",
    "shm_open",
    "shm_unlink",
    "MappedMemory",
    "MapProtections",
    "MapFlags",
    "RelativeView",
]
