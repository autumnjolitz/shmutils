from __future__ import annotations

from .posix import PosixSharedMemory, shm_open, shm_unlink
from .mmap import MappedMemory, Flags as MapFlags, Protections as MapProtections
from .utils import RelativeView


__all__ = [
    "PosixSharedMemory",
    "shm_open",
    "shm_unlink",
    "MappedMemory",
    "RelativeView",
]
