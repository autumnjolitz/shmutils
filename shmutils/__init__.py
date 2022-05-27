from __future__ import annotations

import os
import errno
from typing import Union

from .page import SharedPage, PageFlags as SharedPageFlags, shm_malloc, free, remove
from .utils import RelativeView
from _shmutils import lib, ffi


def get_errname():
    try:
        return (ffi.errno, errno.errorcode[ffi.errno])
    except KeyError:
        return (ffi.errno, "UNK")


def Lock(memory: MemoryGroup, *, _ranges=None):
    return SharedLock(memory, _ranges=_ranges)


def RLock(memory: MemoryGroup, *, _ranges=None):
    return SharedLock(memory, recursive=True, _ranges=_ranges)


def _lock_with_ranges(memory, ranges):
    return Lock(memory, _ranges=ranges)


def _rlock_with_ranges(memory, ranges):
    return RLock(memory, _ranges=ranges)


class SharedLock:
    """
    A multiprocess lock.
    """

    def __init__(self, memory: MemoryGroup, *, recursive: bool = False, _ranges=None):
        self.memory = memory
        if _ranges is None:
            attr = memory.new("pthread_mutexattr_t*")
            attr_range = memory.ptrs[attr]
            lock = memory.new("pthread_mutex_t*")
            lock_range = memory.ptrs[lock]
            if lib.pthread_mutexattr_init(attr) != 0:
                raise ValueError("pthread_mutexattr_init error")
            if lib.pthread_mutexattr_setpshared(attr, lib.get_pthread_process_shared()) != 0:
                raise ValueError("Set shared error!")
            if recursive:
                if lib.pthread_mutexattr_settype(attr, lib.get_pthread_recursive_type()) != 0:
                    raise ValueError(f"[{get_errname()}] mutex attr set type error!!")
            if lib.pthread_mutex_init(lock, attr) != 0:
                raise ValueError(f"[{get_errname()}] mutex init error!")
        else:
            (_, attr_range), (_, lock_range) = _ranges
            attr = ffi.cast("pthread_mutexattr_t*", memory.c_buf[attr_range[0] : attr_range[1]])
            lock = ffi.cast("pthread_mutex_t*", memory.c_buf[lock_range[0] : lock_range[1]])
        self.mutexattr = attr
        self._mutex = lock
        self.locked = 0
        self.ranges = (attr_range, lock_range)
        self.recursive = recursive

    def __reduce__(self):
        if self.recursive:
            return _rlock_with_ranges, (self.memory, self.ranges)
        return _lock_with_ranges, (self.memory, self.ranges)

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()

    def acquire(self, blocking=True, timeout=-1):
        if blocking:
            result = lib.pthread_mutex_lock(self._mutex)
        else:
            result = lib.pthread_mutex_trylock(self._mutex)
        if result != 0:
            raise ValueError(f"[{get_errname()}] Unable to lock!")
        self.locked += 1

    def release(self):
        assert self.locked >= 0
        if not self.locked:
            raise RuntimeError("unlocked")
        result = lib.pthread_mutex_unlock(self._mutex)
        if result != 0:
            err_name = get_errname()
            raise ValueError(f"{err_name} Unlock failure!")
        self.locked -= 1


class MemoryGroup:
    """
    Attempt to allow a SHM mmap to be passed into
    other processes.
    """

    def heap(self) -> RelativeView:
        """
        Return a view of the heap (after the headers)
        """
        return RelativeView(self.file._mmap, self._memory_start, self.size - self._memory_start)

    def __reduce__(self):
        return MemoryGroup, (self.file, self.size)

    def new_mutex(self) -> SharedLock:
        return SharedLock(self)

    def __init__(self, name: Union[SharedPage, str], size: int):
        self._allocated_ptrs = {}
        self.size = size
        file = None
        if isinstance(name, str):
            self.name = name
        elif isinstance(name, SharedPage):
            file = name
            self.name = name = file.name
        if file is None:
            self.file = file = shm_malloc(self.name, "x+", size)
            if file.mode == "x+":
                self._init_malloc_map()
            else:
                self._load_malloc_map()
        else:
            self.file = file
            self._load_malloc_map()
        self.new = ffi.new_allocator(
            alloc=ffi.callback("void*(size_t)")(self._malloc),
            free=ffi.callback("void(void*)")(self._free),
        )

    def _init_malloc_map(self):
        header_size = ffi.sizeof("shmmmap_header_t")
        # if we use a bit to mark a byte as "used" and zero as free,
        # we can just scan for a good enough size linearly
        bytes_needed = self.file.size // 8
        header = ffi.cast("shmmmap_header_t*", self.c_buf[0:header_size])
        assert ffi.string(header.header) != b"shmutils_mmap"
        header.header = b"shmutils_mmap\x00"
        header.size = self.file.size
        header.owner_pid = os.getpid()
        del header

        with memoryview(self.file._mmap) as m:
            with m[header_size : header_size + bytes_needed] as view:
                view[0:bytes_needed] = b"\x00" * bytes_needed
        self.seek(header_size + bytes_needed)
        self._memory_start = bytes_needed + header_size

    def _load_malloc_map(self):
        header_size = ffi.sizeof("shmmmap_header_t")
        header = ffi.cast("shmmmap_header_t*", self.c_buf[0:header_size])
        assert ffi.string(header.header) == b"shmutils_mmap"
        bytes_needed = self.file.size // 8
        self._memory_start = bytes_needed + header_size
        self.file.seek(bytes_needed + header_size)

    @property
    def ptrs(self):
        return self._allocated_ptrs

    @property
    def c_buf(self):
        return self.file.c_buffer

    def _malloc(self, size: int):
        header_size = ffi.sizeof("shmmmap_header_t")
        bytes_needed = self.file.size // 8

        with memoryview(self.file._mmap) as buf, buf[
            header_size : header_size + bytes_needed
        ] as memory_used:
            span_start = None
            span_length = 0
            for index, state in enumerate(memory_used):
                if state == 0:
                    # unused
                    if span_start is None:
                        span_start = index
                    span_length += 1
                    if span_length == size:
                        # mark in use
                        memory_used[span_start : span_start + size] = b"\x01" * size
                        real_start = header_size + bytes_needed + span_start
                        real_end = real_start + size
                        ptr = ffi.addressof(self.c_buf[real_start:real_end])
                        self._allocated_ptrs[ptr] = (
                            (span_start, span_start + size),
                            (real_start, real_end),
                        )
                        return ptr
                elif state == 1:
                    # used
                    if span_start is not None:
                        span_start = None
                        span_length = 0
                else:
                    raise ValueError(f"wtf, got {state}")
        print("OOM!")
        return None

    def _free(self, ptr):
        if not self.file:
            # print(f'{ptr} was freed by gc after closed')
            return
        header_size = ffi.sizeof("shmmmap_header_t")
        bytes_needed = self.file.size // 8

        try:
            span, (index, endex) = self._allocated_ptrs.pop(ptr)
        except KeyError:
            print(f"ptr {ptr} not in {self._allocated_ptrs}")
        else:
            print(f"freed {index}:{endex}")
            self.c_buf[index:endex] = b"\xee" * (endex - index)
            with memoryview(self.file._mmap) as buf, buf[
                header_size : header_size + bytes_needed
            ] as use_map:
                span_start, span_end = span
                use_map[span_start:span_end] = b"\x00" * (span_end - span_start)

    def __getitem__(self, *args, **kwargs):
        return self.file.__getitem__(*args, **kwargs)

    def __setitem__(self, *args, **kwargs):
        return self.file.__setitem__(*args, **kwargs)

    def __getattr__(self, key):
        if key in (
            "read",
            "write",
            "tell",
            "seek",
        ):
            return getattr(self.file, key)
        return object.__getattribute__(self, key)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        if self.file and not self.file.closed:
            self.file.close()
        self.file = None


__all__ = ["SharedPage", "SharedPageFlags", "shm_malloc", "free", "remove"]
