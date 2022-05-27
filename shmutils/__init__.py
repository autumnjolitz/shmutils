from __future__ import annotations

import os
import errno
import mmap
from enum import IntFlag
from typing import Union, Optional

from _shmutils import lib, ffi


def get_errname():
    try:
        return (ffi.errno, errno.errorcode[ffi.errno])
    except KeyError:
        return (ffi.errno, 'UNK')


class SHMFlags(IntFlag):
    READ_ONLY = os.O_RDONLY
    READ_WRITE = os.O_RDWR
    CREATE = os.O_CREAT
    EXCLUSIVE_CREATION = os.O_EXCL
    TRUNCATE_ON_OPEN = os.O_TRUNC

    def validate(self):
        if self & SHMFlags.READ_ONLY and self & SHMFlags.READ_WRITE:
            raise ValueError('Cannot be both readonly and readwrite')
        if self & SHMFlags.EXCLUSIVE_CREATION and not self & SHMFlags.CREATE:
            raise ValueError('EXCLUSIVE_CREATION only makes sense if CREATE is specified')
        if self & SHMFlags.READ_ONLY == self.READ_ONLY or self & self.READ_WRITE == self.READ_WRITE:
            return self
        raise ValueError('READ_ONLY or READ_WRITE must be specified')

    @classmethod
    def from_mode(cls, mode: str) -> SHMFlags:
        if mode.endswith("b"):
            mode = mode[:-1]
        mode_special = ''
        if len(mode) == 2:
            mode, mode_special = mode[0], mode[1]

        if mode not in ("r", "w", "a", "x"):
            raise ValueError("Must have exactly one of create/read/write/append mode and at most one plus")
        if mode_special not in ('', '+'):
            raise ValueError("Must have exactly one of create/read/write/append mode and at most one plus")
        if mode == "r":
            flags = cls.READ_ONLY
            if mode_special:
                flags = cls.READ_WRITE
        elif mode == "w":
            flags = cls.CREATE | cls.READ_WRITE
            if not mode_special:
                flags |= cls.TRUNCATE_ON_OPEN
        elif mode == "x":
            flags = cls.CREATE | cls.EXCLUSIVE_CREATION | cls.READ_WRITE
        elif mode == "a":
            raise NotImplementedError("appending to shared memory not implemented")
        return flags

    def to_mode(self) -> str:
        self.validate()
        mode = 'r'
        if self & self.CREATE:
            mode = 'w'
            if self & self.EXCLUSIVE_CREATION:
                mode = 'x'
        if self & self.TRUNCATE_ON_OPEN:
            mode = 'w'
        if self & self.READ_WRITE:
            mode = f'{mode}+'
        return mode


def reattach_shmpage(name, mode, size, skip_to):
    page = SHMPage(name, 'r+b', size)
    if skip_to:
        page.seek(skip_to)
    return page


class SHMPage:
    MAX_SIZE_BYTES = 4 * 1024 * 1024
    MIN_SIZE_BYTES = 1

    def __init__(
        self, name: Union[str, bytes, int], mode: Union[SHMFlags, str], size: Optional[int] = None, *, fd=None
    ):
        if size is None:
            size = self.MAX_SIZE_BYTES
        assert self.MIN_SIZE_BYTES <= size <= self.MAX_SIZE_BYTES
        if isinstance(mode, str):
            self.flags = SHMFlags.from_mode(mode)
            self.mode = mode
        elif isinstance(mode, (int, SHMFlags)):
            if isinstance(mode, int):
                mode = SHMFlags(mode)
            self.flags = mode
            self.mode = mode.to_mode()
        else:
            raise TypeError(f'unknown type {type(mode)}')
        if fd is None:
            fd = shm_open(name, self.flags, 0o600)
        self._fd = fd
        if self.flags & SHMFlags.EXCLUSIVE_CREATION:
            os.ftruncate(self._fd, size)
        self._mmap = mmap.mmap(self._fd, size)
        self.closed = False
        self.name = name
        self.size = size
        self._depth = 0
        self._allocated_ptrs = {}
        self._cbuf = ffi.from_buffer(self._mmap)

    def __reduce__(self):
        return reattach_shmpage, (self.name, self.mode, self.size, self.tell())

    def __getitem__(self, *args, **kwargs):
        return self._mmap.__getitem__(*args, **kwargs)

    def __setitem__(self, *args, **kwargs):
        self._mmap.__setitem__(*args, **kwargs)

    def tell(self):
        return self._mmap.tell()

    def seek(self, *args, **kwargs):
        self._mmap.seek(*args, **kwargs)

    def write(self, *args, **kwargs):
        return self._mmap.write(*args, **kwargs)

    def read(self, *args, **kwargs):
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
        self._allocated_ptrs.clear()
        self._cbuf = None
        self._mmap.close()
        os.close(self._fd)
        if self.flags & SHMFlags.EXCLUSIVE_CREATION:
            remove(self.name)
        self._fd = None
        self._mmap = None


DEFAULT_PERMISSIONS = 0o600


def shm_open(name: Union[str, bytes], flags: SHMFlags, permissions: int = DEFAULT_PERMISSIONS) -> int:
    if isinstance(name, str):
        name = name.encode()
    flags = flags.validate()
    with ffi.new('char[]', name) as c_name:
        fd = lib.shm_open(c_name, int(flags), permissions)
    if fd == -1:
        try:
            err_name = errno.errorcode[ffi.errno]
        except KeyError:
            raise ValueError(f"Unrecognized error code {ffi.errno}")
        if err_name == "EACCES":
            raise PermissionError(ffi.errno, err_name, name)
        elif err_name == "ENAMETOOLONG":
            raise ValueError(f'too many characters in {name!r}')
        elif err_name == "EEXIST":
            raise FileExistsError(f'[Errno {ffi.errno}]: File already exists: {name!r}')
        elif err_name == "ENOENT":
            raise FileNotFoundError(f'[Errno {ffi.errno}] No such file or directory: {name!r}')
        raise ValueError('Unable to open shm file due to %s' % err_name)
    return fd


def remove(name: Union[str, bytes]):
    if isinstance(name, str):
        name = name.encode()
    with ffi.new('char []', name) as c_name:
        errored = lib.shm_unlink(c_name)
    if not errored:
        return
    try:
        err_name = errno.errorcode[ffi.errno]
    except KeyError:
        raise IOError(f'Unknown errno {ffi.errno}')
    else:
        if err_name == 'EACCES':
            raise PermissionError(f"[Errno {ffi.errno}] Unable to access path {name!r}")
        elif err_name == "ENOENT":
            raise FileNotFoundError(f'[Errno {ffi.errno}] No such file or directory: {name!r}')
        elif err_name == "ENAMETOOLONG":
            raise ValueError(f'too many characters in {name!r}')
        raise IOError(f"Unknown error {ffi.errno} [{err_name}]")


def Lock(memory: MemoryGroup, *, _ranges=None):
    return SharedLock(memory, _ranges=_ranges)


def RLock(memory: Union[MemoryGroup], *, _ranges=None):
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
            attr = memory.new('pthread_mutexattr_t*')
            attr_range = memory.ptrs[attr]
            lock = memory.new('pthread_mutex_t*')
            lock_range = memory.ptrs[lock]
            if lib.pthread_mutexattr_init(attr) != 0:
                raise ValueError('pthread_mutexattr_init error')
            if lib.pthread_mutexattr_setpshared(attr, lib.get_pthread_process_shared()) != 0:
                raise ValueError('Set shared error!')
            if recursive:
                if lib.pthread_mutexattr_settype(attr, lib.get_pthread_recursive_type()) != 0:
                    raise ValueError(f'[{get_errname()}] mutex attr set type error!!')
            if lib.pthread_mutex_init(lock, attr) != 0:
                raise ValueError(f'[{get_errname()}] mutex init error!')
        else:
            (_, attr_range), (_, lock_range) = _ranges
            attr = ffi.cast('pthread_mutexattr_t*', memory.c_buf[attr_range[0]:attr_range[1]])
            lock = ffi.cast('pthread_mutex_t*', memory.c_buf[lock_range[0]:lock_range[1]])
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

    def acquire(self, blocking=True, timeout=- 1):
        if blocking:
            result = lib.pthread_mutex_lock(self._mutex)
        else:
            result = lib.pthread_mutex_trylock(self._mutex)
        if result != 0:
            raise ValueError(f'[{get_errname()}] Unable to lock!')
        self.locked += 1

    def release(self):
        assert self.locked >= 0
        if not self.locked:
            raise RuntimeError('unlocked')
        result = lib.pthread_mutex_unlock(self._mutex)
        if result != 0:
            err_name = get_errname()
            raise ValueError(f'{err_name} Unlock failure!')
        self.locked -= 1


class MemoryGroup:
    """
    Attempt to allow a SHM mmap to be passed into
    other processes.
    """

    def __reduce__(self):
        return MemoryGroup, (self.file,)

    def new_mutex(self) -> SharedLock:
        return SharedLock(self)

    def __init__(self, name: Union[SHMPage, str]):
        file = None
        if isinstance(name, str):
            self.name = name
        elif isinstance(name, SHMPage):
            file = name
            self.name = name = file.name
        if file is None:
            try:
                # original allocator gets to make the data structures
                self.file = SHMPage(self.name, 'x+')
            except FileExistsError:
                self.file = SHMPage(self.name, "r+")
                self._load_malloc_map()
            else:
                self._init_malloc_map()
        else:
            self.file = file
            self._load_malloc_map()
        self.new = ffi.new_allocator(
            alloc=ffi.callback('void*(size_t)')(self._malloc), free=ffi.callback('void(void*)')(self._free)
        )

    def _init_malloc_map(self):
        header_size = ffi.sizeof('shmmmap_header_t')
        # if we use a bit to mark a byte as "used" and zero as free,
        # we can just scan for a good enough size linearly
        bytes_needed = self.file.size // 8
        header = ffi.cast('shmmmap_header_t*', self.c_buf[0:header_size])
        assert ffi.string(header.header) != b"shmutils_mmap"
        header.header = b'shmutils_mmap\x00'
        header.size = self.file.size
        header.owner_pid = os.getpid()
        del header

        with memoryview(self.file._mmap) as m:
            with m[header_size:header_size + bytes_needed] as view:
                view[0:bytes_needed] = b'\x00' * bytes_needed
        self.seek(header_size + bytes_needed)

    def _load_malloc_map(self):
        header_size = ffi.sizeof('shmmmap_header_t')
        header = ffi.cast('shmmmap_header_t*', self.c_buf[0:header_size])
        assert ffi.string(header.header) == b"shmutils_mmap"
        bytes_needed = self.file.size // 8
        self.file.seek(bytes_needed + header_size)

    @property
    def ptrs(self):
        return self.file._allocated_ptrs

    @property
    def c_buf(self):
        return self.file._cbuf

    def _malloc(self, size: int):
        header_size = ffi.sizeof('shmmmap_header_t')
        bytes_needed = self.file.size // 8

        with memoryview(self.file._mmap) as buf, buf[header_size:header_size+bytes_needed] as memory_used:
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
                        memory_used[span_start:span_start+size] = b'\x01' * size
                        real_start = header_size + bytes_needed + span_start
                        real_end = real_start + size
                        ptr = ffi.addressof(self.c_buf[real_start: real_end])
                        self.file._allocated_ptrs[ptr] = ((span_start, span_start+size), (real_start, real_end))
                        return ptr
                elif state == 1:
                    # used
                    if span_start is not None:
                        span_start = None
                        span_length = 0
                else:
                    raise ValueError(f'wtf, got {state}')
        print('OOM!')
        return None

    def _free(self, ptr):
        if not self.file:
            # print(f'{ptr} was freed by gc after closed')
            return
        header_size = ffi.sizeof('shmmmap_header_t')
        bytes_needed = self.file.size // 8

        try:
            span, (index, endex) = self.file._allocated_ptrs.pop(ptr)
        except KeyError:
            print(f'ptr {ptr} not in {self.file._allocated_ptrs}')
        else:
            print(f'freed {index}:{endex}')
            self.c_buf[index:endex] = b'\xee' * (endex-index)
            with memoryview(self.file._mmap) as buf, buf[header_size:header_size+bytes_needed] as use_map:
                span_start, span_end = span
                use_map[span_start:span_end] = b'\x00' * (span_end - span_start)

    def __getitem__(self, *args, **kwargs):
        return self.file.__getitem__(*args, **kwargs)

    def __setitem__(self, *args, **kwargs):
        return self.file.__setitem__(*args, **kwargs)

    def __getattr__(self, key):
        if key in ('read', 'write', 'tell', 'seek',):
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


def reattach_cffi(c_name, memory: MemoryGroup, index, endex):
    return cffiwrapper(ffi.cast(c_name, memory.c_buf[index:endex]), memory)


class cffiwrapper:
    """
    cdatas are not pickleable, except in this case we can restore it
    with a terrible cast because we've made the memory pool pickleable/unpickleable on
    the same system.
    """

    def __getitem__(self,  *args, **kwargs):
        return self.cdata.__getitem__(*args, **kwargs)

    def __setitem__(self,  *args, **kwargs):
        self.cdata.__setitem__(*args, **kwargs)

    def __init__(self, cdata, memory: MemoryGroup):
        self.cdata = cdata
        self.memory = memory

    def __reduce__(self):
        _, (index, endex) = self.memory.ptrs[self.cdata]
        return reattach_cffi, (ffi.typeof(self.cdata).cname, self.memory, index, endex)
