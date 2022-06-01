import errno
from typing import Optional, Tuple
from enum import Flag
from .errors import libc_error
from . import errors
from .mmap import MappedMemory
from _shmutils import lib, ffi


class LockType(Flag):
    NORMAL = lib.PTHREAD_MUTEX_NORMAL
    ERRORCHECK = lib.PTHREAD_MUTEX_ERRORCHECK
    RECURSIVE = lib.PTHREAD_MUTEX_RECURSIVE
    DEFAULT = lib.PTHREAD_MUTEX_DEFAULT


mutex_attr_t_size = ffi.sizeof("pthread_mutexattr_t")
mutex_t_size = ffi.sizeof("pthread_mutex_t")
mutex_size = mutex_attr_t_size + mutex_t_size


class RelativeHandleMeta(type):
    def __len__(self):
        return self._ctype_size


class RelativeHandle(metaclass=RelativeHandleMeta):
    __slots__ = ("_heap",)

    def new(self, cdecl, init=None):
        return self._heap.new(cdecl, init)

    def __init__(self, heap: MappedMemory):
        self._heap = heap

    @classmethod
    def from_mmap(cls, buffer: MappedMemory, *args, **kwargs):
        index = buffer.tell()
        buffer.write("\xee" * len(cls))
        view = buffer[index : index + len(cls)]
        result = cls(view, *args, **kwargs)
        buffer.register_range(result, index, len(cls))
        return result


DEFAULT_LOCK_TYPE = LockType.ERRORCHECK


class RelativeLock(RelativeHandle):
    _ctype_size = ffi.sizeof("pthread_mutexattr_t") + ffi.sizeof("pthread_mutex_t")
    __slots__ = (
        "buffer",
        "closed",
        "lock_type",
        "_lock_level",
        "mutex_attr",
        "mutex_t",
        "_should_free",
    )

    def __reduce__(self):
        offset_mutex_attr_t = ffi.cast("void*", self.mutex_attr) - self._heap._raw.address
        offset_mutex_t = ffi.cast("void *", self.mutex_t) - self._heap._raw.address

        assert self._heap.at[
            offset_mutex_t : offset_mutex_t + ffi.sizeof("pthread_mutex_t")
        ] == ffi.buffer(self.mutex_t)
        assert self._heap.at[
            offset_mutex_attr_t : offset_mutex_attr_t + ffi.sizeof("pthread_mutexattr_t")
        ] == ffi.buffer(self.mutex_attr)

        return type(self), (
            self._heap,
            self.lock_type,
            (int(offset_mutex_attr_t), int(offset_mutex_t)),
        )

    def __init__(
        self,
        heap: MappedMemory,
        lock_type: Optional[LockType] = None,
        buffers: Optional[Tuple[int, int]] = None,
    ):
        super().__init__(heap)
        if lock_type is None:
            lock_type = DEFAULT_LOCK_TYPE
        self.lock_type = lock_type
        self.closed = False
        self._should_free = True
        self._lock_level = 0
        if buffers:
            self._should_free = False
            self.mutex_attr, self.mutex_t = ffi.cast(
                "pthread_mutexattr_t*",
                self._heap._raw.address + buffers[0],
            ), ffi.cast(
                "pthread_mutex_t*",
                self._heap._raw.address + buffers[1],
            )
        else:
            self.mutex_attr = self.new("pthread_mutexattr_t*")
            self.mutex_t = self.new("pthread_mutex_t*")
            self._init_cdata()

    def _init_cdata(self):
        attr = self.mutex_attr
        lock = self.mutex_t
        if lib.pthread_mutexattr_init(attr) != 0:
            raise libc_error()
        if lib.pthread_mutexattr_setpshared(attr, lib.PTHREAD_PROCESS_SHARED) != 0:
            template = None
            if ffi.errno == errno.EINVAL:
                template = errors.INVALID_LOCK_ATTR
            raise libc_error(template)
        if self.lock_type is LockType.RECURSIVE:
            if lib.pthread_mutexattr_settype(attr, self.lock_type.value) != 0:
                template = None
                if ffi.errno == errno.EINVAL:
                    template = errors.INVALID_LOCK_ATTR
                raise libc_error(template)
        if lib.pthread_mutex_init(lock, attr) != 0:
            raise libc_error()

    def close(self):
        if self.closed:
            return
        if self.mutex_t is not None:
            if self._should_free:
                result = lib.pthread_mutex_destroy(self.mutex_t)
                if result:
                    raise errors.libc_error(error_code=result)
            self.mutex_t = None
        if self.mutex_attr is not None:
            if self._should_free:
                result = lib.pthread_mutexattr_destroy(self.mutex_attr)
                if result:
                    raise errors.libc_error(error_code=result)
            self.mutex_attr = None
        self.closed = True

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.release()

    def acquire(self, blocking=True, timeout: int = -1):
        if timeout > -1:
            raise NotImplementedError
        if self._lock_level > 0 and self.lock_type is not LockType.RECURSIVE:
            raise RuntimeError("lock already acquired!")
        if blocking:
            result = lib.pthread_mutex_lock(self.mutex_t)
            if result:
                raise errors.libc_error(
                    error_code=result,
                    codes={
                        errno.EDEADLK: (
                            IOError,
                            "A deadlock would occur if the thread blocked waiting for mutex.",
                        ),
                        errno.EINVAL: (ValueError, "The value specified by mutex is invalid"),
                    },
                )
        else:
            result = lib.pthread_mutex_trylock(self.mutex_t)
            if result:
                raise errors.libc_error(
                    error_code=result,
                    codes={
                        errno.EINVAL: (ValueError, "The value specified by mutex is invalid."),
                        errno.EBUSY: (OSError, "Mutex is already locked"),
                    },
                )
        self._lock_level += 1

    def release(self):
        assert self._lock_level >= 0
        if not self._lock_level:
            raise RuntimeError("unlocked")
        result = lib.pthread_mutex_unlock(self.mutex_t)
        if result:
            raise errors.libc_error(
                error_code=result,
                codes={
                    errno.EPERM: (
                        PermissionError,
                        "The current thread does not hold a lock on mutex",
                    ),
                    errno.EINVAL: (ValueError, "The value specified by mutex is invalid"),
                },
            )
        self._lock_level -= 1


class Lock(RelativeLock):
    def __reduce__(self):
        offset_mutex_attr_t = ffi.cast("void*", self.mutex_attr) - self._heap._raw.address
        offset_mutex_t = ffi.cast("void *", self.mutex_t) - self._heap._raw.address

        assert self._heap.at[
            offset_mutex_t : offset_mutex_t + ffi.sizeof("pthread_mutex_t")
        ] == ffi.buffer(self.mutex_t)
        assert self._heap.at[
            offset_mutex_attr_t : offset_mutex_attr_t + ffi.sizeof("pthread_mutexattr_t")
        ] == ffi.buffer(self.mutex_attr)

        return type(self), (self._heap, (int(offset_mutex_attr_t), int(offset_mutex_t)))

    def __init__(self, heap: MappedMemory, buffers=None):
        super().__init__(heap, lock_type=LockType.DEFAULT, buffers=buffers)


class RLock(RelativeLock):
    def __reduce__(self):
        offset_mutex_attr_t = ffi.cast("void*", self.mutex_attr) - self._heap._raw.address
        offset_mutex_t = ffi.cast("void *", self.mutex_t) - self._heap._raw.address

        assert self._heap.at[
            offset_mutex_t : offset_mutex_t + ffi.sizeof("pthread_mutex_t")
        ] == ffi.buffer(self.mutex_t)
        assert self._heap.at[
            offset_mutex_attr_t : offset_mutex_attr_t + ffi.sizeof("pthread_mutexattr_t")
        ] == ffi.buffer(self.mutex_attr)

        return type(self), (self._heap, (int(offset_mutex_attr_t), int(offset_mutex_t)))

    def __init__(self, heap: MappedMemory, buffers=None):
        super().__init__(heap, lock_type=LockType.RECURSIVE, buffers=buffers)
