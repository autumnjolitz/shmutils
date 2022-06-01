from typing import NewType

from _shmutils import ffi

ssize_t = NewType("ssize_t", type(ffi.cast("ssize_t", -1)))
void_ptr = NewType("void*", type(ffi.cast("void*", -1)))
buffer_t = NewType("buffer_t", ffi.buffer)
