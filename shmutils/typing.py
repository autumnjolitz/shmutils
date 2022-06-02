from typing import NewType

from ._shmutils import ffi

ssize_t = NewType("ssize_t", ffi.CData)
void_ptr = NewType("void*", ffi.CData)

MAP_FAILED = ffi.cast("void*", -1)


buffer_t = NewType("buffer_t", ffi.buffer)
AddressRange = NewType("AddessRange", range)
