from __future__ import annotations

from ._shmutils import ffi


def reattach_cffi(c_name, memory, index, endex):
    return cffiwrapper(ffi.cast(c_name, memory.c_buf[index:endex]), memory)


class cffiwrapper:
    """
    cdatas are not pickleable, except in this case we can restore it
    with a terrible cast because we've made the memory pool pickleable/unpickleable on
    the same system.
    """

    def __getitem__(self, *args, **kwargs):
        return self.cdata.__getitem__(*args, **kwargs)

    def __setitem__(self, *args, **kwargs):
        self.cdata.__setitem__(*args, **kwargs)

    def __init__(self, cdata, memory):
        self.cdata = cdata
        self.memory = memory

    def __reduce__(self):
        _, (index, endex) = self.memory.ptrs[self.cdata]
        return reattach_cffi, (ffi.typeof(self.cdata).cname, self.memory, index, endex)
