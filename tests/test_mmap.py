from shmutils import MappedMemory
from _shmutils import ffi


def test_mmap_malloc():
    with MappedMemory(None, 1024) as m:
        ptr = m.malloc(10)
        ffi_malloc = ffi.callback("void*(size_t)")(m.malloc)
        m.free(ptr)
        ptr_m = ffi_malloc(10)
        assert ptr_m == ptr


def test_mmap_malloc_free():
    with MappedMemory(None, 800) as m:
        ptr = m.malloc(10)
        assert ptr != ffi.NULL
        assert (len(m._freelist), len(m._used)) == (0, 1)
        m.free(ptr)
        assert (len(m._freelist), len(m._used)) == (0, 0)
        ptr2 = m.malloc(10)
        assert ptr == ptr2
        assert (len(m._freelist), len(m._used)) == (0, 1)
        m.free(ptr2)
        assert (len(m._freelist), len(m._used)) == (0, 0)
        assert m.tell() == 0
        del ptr2

        # None allocated
        ptr_1 = m.malloc(1)
        assert ptr_1 == ptr
        ptr_2 = m.malloc(13)
        assert (len(m._freelist), len(m._used)) == (0, 2)
        assert ptr_2 > ptr_1
        m.free(ptr_1)
        assert (len(m._freelist), len(m._used)) == (1, 1)
        ptr_3 = m.malloc(40)
        assert ptr_3 > ptr_2
        assert (len(m._freelist), len(m._used)) == (1, 2)
        m.free(ptr_2)
        assert (len(m._freelist), len(m._used)) == (1, 1)
        m.free(ptr_3)
        assert (len(m._freelist), len(m._used)) == (0, 0), m._freelist
        assert m.tell() == 0
