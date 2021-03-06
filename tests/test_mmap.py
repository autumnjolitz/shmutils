import pytest
import multiprocessing
import platform
from contextlib import suppress
from concurrent.futures import wait, ProcessPoolExecutor

from shmutils import MappedMemory, MapFlags
from shmutils.mmap import munmap, round_to_page_size
from mmap import PAGESIZE
from shmutils.utils import cffiwrapper
from shmutils._shmutils import ffi
from shmutils.shm import shm_open, shm_unlink


def _set_data_to(value: cffiwrapper, to: int):
    was = value[0]
    for i in range(was, to):
        value[0] = i
    value[0] = to
    return was


def test_mmap():
    with MappedMemory(None, PAGESIZE, flags=MapFlags.PRIVATE | MapFlags.ANONYMOUS, fd=-1) as m:
        address = m.abs_address_at[0]
        assert address == m._raw.as_absolute_offset()
        assert m.relative_address_at[m.abs_address_at[0]] == 0
        with MappedMemory(
            m.abs_address_at[0], PAGESIZE, flags=MapFlags.PRIVATE | MapFlags.ANONYMOUS, fd=-1
        ) as m2:
            assert m is m2


def test_mmap_fork():
    with suppress(FileNotFoundError):
        shm_unlink("test-mmap-fork")

    with shm_open("test-mmap-fork", "x+") as fd:
        fd.truncate(PAGESIZE)
        with MappedMemory(None, PAGESIZE, flags=MapFlags.SHARED, fd=fd) as m:
            with ProcessPoolExecutor(mp_context=multiprocessing.get_context("fork")) as exe:
                value = m.new("int64_t*", 1923)
                assert value[0] == 1923
                future = exe.submit(_set_data_to, cffiwrapper(value, m), 8900)
                wait([future])
                assert future.done() and not future.exception()
                assert (future.result(), value[0]) == (1923, 8900)
    with pytest.raises(FileNotFoundError):
        shm_unlink("test-mmap-fork")


@pytest.mark.skipif(platform.system() != "Darwin", reason="requires osx")
def test_mmap_spawn():
    """
    ARJ: ASLR lives to make our lives hard.

    However, if we push the parents address space to be big enough, we should
    be able to ensure our child spawn (fork+execve) process's min mmap will be well before
    our max memory location.
    """
    with suppress(FileNotFoundError):
        shm_unlink("test-mmap-spawn")

    with shm_open("test-mmap-spawn", "x+") as fd:
        shared_size = round_to_page_size(1024 * 1024 * 1024)
        fd.truncate(shared_size)
        # Allocate a dummy 512 MiB blockrange
        unused_space = MappedMemory(None, 512 * 1024 * 1024)
        # write to the pages to ensure we're not being fooled
        unused_space.at[len(unused_space) - PAGESIZE : len(unused_space) - PAGESIZE + 4] = b"sink"

        # Calculate the last page in the unused space range
        start_address: int = unused_space.address + len(unused_space) - PAGESIZE
        # detach the unused space guts so we can free all bu the last page
        raw_mmap = unused_space.detach()
        # free all BUT the last page
        munmap(raw_mmap.address, raw_mmap.size - PAGESIZE)
        del unused_space

        # Prove our start address is the last page of the mostly freed range
        # (our last page is still mapped.)
        assert (
            int(ffi.cast("uintptr_t", raw_mmap.address)) + raw_mmap.size - PAGESIZE == start_address
        )

        with MappedMemory(
            start_address, shared_size, flags=MapFlags.SHARED | MapFlags.FIXED, fd=fd
        ) as m:
            with ProcessPoolExecutor(1, mp_context=multiprocessing.get_context("spawn")) as exe:
                value = m.new("int64_t*", 1923)
                assert value[0] == 1923
                future = exe.submit(_set_data_to, cffiwrapper(value, m), 8900)
                wait([future])
                assert future.done() and not future.exception()
                assert (future.result(), value[0]) == (1923, 8900)
    with pytest.raises(FileNotFoundError):
        shm_unlink("test-mmap-spawn")


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
