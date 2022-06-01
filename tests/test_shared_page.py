import resource
from contextlib import suppress

import pytest

from shmutils import shm_open, shm_unlink, PosixSharedMemory

page_size = resource.getpagesize()


@pytest.mark.parametrize(
    "size,expected_size",
    [(1, page_size), (page_size + 1, 2 * page_size), ((2 * page_size - 1), 2 * page_size)],
)
def test_malloc_sizes(size, expected_size):
    name = "test_malloc_sizes"
    with suppress(FileNotFoundError):
        shm_unlink(name)
    with shm_open(name, "w+", size=size) as m:
        assert isinstance(m, PosixSharedMemory)
        assert m.size == expected_size
        assert m.tell() == 0
