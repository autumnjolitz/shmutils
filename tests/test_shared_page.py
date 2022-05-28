import resource
from contextlib import suppress

import pytest

from shmutils import shm_malloc, free, remove

page_size = resource.getpagesize()


@pytest.mark.parametrize(
    "size,expected_size",
    [(1, page_size), (page_size + 1, 2 * page_size), ((2 * page_size - 1), 2 * page_size)],
)
def test_malloc(size, expected_size):
    name = test_malloc.__name__
    with suppress(FileNotFoundError):
        remove(name)
    with shm_malloc(name, "w+", size=size) as m:
        assert m.size == expected_size
