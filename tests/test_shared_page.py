import resource
from contextlib import suppress

import pytest

from shmutils import shm_open, shm_unlink, PosixSharedMemory
from shmutils.utils import RelativeView


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

        with m.relative_view(120, 512) as view:
            assert isinstance(view, RelativeView)
            view[0:30] = b"hello, this is a relative view"
            assert view[29:30] == b"w"
            with view.relative_view(29, 5) as view2:
                assert (view2[0:1]) == b"w"
                view2[0:5] = b"W. F1"
                assert view2[0:5] == b"W. F1"
                assert view[29:34] == b"W. F1"
            assert view[0:34] == b"hello, this is a relative vieW. F1"
        assert m.tell() == 0
