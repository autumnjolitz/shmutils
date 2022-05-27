import pytest

from shmutils.page import RelativeView


def test_view():
    buffer = bytearray(2048)
    with RelativeView(buffer, 1024, 1024) as view:
        with RelativeView(view, 0, 512) as view1, RelativeView(view, 512, 512) as view2:
            view1[0 : len("foobar")] = b"foobar"
            view2[0 : len("bazbaz")] = b"bazbaz"
            with RelativeView(view2, 16, 32) as v:
                v[0:16] = b"\x01" * 16
                with RelativeView(v, 32, 64) as v2:
                    assert len(v2) == 0

    assert buffer[1024 : 1024 + len("foobar")] == b"foobar"
    assert buffer[1024 + 512 : 1024 + 512 + len("foobar")] == b"bazbaz"
    assert buffer[1024 + 512 + 16 : 1024 + 512 + 32] == b"\x01" * 16
    buffer.clear()
    buffer.extend(0 for _ in range(2048))

    with pytest.raises(IndexError) as e:
        with RelativeView(buffer, 1024, 1024) as view:
            view[1024:] = b"abc"
    assert str(e.value).startswith("Attempted to")

    with RelativeView(buffer, 2048, 1024) as view:
        assert len(view) == 0
        with pytest.raises(IndexError):
            view[0] = b"x"
