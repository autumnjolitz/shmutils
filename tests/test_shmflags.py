from shmutils import SharedRegionFlags


def test_mode_to_flags():
    assert SharedRegionFlags.from_mode("r") == SharedRegionFlags.READ_ONLY
    assert SharedRegionFlags.from_mode("r+") == SharedRegionFlags.READ_WRITE
    assert (
        SharedRegionFlags.from_mode("w")
        == SharedRegionFlags.CREATE
        | SharedRegionFlags.READ_WRITE
        | SharedRegionFlags.TRUNCATE_ON_OPEN
    )
    assert (
        SharedRegionFlags.from_mode("w+") == SharedRegionFlags.CREATE | SharedRegionFlags.READ_WRITE
    )
    assert (
        SharedRegionFlags.from_mode("x")
        == SharedRegionFlags.EXCLUSIVE_CREATION
        | SharedRegionFlags.CREATE
        | SharedRegionFlags.READ_WRITE
    )
    assert (
        SharedRegionFlags.from_mode("x+")
        == SharedRegionFlags.EXCLUSIVE_CREATION
        | SharedRegionFlags.CREATE
        | SharedRegionFlags.READ_WRITE
    )

    assert SharedRegionFlags.from_mode("r").to_mode() == "r"
    assert SharedRegionFlags.from_mode("r+").to_mode() == "r+"
    assert SharedRegionFlags.from_mode("w").to_mode() == "w"
    assert SharedRegionFlags.from_mode("w+").to_mode() == "w+"
    assert SharedRegionFlags.from_mode("x").to_mode() == "x+"
    assert SharedRegionFlags.from_mode("x+").to_mode() == "x+"
