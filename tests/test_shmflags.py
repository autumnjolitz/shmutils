from shmutils.page import SHMFlags


def test_mode_to_flags():
    assert SHMFlags.from_mode("r") == SHMFlags.READ_ONLY
    assert SHMFlags.from_mode("r+") == SHMFlags.READ_WRITE
    assert (
        SHMFlags.from_mode("w") == SHMFlags.CREATE | SHMFlags.READ_WRITE | SHMFlags.TRUNCATE_ON_OPEN
    )
    assert SHMFlags.from_mode("w+") == SHMFlags.CREATE | SHMFlags.READ_WRITE
    assert (
        SHMFlags.from_mode("x")
        == SHMFlags.EXCLUSIVE_CREATION | SHMFlags.CREATE | SHMFlags.READ_WRITE
    )
    assert (
        SHMFlags.from_mode("x+")
        == SHMFlags.EXCLUSIVE_CREATION | SHMFlags.CREATE | SHMFlags.READ_WRITE
    )

    assert SHMFlags.from_mode("r").to_mode() == "r"
    assert SHMFlags.from_mode("r+").to_mode() == "r+"
    assert SHMFlags.from_mode("w").to_mode() == "w"
    assert SHMFlags.from_mode("w+").to_mode() == "w+"
    assert SHMFlags.from_mode("x").to_mode() == "x+"
    assert SHMFlags.from_mode("x+").to_mode() == "x+"
