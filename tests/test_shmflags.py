from shmutils import SharedPageFlags


def test_mode_to_flags():
    assert SharedPageFlags.from_mode("r") == SharedPageFlags.READ_ONLY
    assert SharedPageFlags.from_mode("r+") == SharedPageFlags.READ_WRITE
    assert (
        SharedPageFlags.from_mode("w")
        == SharedPageFlags.CREATE | SharedPageFlags.READ_WRITE | SharedPageFlags.TRUNCATE_ON_OPEN
    )
    assert SharedPageFlags.from_mode("w+") == SharedPageFlags.CREATE | SharedPageFlags.READ_WRITE
    assert (
        SharedPageFlags.from_mode("x")
        == SharedPageFlags.EXCLUSIVE_CREATION | SharedPageFlags.CREATE | SharedPageFlags.READ_WRITE
    )
    assert (
        SharedPageFlags.from_mode("x+")
        == SharedPageFlags.EXCLUSIVE_CREATION | SharedPageFlags.CREATE | SharedPageFlags.READ_WRITE
    )

    assert SharedPageFlags.from_mode("r").to_mode() == "r"
    assert SharedPageFlags.from_mode("r+").to_mode() == "r+"
    assert SharedPageFlags.from_mode("w").to_mode() == "w"
    assert SharedPageFlags.from_mode("w+").to_mode() == "w+"
    assert SharedPageFlags.from_mode("x").to_mode() == "x+"
    assert SharedPageFlags.from_mode("x+").to_mode() == "x+"
