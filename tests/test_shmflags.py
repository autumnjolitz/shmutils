from shmutils.shm import Flags


def test_mode_to_flags():
    assert Flags.from_mode("r") == Flags.READ_ONLY
    assert Flags.from_mode("r+") == Flags.READ_WRITE
    assert Flags.from_mode("w") == Flags.CREATE | Flags.READ_WRITE | Flags.TRUNCATE_ON_OPEN
    assert Flags.from_mode("w+") == Flags.CREATE | Flags.READ_WRITE
    assert Flags.from_mode("x") == Flags.EXCLUSIVE_CREATION | Flags.CREATE | Flags.READ_WRITE
    assert Flags.from_mode("x+") == Flags.EXCLUSIVE_CREATION | Flags.CREATE | Flags.READ_WRITE

    assert Flags.from_mode("r").to_mode() == "r"
    assert Flags.from_mode("r+").to_mode() == "r+"
    assert Flags.from_mode("w").to_mode() == "w"
    assert Flags.from_mode("w+").to_mode() == "w+"
    assert Flags.from_mode("x").to_mode() == "x+"
    assert Flags.from_mode("x+").to_mode() == "x+"
