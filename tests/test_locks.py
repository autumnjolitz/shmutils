import multiprocessing
from contextlib import suppress
from concurrent.futures import ProcessPoolExecutor, as_completed
from shmutils import MappedMemory, MapFlags, MapProtections
from shmutils.utils import cffiwrapper
from shmutils.lock import Lock
from shmutils.shm import shm_open, shm_unlink


def _increment_to(lock: Lock, value: cffiwrapper, limit: int):
    count = value[0]
    num_incr = 0
    while count < limit:
        with lock:
            count = value[0]
            if count >= limit:
                break
            num_incr += 1
            value[0] = count + 1
    return num_incr, id(lock._heap)


def test_simple_shared_lock():
    with suppress(FileNotFoundError):
        shm_unlink("test-lock")

    fd = shm_open("test-lock", "w+")
    size = 4096 * 100
    fd.truncate(size)
    assert fd.size() == size
    with MappedMemory(0, size, MapProtections.READ_WRITE, MapFlags.SHARED, fd) as m:
        with ProcessPoolExecutor(mp_context=multiprocessing.get_context("fork")) as exe:
            lock = Lock(m)
            counter = m.new("size_t *", 0)
            with lock:
                result1 = exe.submit(_increment_to, lock, cffiwrapper(counter, m), 2_0000)
                result2 = exe.submit(_increment_to, lock, cffiwrapper(counter, m), 2_0000)
            tuple(as_completed((result1, result2)))
            (r1, mapping_id_from1), (r2, mapping_id_from2) = result1.result(), result2.result()
        assert (result1.exception(), result2.exception()) == (None, None)
        assert (counter[0], r1 + r2) == (2_0000, 2_0000)
        # prove that all processes accessed the same id through fork
        # (we didn't modify anything in the heap)
        assert mapping_id_from1 == mapping_id_from2 == id(m)
