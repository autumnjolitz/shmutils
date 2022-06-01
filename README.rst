shmutils - Shared Memory structures in Python
=================================================

|Build Status|

I've wondered why isn't it easier to have multiple processes be able to have a shared memory space.

I've also wondered about how to pass shared memory definitions between processes.


.. |Build Status| image:: https://github.com/autumnjolitz/shmutils/actions/workflows/python-app.yml/badge.svg
    :target: https://github.com/autumnjolitz/shmutils/actions/workflows/python-app.yml

Examples
-----------


.. code-block:: python

    import multiprocessing
    from contextlib import suppress
    from concurrent.futures import ProcessPoolExecutor, as_completed
    from shmutils import MappedMemory, MapFlags, MapProtections
    from shmutils.utils import cffiwrapper
    from shmutils.lock import Lock
    from shmutils.shm import shm_open, shm_unlink


    def _increment_to(m, lock: Lock, value: cffiwrapper, limit: int):
        """
        Returns the number of times we increments the number
        """
        count = value[0]
        num_incr = 0
        while count < limit:
            with lock:
                count = value[0]
                if count >= limit:
                    break
                num_incr += 1
                value[0] = count + 1
        return num_incr


    if __name__ == "__main__":
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
                    result1 = exe.submit(_increment_to, m, lock, cffiwrapper(counter, m), 2_0000)
                    result2 = exe.submit(_increment_to, m, lock, cffiwrapper(counter, m), 2_0000)
                tuple(as_completed((result1, result2)))
                r1, r2 = result1.result(), result2.result()
            assert (result1.exception(), result2.exception()) == (None, None)
            assert counter[0] == 2_0000
            assert r1 + r2 == 2_0000




Limitations
------------------

- Toy allocator, does not synchronize writes between processes (only parent is expected to have allocated ahead of time).

spawn vs fork
*******************


Use "fork" multiprocessing method instead.

The "spawn" multiprocessing method is subject to ASLR and **sometimes** the kernel locates a child process starting much higher than our process. This has the effect of breaking the requirement for absolute pointers working.

However, it is observed that if a parent process manages to get a high enough memory page, the probability of the child process being able to ``mmap(2)`` the same address increases significantly.

.. code-block:: python

    import multiprocessing
    from contextlib import suppress
    from concurrent.futures import ProcessPoolExecutor, wait
    from mmap import PAGESIZE

    from shmutils import MappedMemory, MapFlags
    from shmutils.mmap import munmap, round_to_page_size
    from shmutils.shm import shm_open, ffi, shm_unlink
    from shmutils.utils import cffiwrapper

    # cffiwrapper - use to pickle/unpickle cffi objects between processes


    def _set_data_to(value: cffiwrapper, to: int) -> int:
        was = value[0]
        for i in range(was, to):
            value[0] = i
        value[0] = to
        return was


    if __name__ == "__main__":
        with suppress(FileNotFoundError):
            shm_unlink("test-mmap-spawn")
        with shm_open("test-mmap-spawn", "x+") as fd:
            shared_size = round_to_page_size(1024 * 1024 * 1024)
            fd.truncate(shared_size)
            # Allocate a dummy 512 MiB blockrange
            unused_space = MappedMemory(None, 512 * 1024 * 1024)
            # write to the pages to ensure we're not being fooled
            unused_space[len(unused_space) - PAGESIZE : len(unused_space) - PAGESIZE + 4] = b"sink"

            # Calculate the last page in the unused space range
            start_address: int = unused_space.abs_address_at[len(unused_space) - PAGESIZE]
            # detach the unused space guts so we can free all bu the last page
            raw_address, size = unused_space.detach()
            # free all BUT the last page
            munmap(raw_address, size - PAGESIZE)
            del unused_space

            # Prove our start address is the last page of the mostly freed range
            # (our last page is still mapped.)
            assert int(ffi.cast("uintptr_t", raw_address)) + size - PAGESIZE == start_address

            with MappedMemory(
                start_address, shared_size, flags=MapFlags.SHARED | MapFlags.FIXED, fd=fd
            ) as m:
                with ProcessPoolExecutor(1, mp_context=multiprocessing.get_context("spawn")) as exe:
                    value = m.new("int64_t*", 1923)
                    assert value[0] == 1923
                    # The child process will now be able to mess with this counter
                    future = exe.submit(_set_data_to, cffiwrapper(value, m), 8900)
                    wait([future])
                    # And we can see the results both on the value in memory and from the
                    # return
                    assert future.done() and not future.exception()
                    assert (future.result(), value[0]) == (1923, 8900)















