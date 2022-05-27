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

    import os
    import time
    from typing import Tuple
    from shmutils import MemoryGroup, Lock, remove
    from shmutils.utils import cffiwrapper
    from concurrent.futures import ProcessPoolExecutor, as_completed


    def read_and_count_to(
        mutex: Lock, counter: cffiwrapper, limit: int
    ) -> Tuple[int, float]:
        t_s = time.time()
        while True:
            with mutex:
                value = counter[0]
                if value == limit:
                    break
                counter[0] = value + 1
        return value, time.time() - t_s


    if __name__ == "__main__":
        try:
            remove("my-shared-heap")
        except FileNotFoundError:
            pass
        futures = []
        cores = os.cpu_count()
        limit = 250_000

        with MemoryGroup("my-shared-heap", 4 * 1024 * 1024) as shared_memory:
            lock = Lock(shared_memory)
            # wrap a CFFI integer so we can restore it across the process boundary
            counter = cffiwrapper(shared_memory.new("int32_t*"), shared_memory)
            with ProcessPoolExecutor(cores) as exe:
                with lock:
                    for _ in range(cores):
                        futures.append(
                            exe.submit(read_and_count_to, lock, counter, limit)
                        )
                # Let them go
                t_s = time.time()
                process_results = [x.result() for x in as_completed(futures)]
                t_e = time.time() - t_s
            final_value = counter[0]
        print(
            f"Took {t_e:.2f}s for {cores} contending processes to count to {limit:,d} @ {limit / t_e:,.2f} sets/second"
        )

