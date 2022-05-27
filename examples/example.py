import os
import time
from typing import Tuple
from shmutils import MemoryGroup, Lock, remove
from shmutils.utils import cffiwrapper


def read_and_count_to(
    m: MemoryGroup, mutex: Lock, counter: cffiwrapper, limit: int
) -> Tuple[int, float]:
    t_s = time.time()
    with m:
        while True:
            with mutex:
                value = counter[0]
                if value == limit:
                    break
                counter[0] = value + 1
    return value, time.time() - t_s


if __name__ == "__main__":
    import argparse
    from concurrent.futures import ProcessPoolExecutor, as_completed

    parser = argparse.ArgumentParser()
    parser.add_argument("-c", "--cores", default=os.cpu_count(), type=int)
    parser.add_argument("limit", default=2_500_000, nargs="?", type=int)
    args = parser.parse_args()
    limit = args.limit
    cores = args.cores
    assert limit > 0
    try:
        remove("hello")
    except FileNotFoundError:
        pass
    futures = []

    with MemoryGroup("hello", 4 * 1024 * 1024) as shared_memory:
        lock = Lock(shared_memory)
        counter = cffiwrapper(shared_memory.new("int32_t*"), shared_memory)
        print("starting workers")
        with ProcessPoolExecutor(cores) as exe:
            with lock:
                for _ in range(cores):
                    futures.append(
                        exe.submit(read_and_count_to, shared_memory, lock, counter, limit)
                    )
            # Let them go
            t_s = time.time()
            process_results = [x.result() for x in as_completed(futures)]
            t_e = time.time() - t_s
        final_value = counter[0]
    print(f"Final value is {final_value}")
    print(f"Process results {process_results}")
    print(
        f"Took {t_e:.2f}s for {cores} contending processes to count to {limit:,d} @ {limit / t_e:,.2f} sets/second"
    )
