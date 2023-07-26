import multiprocessing
import concurrent.futures
import functools
import asyncio
from .mmap import mmap, munmap, Flags, Protections, rawmmap
from contextlib import contextmanager
from .types import get_context, AbstractAsyncioProcessMixin, ImmutableSpan

from .process_main import on_worker_bootstrap, on_worker_exit


# ARJ: Here
class Server:
    def __init__(self, process: AbstractAsyncioProcessMixin, loop: asyncio.AbstractEventLoop):
        self._fd_lookup = {-1: -1}
        self._mappings = {}

    async def run_forever(self):
        ...

    async def handle(self, op_name, *args):
        loop = asyncio.get_running_loop()
        if op_name == "incoming_fd":
            (their_fd,) = args
            fd = await loop.run_in_executor(
                multiprocessing.reduction.recv_handle(self.process.channel.read)
            )
            self._fd_lookup[their_fd] = fd
        elif op_name == "show_largest_ranges":
            with mmap(-1, 1 * 1024 * 1024 * 1024, flags=Flags.NORESERVE) as map:
                span = map.span
            await self.process.send(span)

        elif op_name == "try_reserve_range":
            (requested_span,) = args
            mapping = mmap(
                requested_span.start, requested_span.size, Protections.NONE, Flags.NORESERVE
            )
            self._reserved_ranges[requested_span] = mapping
            await self.process.send(("range_reserved", mapping.span))

        elif op_name == "request_mmap":
            reserved_span, address, size, protection, flags, fd, offset = args
            assert address in reserved_span
            try:
                mapping = map_reserved_range(
                    reserved_range, address, size, protection, flags, fd, offset
                )
            except Exception:
                await self.process.channel.send(("request_mmap_failed", e))
            else:
                self._mappings[mapping.span] = mapping
                await self.process.channel.send(("mmap_created", mapping.span))


class AsyncProcessPoolExecutor(concurrent.futures.ProcessPoolExecutor):
    def __init__(self, *args, mp_context=None, initializer=None, initargs=(), **kwargs):
        mp_context = get_context(mp_context)
        process_cls = mp_context.Process
        if hasattr(process_cls, "_Process"):
            process_cls = process_cls._Process

        self._mappings: dict[ImmutableSpan, rawmmap] = {}

        class WithServer(AbstractAsyncioProcessMixin):
            async def on_event_loop_started(self, loop):
                self._server = Server(self, loop)
                self.add_background_task(self._server.run_forever())
                return await super(WithServer, self).on_event_loop_started(loop)

        cls = WithServer.wraps(process_cls)

        mp_context.Process = cls
        super().__init__(*args, mp_context=mp_context, **kwargs)

    async def show_largest_ranges(self, parent=True):
        ranges = []
        if parent:
            with mmap(-1, 1 * 1024 * 1024 * 1024, flags=Flags.NORESERVE) as map:
                span = map.span
                ranges.append(span)

        async with asyncio.TaskGroup() as group:
            for process in self._processes:
                channel = process.channel
                group.create_task(channel.send(("show_largest_ranges",)))
        tasks = [asyncio.create_task(process.channel.recv) for process in self._processes]
        ranges.extend(await asyncio.gather(*tasks))
        return tuple(ranges)

    async def highest_common_range(self) -> ImmutableSpan:
        ranges = await self.show_largest_ranges()
        size = min(x[1] for x in ranges)
        lowest_range = min(x[0] for x in ranges)
        highest_range = max(x[0] for x in ranges)
        variance = highest_range - lowest_range
        highest_range += variance
        size -= variance
        return ImmutableSpan(highest_range, size)

    async def mmap(
        self,
        size: int,
        protection: Protections | int = Protections.READ_WRITE,
        flags: Flags | None = Flags.NONE,
        fd: int = -1,
        offset: int = 0,
    ):
        loop = asyncio.get_running_loop()
        address, available_size = await self.highest_common_range()
        if available_size < size:
            raise ValueError
        processes = tuple(self._processes)
        # Now try to reserve the range with address
        # we want to get an overallocated range that is ours
        # so we can do a MAP_FIXED replacement inside it!

        # try_reserve_range

        tasks = []
        reserved_size = min(size * 2, available_size)

        async def _reserve_range(process) -> ImmutableSpan:
            await process.channel.send(("try_reserve_range", address, reserved_size))
            return await process.channel.recv()

        parent_reserved = mmap(address, reserved_size)

        for process in processes:
            tasks.append(loop.create_task(_reserve_range(process)))
        reserved_ranges = await asyncio.gather(*tasks)
        reserved_ranges = (parent_reserved.span, *reserved_ranges)
        del tasks
        if len(set(reserved_ranges)) > 1:
            # wtf
            parent_reserved.close()
            async with asyncio.TaskGroup() as group:
                for process, reserved in zip(processes, reserved_ranges[1:]):
                    group.create_task(process.channel.send(("release_reserved_range", reserved)))
            raise ValueError(f"Unable to reserve ranges: {reserved_ranges}")

        # Ranges provisionally secure, now send over the fildes
        async def _send_fd_to(fd, process):
            loop = asyncio.get_running_loop()
            await process.channel.send(("incoming_fd", fd))
            await loop.run_in_executor(
                None, multiprocessing.reduction.send_handle, process.channel, fd, process.pid
            )
            their_fd = await process.channel.recv()
            return their_fd

        if fd > -1:
            tasks = []
            for process in processes:
                task = loop.run_in_executor(None, _send_fd_to(fd, process))
                tasks.append(task)
            process_fds = await asyncio.gather(*tasks)
            del tasks
        else:
            process_fds = [-1] * len(processes)

        # Now get our mmap!
        parent_mapping = map_reserved_range(
            parent_reserved, address, size, protection, flags, fd, offset
        )
        self._mappings[parent_mapping.span] = parent_mapping

        async def _request_mmap(process, process_fd, reserved_range):
            await process.channel.send(
                (
                    "request_mmap",
                    reserved_range,
                    address,
                    size,
                    protection,
                    flags,
                    process_fd,
                    offset,
                )
            )
            return await process.channel.recv()

        tasks = []
        for process, process_fd, reserved_range in zip(processes, process_fds, reserved_ranges):
            tasks.append(loop.create_task(_request_mmap(process, process_fd, reserved_range)))
        responses = await asyncio.gather(*tasks)
        if not all(response == "mmap_created" for response in responses):
            tasks = []
            for process, response in zip(processes, responses):
                if response != "mmap_created":
                    tasks.append(
                        loop.create_task(process.channel.send(("close_mmap", address, size)))
                    )
            await asyncio.gather(*tasks)
            parent_mapping.close()
            raise ValueError(f"At least one child failed securing mmap: {responses}")
        return parent_mapping

    def shutdown(self, *args, **kwargs):
        try:
            return super().shutdown(*args, **kwargs)
        finally:
            for mmap in self._mappings.values():
                mmap.close()
            self._mappings.clear()


def map_reserved_range(
    reserved_range: ImmutableSpan, address: int, size: int, protection, flags, fd, offset
):
    flags |= Flags.FIXED
    mapping = mmap(address, size, protection, flags, fd, offset)

    skipped_prefix_size = address - reserved_range.start
    skipped_postfix_size = reserved_range.start + reserved_range.length - size
    # Unmap any unused pages
    if skipped_prefix_size:
        munmap(address, skipped_prefix_size)
    if skipped_postfix_size:
        munmap(address + size, skipped_postfix_size)
    return mapping


if __name__ == "__main__":
    import asyncio
    import argparse
    import os
    import concurrent.futures
    from multiprocessing import get_context

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c",
        "--context",
        choices=multiprocessing.get_all_start_methods(),
        default=multiprocessing.get_start_method(),
    )
    args = parser.parse_args()

    context = get_context(args.context)
    common_start, size = asyncio.run(main(context))
    print(f"0x{common_start:X} @ { size / 1024 / 1024 / 1024 :.2f} GiB")
