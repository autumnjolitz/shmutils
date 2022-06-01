shmutils - Shared Memory structures in Python
=================================================

|Release Status| |Style Status| |Test Status|

I've wondered why isn't it easier to have multiple processes be able to have a shared memory space.

I've also wondered about how to pass shared memory definitions between processes.

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


Roadmap
--------

- |done| Virtual address stability

  - ``MappedMemory.at`` (relative address to bytes)
  - ``MappedMemory.absolute_at`` (absolute address to bytes)
  - ``MappedMemory.abs_address_at`` (relative address -> absolute address)
  - ``MappedMemory.relative_address_at`` (absolute address -> relative address)

- |inprogress| Support Python ``multiprocessing.get_context("spawn")``
- |todo| Refactor ``MappedMemory`` to ``AbsoluteMemory``, ``RelativeMemory`` where ``AbsoluteMemory`` is a subclass of ``RelativeMemory``

  - disallow ``abs_address_at``, ``absolute_at`` on relative only mappings

- |todo| figure out pickling of ``cffi.CData``
-   |todo| switch to ``instruct`` for internal classes

    - implement something like:

      .. code-block:: python

        from instruct import CBase, class_metadata, astuple
        from shmutils import MemoryMap, MemoryFlags, ffi as shmffi

        ...
        fd = shm_open(...).truncate(PAGE_SIZE)
        page = MemoryMap(None, PAGE_SIZE, flags=MemoryFlags.SHARED, fd=fd)
        ...

        ffi = cffi.FFI()
        # You can include other ffi's to reuse c type declarations
        ffi.include(shmffi)
        ffi.cdef('''
            typedef enum {INACTIVE, ACTIVE, DELETED} OrgUserStatus_t;
        ''')
        # pass into the instruct.CBase class an ffi instead of ``instruct.default_ffi``
        class User(CBase, ffi=ffi):
            __slots__ = '''
            struct org_user_t {
                uint64_t id;
                char     *fullname;
                uint8_t  fullname_len;
                OrgUserStatus_t status;   
            };
            '''

        assert User.__slots__ == ()
        assert ffi.typeof(class_metadata(User, "cdecl")) is ffi.typeof('struct org_user_t)
        assert ffi.sizeof('struct org_user_t') == class_metadata(User, "csizeof")
        assert ffi is class_metadata(User, "default_ffi")

        lib = ffi.dlopen(None)
        # Allocate using ``ffi.new``
        u = User.new(12345, b"Autumn", 6, lib.ACTIVE)
        assert User.typeof(u) == 'struct org_user_t*'
        assert ffi.typeof(u.id) is ffi.typeof('uint64_t')
        assert ffi.typeof(u.fullname) is ffi.typeof('char*')
        assert ffi.typeof(u.fullname_len) is ffi.typeof('uint8_t')
        assert len(memoryview(User.getbuffer(u))) == User.sizeof()
        assert len(memoryview(User.getbuffer(u))) == User.sizeof(u)
        assert not hasattr(u, 'sizeof')
        assert u.__internals__["heap"] is None

        # Allocate using an alternate function
        # in this case, use the ``.new`` malloc for the
        # shared page
        SharedUser: Type[User] = User.with_heap(page)
        u2 = SharedUser.new()
        assert u2.__internals__["heap"] is page
        assert u2.id == 0
        assert u2.fullname == ffi.NULL
        assert u2.fullname_len == 0
        assert u2.status == 0

        # as far as the cdata is concerned, it points into the ``page``'s heap
        # User the ``CBase``'s ``.addressof`` call to get a pointer to the entity
        abs_ptr = ffi.cast('uintptr_t', User.addressof(u2))
        assert page.address.begin <= int(abs_ptr) < page.address.end
        # page contents and buffer match each other
        assert page.absolute_at[abs_ptr: abs_ptr + User.sizeof()] == User.getbuffer()[0: User.sizeof()]

        # demo assign
        # allocate space for a name
        raw_u2_fullname = page.new('char*', b'Autumn Jolitz')
        u2.id = 4123
        u2.fullname = u2_fullname  # assign the pointer
        u2.fullname_len = 13
        u2.status = lib.ACTIVE
        assert astuple(u2) == (u2.id, raw_u2_fullname, u2.fullname_len, lib.ACTIVE)
        u2_copy = pickle.loads(pickle.dumps(u2))
        assert u2_copy.__internals__["heap"] is page
        assert astuple(u2) == astuple(u2_copy)

- |todo| split Locks into ``RawLock|RawRLock`` (consumes a ``memoryview|bytebuffer|ffi.buffer``, allocates from 0 to length of lock size)
- |todo| split Locks into ``Lock|RLock``
- |todo| reimplement locking in terms of a condition variable
- |todo| use liblfs for a freelist
- |todo| make a shared heap process-safe

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

.. |done| unicode:: U+2705
.. |warning| unicode:: U+FE0F
.. |error| unicode:: U+274C
.. |inprogress| unicode:: U+1F6A7
.. |todo| unicode:: U+2610

.. |Release Status| image:: https://github.com/autumnjolitz/shmutils/actions/workflows/release.yml/badge.svg
    :target: https://github.com/autumnjolitz/shmutils/actions/workflows/release.yml

.. |Style Status| image:: https://github.com/autumnjolitz/shmutils/actions/workflows/style.yml/badge.svg
    :target: https://github.com/autumnjolitz/shmutils/actions/workflows/style.yml

.. |Test Status| image:: https://github.com/autumnjolitz/shmutils/actions/workflows/test.yml/badge.svg
    :target: https://github.com/autumnjolitz/shmutils/actions/workflows/test.yml









