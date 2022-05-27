import errno
import functools
from typing import Tuple, Type, Dict

PAGE_MAPPINGS = {
    errno.EACCES: PermissionError,
    errno.ENOENT: FileNotFoundError,
    errno.ENAMETOOLONG: ValueError,
}


def exception_from(
    code: int, mapping: Dict[int, Type[Exception]]
) -> Tuple[Type[Exception], int, str]:
    try:
        err_name = errno.errorcode[code]
    except KeyError:
        err_name = "?????"
    try:
        exc_type = mapping[code]
    except KeyError:
        exc_type = OSError
    return exc_type, code, err_name


exception_from_shm_calls = functools.partial(exception_from, mapping=PAGE_MAPPINGS)
