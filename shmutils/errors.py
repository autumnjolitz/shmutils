from __future__ import annotations

import logging
from typing import Type, Union, Tuple

from .exceptions import EXC_NAMES

logger = logging.getLogger(__name__)

MMAP_NEW_EBADF = "The fd argument is not a valid open file descriptor."
MMAP_NEW_ENODEV = (
    "MAP_ANON has not been specified and the file fd refers to does not support mapping."
)
MMAP_NEW_ENXIO = "Addresses in the specified range are invalid for fd."
MMAP_NEW_EOVERFLOW = "Addresses in the specified range exceed the maximum offset set for fd."

MMAP_NEW_EACCESS_READ_ASKED = (
    "The flag PROT_READ was specified as part of the prot argument and fd was not open for reading."
)
MMAP_NEW_EACCESS_WRITE_SHARED_ASKED = "The flags MAP_SHARED and PROT_WRITE were specified as part of the flags and prot argument and fd was not open for writing."

MMAP_NEW_ENOMEM_MAP_FIXED = "MAP_FIXED was specified and the addr argument was not available. "
MMAP_NEW_ENOMEM_MAP_ANON = "MAP_ANON was specified and insufficient memory was available."
MMAP_NEW_EINVAL_FIXED = (
    "Part of the desired address space resides out of the valid address space for a user process."
)
# MUNMAP_EINVAL_ = The addr parameter was not page aligned (i.e., a multiple of the page size).
# MUNMAP_EINVAL_ = The len parameter was negative or zero.
MUNMAP_EINVAL_MAP_STOMPED_BY_FIXED = (
    "Some part of the region being unmapped is not part of the currently valid address space."
)
GENERIC_C_ERROR = "error"


def get_template_from(template_name: str) -> Tuple[str, str]:
    try:
        template_value = ERRORS_BY_NAME[template_name]
    except KeyError:
        template_value = template_name
        try:
            template_name = _ERRORS_TO_NAMES[template_name]
        except KeyError:
            template_name = ""
        logger.warning(f"no name assigned for {template_value!r}")
    return template_name, template_value


def format_exception(exc_type: Union[str, Type[Exception]], template_name, *args, **kwargs):
    if not isinstance(exc_type, type):
        exc_type = EXC_NAMES[exc_type]
    template_name, template = get_template_from(template_name)
    e: Exception = exc_type(*args, format(template, **kwargs))
    e.template_name = template_name
    e.template_values = kwargs
    return e


ERRORS_BY_NAME = {
    key: value for key, value in locals().items() if isinstance(value, str) and key.upper() == key
}
_ERRORS_TO_NAMES = {value: key for key, value in ERRORS_BY_NAME.items()}

assert len(ERRORS_BY_NAME) == len(_ERRORS_TO_NAMES), "values that are duplicate are not allowed"
