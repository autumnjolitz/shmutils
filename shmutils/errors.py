from __future__ import annotations
import io
import errno
import logging
from collections import ChainMap
from typing import Type, Union, Tuple, Optional, Dict, Any
from ._shmutils import ffi

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

GENERIC_C_ERROR = "error - {errno} {err_name}"
INVALID_LOCK_ATTR = "The new value specified for the attribute is outside the range of legal values for that attribute."


def load_error(name, args):
    from . import exceptions

    return getattr(exceptions, name)(*args)


class IErrorable:
    def __reduce__(self):
        return load_error, (self.__name__, self.args)

    template_name: str
    template_values: Dict[str, Any]

    def with_template(self, template_name: str, **kwargs: Dict[str, Any]) -> Exception:
        if template_name is None:
            template_name = self.template_name
        return with_template(self, template_name, **kwargs)

    def with_template_values(self, **kwargs: Dict[str, Any]) -> Exception:
        return with_template(self, self.template_name, **kwargs)


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


def with_template(exc_value, template_name: str, **kwargs: Dict[str, Any]):
    exc_type = type(exc_value)
    template_name, template = get_template_from(template_name)
    args = exc_value.args[:-1]

    kwargs = {**exc_value.template_values, **kwargs}
    new_exc: Exception = exc_type(*args, format_template(template, **kwargs))
    new_exc.template_name = template_name
    new_exc.template_values = kwargs
    if exc_value.__traceback__:
        return new_exc.with_template(exc_value.__traceback__)
    return new_exc


def format_template(template, **kwargs):
    return template.format_map(kwargs)


def format_exception(exc_type: Union[str, Type[Exception]], template_name, *args, **kwargs):
    from . import exceptions

    if isinstance(exc_type, str):
        if "." in exc_type:
            *steps, last = exc_type.split(".")
            import importlib

            module = importlib.import_module(".".join(steps))
        else:
            module = exceptions
        exc_type = getattr(module, exc_type)
    template_name, template = get_template_from(template_name)
    if not issubclass(exc_type, IErrorable):
        type_name = exc_type.__qualname__.replace(".", "_")
        exc_type = type(
            type_name,
            (exc_type, IErrorable),
            {
                "template_name": template_name,
                "template_values": kwargs,
                "__module__": exceptions.__name__,
            },
        )
        setattr(exceptions, type_name, exc_type)
    e: Exception = exc_type(*args, format_template(template, **kwargs))
    return e


GENERIC_C_ERRNOS = {
    errno.EACCES: PermissionError,
    errno.EBADF: OSError,
    errno.EINVAL: ValueError,
    errno.EOVERFLOW: OverflowError,
    errno.ENOENT: FileNotFoundError,
    errno.ENOMEM: OSError,
    errno.ENOTSUP: io.UnsupportedOperation,
}


def libc_error(
    *,
    template: Optional[str] = None,
    error_code: Optional[int] = None,
    codes: Optional[Dict[int, Type[Exception]]] = None,
    default_template=GENERIC_C_ERROR,
    default_type=None,
    **kwargs,
) -> Exception:
    if error_code is None:
        error_code = ffi.errno
    try:
        err_name: str = errno.errorcode[error_code]
    except KeyError:
        err_name = ""
    if "errno" not in kwargs:
        kwargs["errno"] = error_code
    if "err_name" not in kwargs:
        kwargs["err_name"] = err_name
    if default_type is None:
        default_type = OSError
    exc_type = default_type
    if codes is not None:
        codes = ChainMap(codes, GENERIC_C_ERRNOS)
    else:
        codes = GENERIC_C_ERRNOS
    if codes is not None:
        try:
            exc_type = codes[error_code]
        except KeyError:
            exc_type = OSError
        else:
            if isinstance(exc_type, tuple):
                exc_type, template = exc_type
    if template is None:
        template = default_template
    if hasattr(exc_type, "errno"):
        if err_name:
            return format_exception(exc_type, template, error_code, err_name, **kwargs)
        return format_exception(exc_type, template, error_code, **kwargs)
    return format_exception(exc_type, template, **kwargs)


ERRORS_BY_NAME = {
    key: value for key, value in locals().items() if isinstance(value, str) and key.upper() == key
}
_ERRORS_TO_NAMES = {value: key for key, value in ERRORS_BY_NAME.items()}

assert len(ERRORS_BY_NAME) == len(_ERRORS_TO_NAMES), "values that are duplicate are not allowed"
