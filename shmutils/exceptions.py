import sys
import builtins
from .errors import IErrorable
from typing import Dict, Type

exc_types: Dict[str, Type[IErrorable]] = {}


class DispatchError(ValueError):
    pass


def _update():
    here = sys.modules[__name__]
    exc_types = {
        key: type(value.__name__, (value, IErrorable), {})
        for key, value in ((key, getattr(builtins, key)) for key in dir(builtins))
        if key.endswith("Error") and isinstance(value, type)
    }
    here.exc_types = exc_types

    for key in dir(here):
        value = getattr(here, key)
        if isinstance(value, type) and issubclass(value, Exception):
            exc_types[key] = value


_update()


def __getattr__(key):
    try:
        return exc_types[key]
    except KeyError:
        raise AttributeError(key)
