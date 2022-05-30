import sys
from typing import Type, Dict


class DispatchError(ValueError):
    pass


EXC_NAMES: Dict[str, Type[Exception]] = {}


def _update():
    here = sys.modules[__name__]
    for key in dir(here):
        value = getattr(here, key)
        if isinstance(value, type) and issubclass(value, Exception):
            EXC_NAMES[key] = value


_update()
