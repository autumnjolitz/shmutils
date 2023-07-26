"Shared memory utils in python"
__version__ = "0.0.2"

from .mmap import Flags as MapFlags, Protections as MapProtections, mmap


__all__ = ["MapProtections", "MapFlags", "mmap"]
