from setuptools import setup

setup(
    cffi_modules=["shmutils/ffibuilder.py:ffi"],
)
