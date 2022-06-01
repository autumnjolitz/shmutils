from codecs import open  # To use a consistent encoding
from os import path

# Always prefer setuptools over distutils
from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))

with open(path.join(here, "README.rst"), encoding="utf-8") as fh:
    long_description = fh.read()

# We separate the version into a separate file so we can let people
# import everything in their __init__.py without causing ImportError.
__version__ = None
exec(open("shmutils/about.py").read())
if __version__ is None:
    raise IOError("about.py in project lacks __version__!")

setup(
    name="shmutils",
    version=__version__,
    author="Autumn Jolitz",
    description="Shared memory structures",
    long_description=long_description,
    long_description_content_type="text/x-rst",
    license="BSD",
    packages=find_packages(exclude=["contrib", "docs", "tests*"]),
    include_package_data=True,
    extras_require={
        "test": [
            "pytest",
            "black",
            "flake8",
            "wheel",
            "twine",
        ],
    },
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=["shmutils/ffibuilder.py:ffi"],
    install_requires=[
        "cffi>=1.0.0",
        "intervaltree",
    ],
    keywords=[
        "shm",
        "shared",
        "memory",
        "posix",
        "mmap",
        "munmap",
        "shm_open",
        "shm_unlink",
        "pickle",
        "cffi",
        "cdatqa",
        "shared",
        "heap",
    ],
    url="https://github.com/autumnjolitz/shmutils",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: BSD License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX :: BSD",
        "Operating System :: POSIX :: Linux",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: System :: Hardware :: Symmetric Multi-processing",
    ],
)
