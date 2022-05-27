import sys
from codecs import open  # To use a consistent encoding
from os import path

# Always prefer setuptools over distutils
from setuptools import setup, find_packages

here = path.abspath(path.dirname(__file__))
install_requirements = []
with open("requirements.txt") as fh:
    for line in fh:
        line = line.strip()
        install_requirements.append(line)

test_requirements = []
with open("test-requirements.txt") as fh:
    for line in fh:
        line = line.strip()
        test_requirements.append(line)

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
    license="BSD",
    packages=find_packages(exclude=["contrib", "docs", "tests*"]),
    include_package_data=True,
    extras_require={
        "test": test_requirements,
    },
    setup_requires=["cffi>=1.0.0"],
    cffi_modules=["shmutils/ffibuilder.py:ffi"],
    install_requires=install_requirements,
    keywords=["shm", "shared", "memory"],
    url="https://github.com/autumnjolitz/shmutils",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Topic :: Utilities",
        "License :: OSI Approved :: BSD License",
    ],
)
