# Copyright (c) 2022 Intel Corporation.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import os
from setuptools import setup, Extension
from Cython.Build import cythonize


eii_version = os.getenv("EII_VERSION", "3.0")
cmake_install_prefix = os.getenv("CMAKE_INSTALL_PREFIX", "/opt/intel/eii")

extensions = [
    Extension('*', ['./eii/*.pyx'],
              include_dirs=[cmake_install_prefix + '/include'],
              library_dirs=[cmake_install_prefix + '/lib'],
              libraries=['eiimsgbus', 'eiiutils', 'eiimsgenv'])
]


compiler_directives = {"language_level": 3, "embedsignature": True}
extensions = cythonize(extensions, compiler_directives=compiler_directives)


setup(
    name='eii-msgbus',
    version=eii_version,
    description='EII message bus Python wrapper',
    keywords='msgbus zeromq',
    url='',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Operating System :: POSIX',
        'Intended Audience :: Developers',
        'Topic :: System :: Networking',
    ],
    package_dir={'': '.'},
    packages=['eii'],
    ext_modules=extensions,
    build_dir='./build/cython',
)
