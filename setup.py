#!/usr/bin/env python

# Prepare a release:
#
#  - git pull --rebase  # check that there is no incoming changesets
#  - check version in ptrace_with_parser/version.py and doc/conf.py
#  - set release date in doc/changelog.rst
#  - check that "python3 setup.py sdist" contains all files tracked by
#    the SCM (Git): update MANIFEST.in if needed
#  - git commit -a -m "prepare release VERSION"
#  - Remove untracked files/dirs: git clean -fdx
#  - run tests, type: tox --parallel auto
#  - git push
#  - check GitHub Actions status:
#    https://github.com/vstinner/python-ptrace/actions
#
# Release a new version:
#
#  - git tag VERSION
#  - Remove untracked files/dirs: git clean -fdx
#  - python3 setup.py sdist bdist_wheel
#  - git push --tags
#  - twine upload dist/*
#
# After the release:
#
#  - increment version in  ptrace_with_parser/version.py and doc/conf.py
#  - git commit -a -m "post-release"
#  - git push

import importlib.util
from os import path
try:
    # setuptools supports bdist_wheel
    from setuptools import setup
except ImportError:
    from distutils.core import setup


MODULES = ["ptrace_with_parser", "ptrace_with_parser.binding", "ptrace_with_parser.syscall", "ptrace_with_parser.syscall.linux", "ptrace_with_parser.debugger"]

SCRIPTS = ("strace.py", "gdb.py")

CLASSIFIERS = [
    'Intended Audience :: Developers',
    'Development Status :: 4 - Beta',
    'Environment :: Console',
    'License :: OSI Approved :: GNU General Public License (GPL)',
    'Operating System :: OS Independent',
    'Natural Language :: English',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
]

with open('README.md') as fp:
    LONG_DESCRIPTION = fp.read()

ptrace_with_parser_spec = importlib.util.spec_from_file_location("version", path.join("ptrace_with_parser", "version.py"))
ptrace_with_parser = importlib.util.module_from_spec(ptrace_with_parser_spec)
ptrace_with_parser_spec.loader.exec_module(ptrace_with_parser)

PACKAGES = {}
for name in MODULES:
    PACKAGES[name] = name.replace(".", "/")

install_options = {
    "name": ptrace_with_parser.PACKAGE,
    "version": ptrace_with_parser.__version__,
    "url": ptrace_with_parser.WEBSITE,
    "download_url": ptrace_with_parser.WEBSITE,
    "author": "Victor Stinner",
    "description": "python binding of ptrace_with_parser",
    "long_description": LONG_DESCRIPTION,
    "classifiers": CLASSIFIERS,
    "license": ptrace_with_parser.LICENSE,
    "packages": list(PACKAGES.keys()),
    "package_dir": PACKAGES,
    "scripts": SCRIPTS,
}

setup(**install_options)
