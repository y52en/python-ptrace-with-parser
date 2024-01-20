# python-ptrace

[![Latest release on the Python Cheeseshop (PyPI)](https://img.shields.io/pypi/v/python-ptrace.svg)](https://pypi.python.org/pypi/python-ptrace)
[![Build status of python-ptrace on GitHub Actions](https://github.com/vstinner/python-ptrace/actions/workflows/build.yml/badge.svg)](https://github.com/vstinner/python-ptrace/actions)

このフォークはpython-ptraceからシステムコールの解釈をする機能だけを使えるようにしたものです。
ただし、現在は一部の機能を実装していないため、すべてのシステムコールの出力ができるわけではありません。(例えば、readStructは実装していません)

また、AARCH64の一部のシステムコールしかテストしていません。

インストールするには以下のコマンドを実行してください。
```bash
git clone https://github.com/y52en/python-ptrace-with-parser
python3 setup.py install
```


使い方は以下を参照してください。
[parse_syscall.py](./examples/parse_syscall.py)
```python
from ptrace_with_parser.func_call import FunctionCallOptions
from ptrace_with_parser.syscall.ptrace_syscall import SyscallParser, Arch


def main():
    def mem_read(addr, size) -> bytes:
        return (b"\x00/proc/self/map\x00")[addr : addr + size]

    parser = SyscallParser(
        FunctionCallOptions(
            write_types=True,
            write_argname=True,
            replace_socketcall=False,
            string_max_length=300,
            write_address=False,
            max_array_count=20,
        ),
        Arch.AARCH64,
        mem_read,
    )
    syscall_exit = parser.parse(
        {
            "x8": 93,  # exit
            "x0": 0, # exit code
            "x1": 0,
            "x2": 0,
            "x3": 0,
            "x4": 0,
            "x5": 0,
            "x6": 0,
            "x7": 0,
        },
        0,
    )
    assert syscall_exit == "long exit(int error_code=0)              = 0"

    syscall_openat = parser.parse(
        {
            "x8": 56,  # openat
            "x0": 0,  # dirfd
            "x1": 0x1,  # filename(addr)
            "x2": 0,  # flags
            "x3": 0,  # mode
            "x4": 0,
            "x5": 0,
            "x6": 0,
            "x7": 0,
        },
        1,  # fd
    )
    assert syscall_openat == "long openat(int dirfd=0, const char * filename=bytearray(b'/proc/self/map'), int flags=O_RDONLY, umode_t mode=) = 1"


if __name__ == "__main__":
    main()
```

python-ptrace is a debugger using ptrace (Linux, BSD and Darwin system call to trace processes) written in Python.

- [python-ptrace documentation](http://python-ptrace.readthedocs.io/)
- [python-ptrace at GitHub](https://github.com/vstinner/python-ptrace)
- [python-ptrace at the Python Cheeseshop (PyPI)](https://pypi.python.org/pypi/python-ptrace)

python-ptrace is an open-source project written in Python under GNU GPLv2 license. It supports Python 3.6 and newer.
