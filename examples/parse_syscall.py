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
    assert syscall_openat == "long openat(int error_code=0, int dirfd=0, const char * filename=bytearray(b'/proc/self/map'), int flags=O_RDONLY, umode_t mode=) = 1"


if __name__ == "__main__":
    main()