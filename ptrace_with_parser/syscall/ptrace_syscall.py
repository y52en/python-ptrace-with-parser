from __future__ import annotations

from os import strerror
from errno import errorcode
from typing import Callable, TYPE_CHECKING

from ptrace_with_parser.cpu_info import (
    CPU_X86_64,
    CPU_POWERPC,
    CPU_I386,
    CPU_ARM32,
    CPU_AARCH64,
    CPU_RISCV,
)
from ptrace_with_parser.ctypes_tools import ulong2long, formatAddress, formatWordHex

if TYPE_CHECKING:
    from ptrace_with_parser.debugger.process import PtraceProcess
from ptrace_with_parser.func_call import FunctionCall, FunctionCallOptions
from ptrace_with_parser.syscall import SYSCALL_NAMES, SYSCALL_PROTOTYPES, SyscallArgument
from ptrace_with_parser.syscall.socketcall import setupSocketCall
from ptrace_with_parser.os_tools import RUNNING_LINUX, RUNNING_BSD
from ptrace_with_parser.cpu_info import CPU_WORD_SIZE
from ptrace_with_parser.binding.cpu import CPU_INSTR_POINTER
from ptrace_with_parser.binding import ptrace_registers_t
from enum import Enum

if CPU_POWERPC:
    SYSCALL_REGISTER = "gpr0"
elif CPU_ARM32:
    SYSCALL_REGISTER = "r7"
elif CPU_AARCH64:
    SYSCALL_REGISTER = "r8"
elif CPU_RISCV:
    SYSCALL_REGISTER = "a7"
elif RUNNING_LINUX:
    if CPU_X86_64:
        SYSCALL_REGISTER = "orig_rax"
    else:
        SYSCALL_REGISTER = "orig_eax"
else:
    if CPU_X86_64:
        SYSCALL_REGISTER = "rax"
    else:
        SYSCALL_REGISTER = "eax"

if CPU_ARM32:
    RETURN_VALUE_REGISTER = "r0"
elif CPU_AARCH64:
    RETURN_VALUE_REGISTER = "r0"
elif CPU_I386:
    RETURN_VALUE_REGISTER = "eax"
elif CPU_X86_64:
    RETURN_VALUE_REGISTER = "rax"
elif CPU_POWERPC:
    RETURN_VALUE_REGISTER = "result"
elif CPU_RISCV:
    RETURN_VALUE_REGISTER = "a0"
else:
    raise NotImplementedError("Unsupported CPU architecture")

PREFORMAT_ARGUMENTS = {
    "select": (1, 2, 3),
    "execve": (0, 1, 2),
    "clone": (0, 1),
}


class Arch(Enum):
    X86_64 = 0
    I386 = 1
    ARM32 = 2
    AARCH64 = 3
    RISCV32 = 4
    RISCV64 = 5
    RUNNING_BSD = 6
    PPC32 = 7
    PPC64 = 8


class PtraceSyscall(FunctionCall):
    result_text: str | None

    def __init__(
        self,
        process: PtraceProcess,
        options: FunctionCallOptions,
        regs: ptrace_registers_t | None = None,
    ):
        super().__init__("syscall", options, SyscallArgument)
        self.process = process
        self.restype = "long"
        self.result = None
        self.result_text = None
        self.instr_pointer = None
        if not regs:
            regs = self.process.getregs()
        self.readSyscall(regs)

    def enter(self, regs=None):
        if not regs:
            regs = self.process.getregs()
        argument_values = self.readArgumentValues(regs)
        self.readArguments(argument_values)

        if self.name == "socketcall" and self.options.replace_socketcall:
            setupSocketCall(self, self.process, self[0], self[1].value)

        # Some arguments are lost after the syscall, so format them now
        if self.name in PREFORMAT_ARGUMENTS:
            for index in PREFORMAT_ARGUMENTS[self.name]:
                argument = self.arguments[index]
                argument.format()

        if self.options.instr_pointer:
            self.instr_pointer = getattr(regs, CPU_INSTR_POINTER)  # pc register

    def readSyscall(self, regs: ptrace_registers_t):
        # Read syscall number
        self.syscall = getattr(regs, SYSCALL_REGISTER)
        # Get syscall variables
        self.name = SYSCALL_NAMES.get(self.syscall, "syscall<%s>" % self.syscall)

    def readArgumentValues(self, regs: ptrace_registers_t) -> tuple[int, ...]:
        if CPU_X86_64:
            return (regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9)
        if CPU_ARM32:
            return (regs.r0, regs.r1, regs.r2, regs.r3, regs.r4, regs.r5, regs.r6)
        if CPU_AARCH64:
            return (
                regs.r0,
                regs.r1,
                regs.r2,
                regs.r3,
                regs.r4,
                regs.r5,
                regs.r6,
                regs.r7,
            )
        if CPU_RISCV:
            return (regs.a0, regs.a1, regs.a2, regs.a3, regs.a4, regs.a5, regs.a6)
        if RUNNING_BSD:
            sp = self.process.getStackPointer()
            return [
                self.process.readWord(sp + index * CPU_WORD_SIZE)
                for index in range(1, 6 + 1)
            ]
        if CPU_I386:
            return (regs.ebx, regs.ecx, regs.edx, regs.esi, regs.edi, regs.ebp)
        if CPU_POWERPC:
            return (regs.gpr3, regs.gpr4, regs.gpr5, regs.gpr6, regs.gpr7, regs.gpr8)
        raise NotImplementedError()

    def readArguments(self, argument_values: tuple[int, ...]):
        if self.name in SYSCALL_PROTOTYPES:
            self.restype, formats = SYSCALL_PROTOTYPES[self.name]
            for value, format in zip(argument_values, formats):
                argtype, argname = format
                self.addArgument(value=value, name=argname, type=argtype)
        else:
            for value in argument_values:
                self.addArgument(value=value)

    def exit(self) -> str:
        if self.name in PREFORMAT_ARGUMENTS:
            preformat = set(PREFORMAT_ARGUMENTS[self.name])
        else:
            preformat = set()

        # Data pointed by arguments may have changed during the syscall
        # e.g. uname() syscall
        for index, argument in enumerate(self.arguments):
            if index in preformat:
                # Don't lose preformatted arguments
                continue
            if argument.type and not argument.type.endswith("*"):
                continue
            argument.text = None

        self.result = self.process.getreg(RETURN_VALUE_REGISTER)

        if self.restype.endswith("*"):
            text = formatAddress(self.result)
        else:
            uresult = self.result
            self.result = ulong2long(self.result)
            if self.result < 0 and (-self.result) in errorcode:
                errcode = -self.result
                text = "%s %s (%s)" % (
                    self.result,
                    errorcode[errcode],
                    strerror(errcode),
                )
            elif not (0 <= self.result <= 9):
                text = "%s (%s)" % (self.result, formatWordHex(uresult))
            else:
                text = str(self.result)
        self.result_text = text
        return text

    def __str__(self):
        return "<Syscall name=%r>" % self.name


class SyscallParser(FunctionCall):
    result_text: str | None

    def __init__(
        self,
        options: FunctionCallOptions,
        arch: Arch,
        mem_read: Callable[[int, int], bytes],
    ):
        super().__init__("syscall", options, SyscallArgument, mem_read)
        self.restype = "long"
        self.result = None
        self.result_text = None
        self.instr_pointer = None
        self.arch = arch
        self.mem_read = mem_read
        self.set_const()

    def set_const(self):
        match self.arch:
            case Arch.X86_64:
                from ptrace_with_parser.syscall.linux.x86_64 import (
                    SYSCALL_NAMES,
                    SOCKET_SYSCALL_NAMES,
                )
            case Arch.I386:
                from ptrace_with_parser.syscall.linux.i386 import (
                    SYSCALL_NAMES,
                    SOCKET_SYSCALL_NAMES,
                )
            case Arch.PPC64:
                from ptrace_with_parser.syscall.linux.powerpc64 import (
                    SYSCALL_NAMES,
                    SOCKET_SYSCALL_NAMES,
                )
            case Arch.PPC32:
                from ptrace_with_parser.syscall.linux.powerpc32 import (
                    SYSCALL_NAMES,
                    SOCKET_SYSCALL_NAMES,
                )
            case Arch.AARCH64:
                from ptrace_with_parser.syscall.linux.aarch64 import (
                    SYSCALL_NAMES,
                    SOCKET_SYSCALL_NAMES,
                )
            case Arch.RISCV32:
                from ptrace_with_parser.syscall.linux.riscv32 import (
                    SYSCALL_NAMES,
                    SOCKET_SYSCALL_NAMES,
                )
            case Arch.RISCV64:
                from ptrace_with_parser.syscall.linux.riscv64 import (
                    SYSCALL_NAMES,
                    SOCKET_SYSCALL_NAMES,
                )
            case Arch.RUNNING_BSD:
                from ptrace_with_parser.syscall.freebsd_syscall import (
                    SYSCALL_NAMES,
                    SOCKET_SYSCALL_NAMES,
                )
            case _:
                raise NotImplementedError("Unsupported CPU architecture")

        match self.arch:
            case Arch.PPC32, Arch.PPC64:
                SYSCALL_REGISTER = "gpr0"
            case Arch.ARM32:
                SYSCALL_REGISTER = "r7"
            case Arch.AARCH64:
                SYSCALL_REGISTER = "x8"
            case Arch.RISCV32, Arch.RISCV64:
                SYSCALL_REGISTER = "a7"
            case Arch.X86_64:
                SYSCALL_REGISTER = "rax"
            case _:
                SYSCALL_REGISTER = "eax"

        match self.arch:
            case Arch.ARM32:
                RETURN_VALUE_REGISTER = "r0"
            case Arch.AARCH64:
                RETURN_VALUE_REGISTER = "x0"
            case Arch.I386:
                RETURN_VALUE_REGISTER = "eax"
            case Arch.X86_64:
                RETURN_VALUE_REGISTER = "rax"
            case Arch.PPC32, Arch.PPC64:
                RETURN_VALUE_REGISTER = "result"
            case Arch.RISCV32, Arch.RISCV64:
                RETURN_VALUE_REGISTER = "a0"
            case _:
                raise NotImplementedError("Unsupported CPU architecture")

        self.SYSCALL_REGISTER = SYSCALL_REGISTER
        self.RETURN_VALUE_REGISTER = RETURN_VALUE_REGISTER
        self.SYSCALL_NAMES = SYSCALL_NAMES
        self.SOCKET_SYSCALL_NAMES = SOCKET_SYSCALL_NAMES

    def parse(self, regs: dict[str, int], return_val: int) -> str:
        self._readSyscall(regs)
        self._enter(regs)
        if self.name in PREFORMAT_ARGUMENTS:
            preformat = set(PREFORMAT_ARGUMENTS[self.name])
        else:
            preformat = set()

        # Data pointed by arguments may have changed during the syscall
        # e.g. uname() syscall
        for index, argument in enumerate(self.arguments):
            if index in preformat:
                # Don't lose preformatted arguments
                continue
            if argument.type and not argument.type.endswith("*"):
                continue
            argument.text = None

        self.result = return_val

        if self.restype.endswith("*"):
            text = formatAddress(self.result)
        else:
            uresult = self.result
            self.result = ulong2long(self.result)
            if self.result < 0 and (-self.result) in errorcode:
                errcode = -self.result
                text = "%s %s (%s)" % (
                    self.result,
                    errorcode[errcode],
                    strerror(errcode),
                )
            elif not (0 <= self.result <= 9):
                text = "%s (%s)" % (self.result, formatWordHex(uresult))
            else:
                text = str(self.result)
        self.result_text = text
        self.parsed_text = "%-40s = %s" % (self.format(), self.result_text)
        self.before_args = self.arguments
        self.arguments = []
        return self.parsed_text

    def _enter(self, regs: dict[str, int]):
        argument_values = self._readArgumentValues(regs)
        self._readArguments(argument_values)

        if self.name == "socketcall" and self.options.replace_socketcall:
            raise NotImplementedError()
            # setupSocketCall(self, self.process, self[0], self[1].value)

        # Some arguments are lost after the syscall, so format them now
        if self.name in PREFORMAT_ARGUMENTS:
            for index in PREFORMAT_ARGUMENTS[self.name]:
                argument = self.arguments[index]
                argument.format(self.mem_read)

        if self.options.instr_pointer:
            self.instr_pointer = regs[CPU_INSTR_POINTER]

    def _readSyscall(self, regs: ptrace_registers_t):
        # Read syscall number
        self.syscall = regs[self.SYSCALL_REGISTER]
        # Get syscall variables
        self.name = self.SYSCALL_NAMES.get(self.syscall, "syscall<%s>" % self.syscall)

    def _readArgumentValues(self, regs: dict[str, int]) -> tuple[int, ...]:
        match self.arch:
            case Arch.X86_64:
                return (
                    regs["rdi"],
                    regs["rsi"],
                    regs["rdx"],
                    regs["r10"],
                    regs["r8"],
                    regs["r9"],
                )
            case Arch.ARM32:
                return (
                    regs["r0"],
                    regs["r1"],
                    regs["r2"],
                    regs["r3"],
                    regs["r4"],
                    regs["r5"],
                    regs["r6"],
                )
            case Arch.AARCH64:
                return (
                    regs["x0"],
                    regs["x1"],
                    regs["x2"],
                    regs["x3"],
                    regs["x4"],
                    regs["x5"],
                    regs["x6"],
                    regs["x7"],
                )
            case Arch.RISCV32, Arch.RISCV64:
                return (
                    regs["a0"],
                    regs["a1"],
                    regs["a2"],
                    regs["a3"],
                    regs["a4"],
                    regs["a5"],
                    regs["a6"],
                )
            case Arch.RUNNING_BSD:
                sp = self.process.getStackPointer()
                return [
                    self.process.readWord(sp + index * CPU_WORD_SIZE)
                    for index in range(1, 6 + 1)
                ]
            case Arch.I386:
                return (
                    regs["ebx"],
                    regs["ecx"],
                    regs["edx"],
                    regs["esi"],
                    regs["edi"],
                    regs["ebp"],
                )
            case Arch.PPC32, Arch.PPC64:
                return (
                    regs["gpr3"],
                    regs["gpr4"],
                    regs["gpr5"],
                    regs["gpr6"],
                    regs["gpr7"],
                    regs["gpr8"],
                )
        raise NotImplementedError()

    def _readArguments(self, argument_values: tuple[int, ...]):
        if self.name in SYSCALL_PROTOTYPES:
            self.restype, formats = SYSCALL_PROTOTYPES[self.name]
            for value, format in zip(argument_values, formats):
                argtype, argname = format
                self.addArgument(value=value, name=argname, type=argtype)
        else:
            for value in argument_values:
                self.addArgument(value=value)

    def __str__(self):
        return "<Syscall name=%r>" % self.name
