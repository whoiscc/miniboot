"""misc.py - Minimal Instruction Set Computer

The platform that be treated as *native* by the rest of MiniBoot project.

The design choices of the instruction set:
* Close enough to real-world instruction set, i.e. almost able to be one-to-one 
  translated to x86/RISC instruction set (no reverse)
* Just enough to support a bootstrapping compiler
* Able for human to directly write pratical program in. We need jump label :)

This code implements an emulator. It takes a text-based program written for 
Minimal Instruction Set Computer. The following gives instruction specification.

----

# The Computer

**Registers.** There are 4 general purpose register called RA, RB, RC and RD,
each with 64 bits. No instruction reference registers by name, so the name is 
only for documentation. Some instructions implicitly access to certain 
registers, and some instructions only access to some bits of registers. Normally
instructions do not access RD, so it is suitable for storing stack base address.

**Memory.** Addresses are indexed per byte. Valid address space is from 0 to
2^64 - 1. The implementation only *allocate* memory per 4KB page upon first
accessing, so sparsely accessing address space is safe. The program is stored
at fixed address before execution, and any load/store attempt that perform on
program pages during execution is illegal. Some part of memory can be mapped to
file. If the file exists prior to execution, the content of file will be stored
into specified memory, and after execution the content of memory will be written
back to file. To help development, the implementation only writes back if the
program exit sucessfully, and the writing-back will be store in `filename.1` to
avoid in-place overriding.

# The instructions

Each instruction virtually takes 32 bits. The instructions do not have a binary 
representation, so the size definition is only for defining the offset of each 
instruction in a program. The operand of instructions is immediate number, which 
is at most 24 bits long.

Instruction may not store continuously. If an instruction do not store in the
following address of previous instruction in the program text, it should be
prefixed with its address. Overriding instruction is illegal.

The literal includes address, instruction name, immediate number and comment. 
Immediate number is written in hex without 0x prefix. Comment starts with 
semicolon. Address is written in hex with 0x prefix on separated line.

**`.data`**
Special pseudo instruction, define 32 bits of data located in the address of 
itself, which will be written into memory before execution. Take 4 immediate 
numbers, each should be 8 bits. `.data` and instruction cannot exist in the same 
page, and `.data` page can be accessed during execution.

**`load`** 
Read into RA, from memory address specified by RB. (RB) must align to 8.

**`store64`/`store32`/`store16`/`store8`** 
Write the low 64/32/16/8 bit of RA to memory address specified by RB. (RB) must 
align to 8/4/2/1.

**`loadb`/`loadc`/`loadd`** 
Override RA with RB/RC/RD.

**`storeb`/`storec`/`stored`** 
Override RB/RC/RD with RA.

**`imm24`/`imm16`** 
Override the low 24/16 bit of RA with immediate number.

**`int`**
Interrupt execution and according to immediate number:
* `0` exit with code RA
* `1` start a debugger
* `2` print memory content to a output stream, stream descriptor speicified by 
  RA, buffer address specified by RB, buffer length specified by RC

**`shiftl`**
Left bit-shift RA by immediate number, at most 6 bits long. Zero-padding.

"""
from sys import argv


PAGE_SIZE = 2 ** 12
INST_SIZE = 4


class Page:
    def __init__(self, start):
        self.mem = [0] * PAGE_SIZE
        self.start = start

    def preload_data(self, offset, a, b, c, d):
        assert offset % 4 == 0, "preload data not align to 4"
        self.mem[offset + 0] = a
        self.mem[offset + 1] = b
        self.mem[offset + 2] = c
        self.mem[offset + 3] = d

    def preload_instruction(self, offset, inst):
        raise RuntimeError(
            f"cannot preload instruction into unprotected page {hex(self.start)}"
        )

    def get_slice(self, offset, length):
        return self.mem[offset : offset + length]

    def load_instruction(self, offset):
        raise RuntimeError(
            f"cannot load instruction from unprotectecd page {hex(self.start)}"
        )


class ProtectedPage:
    def __init__(self, start):
        self.mem = [None] * (PAGE_SIZE // INST_SIZE)
        self.start = start

    def preload_data(self, offset, a, b, c, d):
        raise RuntimeError(f"cannot preload data into protected page {hex(self.start)}")

    def preload_instruction(self, offset, inst):
        assert offset % INST_SIZE == 0, f"instruction address not align to {INST_SIZE}"
        index = offset // INST_SIZE
        assert (
            self.mem[index] is None
        ), f"override instruction at {hex(self.start + offset)}"
        self.mem[index] = inst

    def get_slice(self, offset, length):
        raise RuntimeError(f"illegal access to protected page {hex(self.start)}")

    def load_instruction(self, offset):
        assert offset % INST_SIZE == 0, f"instruction address not align to {INST_SIZE}"
        index = offset // INST_SIZE
        return self.mem[index]


class Memory:
    def __init__(self):
        self.page_table = {}

    def touch_page(self, page_index, protected):
        if page_index not in self.page_table:
            page_start = page_index * PAGE_SIZE
            page = protected and ProtectedPage(page_start) or Page(page_start)
            self.page_table[page_index] = page

    def preload_data(self, address, a, b, c, d):
        page_index, page_offset = address // PAGE_SIZE, address % PAGE_SIZE
        self.touch_page(page_index, False)
        self.page_table[page_index].preload_data(page_offset, a, b, c, d)

    def preload_instruction(self, address, inst):
        page_index, page_offset = address // PAGE_SIZE, address % PAGE_SIZE
        self.touch_page(page_index, True)
        self.page_table[page_index].preload_instruction(page_offset, inst)

    def get_slice(self, address, length):
        slice = []
        page_index, page_offset = address // PAGE_SIZE, address % PAGE_SIZE
        while len(slice) < length:
            slice += self.page_table[page_index].get_slice(
                page_offset, length - len(slice)
            )
            page_index += 1
            page_offset = 0
        return slice

    def load_instruction(self, address):
        page_index, page_offset = address // PAGE_SIZE, address % PAGE_SIZE
        return self.page_table[page_index].load_instruction(page_offset)


class Computer:
    def __init__(self, init_pointer):
        self.memory = Memory()
        self.rega, self.regb, self.regc, self.regd = 0, 0, 0, 0
        self.pointer = init_pointer
        self.is_running = False

    def preload_program(self, inst_list):
        for address, inst in inst_list:
            if inst["code"] == ".data":
                a, b, c, d = inst["data"]
                self.memory.preload_data(address, a, b, c, d)
            else:
                self.memory.preload_instruction(address, inst)

    def run(self):
        self.is_running = True
        while self.is_running:
            inst = self.memory.load_instruction(self.pointer)
            self.pointer += INST_SIZE
            code, operand = inst["code"], inst.get("operand", None)
            if code == "shiftl":
                self.rega = (self.rega << operand) & (2 ** 64 - 1)
            elif code == "imm16":
                self.rega = self.rega & ~0xFFFF | operand
            elif code == "storeb":
                self.regb = self.rega
            elif code == "storec":
                self.regc = self.rega
            elif code == "int":
                self.interrupt(operand)
            else:
                raise RuntimeError(f"unkown instruction code {code}")

    def interrupt(self, kind):
        if kind == 0:
            self.is_running = False
            # TODO save exit code
        elif kind == 1:
            raise NotImplementedError()
        elif kind == 2:
            descriptor, address, length = self.rega, self.regb, self.regc
            if descriptor != 0:
                raise NotImplementedError()
            slice = self.memory.get_slice(address, length)
            print(bytes(slice).decode(), end="")


def parse_program(source):
    address = None
    for line in source:
        line = line.split(";")[0].strip()
        if len(line) == 0:
            continue
        if line.startswith("0x"):
            address = int(line, base=16)
            continue

        if len(line.split()) == 1:
            inst = {"code": line}
        elif line.split()[0] == ".data":
            _, a, b, c, d = line.split()
            inst = {
                "code": ".data",
                "data": (
                    int(a, base=16),
                    int(b, base=16),
                    int(c, base=16),
                    int(d, base=16),
                ),
            }
        else:
            code, operand = line.split()
            inst = {"code": code, "operand": int(operand, base=16)}

        # TODO verify instruction

        assert address is not None, "not specify address for first instruction"
        yield address, inst
        address += INST_SIZE


if __name__ == "__main__":
    computer = Computer(0x2000)
    with open(argv[1]) as source_file:
        program = parse_program(source_file)
        computer.preload_program(program)
    computer.run()
