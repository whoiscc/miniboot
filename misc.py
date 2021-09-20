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

**`.data`**
Special pseudo instruction, define 32 bits of data located in the address of 
itself, which will be written into memory before execution. Take 4 immediate 
numbers, each should be 8 bits. `.data` and instruction cannot exist in the same 
page, and `.data` page can be accessed during execution.

**Insturctions.**
See `Computer.run` for their functions.

"""
from sys import argv, stdin, stdout, stderr
from configparser import ConfigParser


PAGE_SIZE = 2 ** 12
INST_SIZE = 4


class Page:
    def __init__(self, start):
        self.mem = [0] * PAGE_SIZE
        self.start = start

    def preload_data(self, offset, a, b, c, d):
        assert offset % 4 == 0, f"preload data not align to 4: {self.start + offset:#x}"
        self.mem[offset + 0] = a
        self.mem[offset + 1] = b
        self.mem[offset + 2] = c
        self.mem[offset + 3] = d

    def preload_instruction(self, offset, inst):
        raise RuntimeError(
            f"cannot preload instruction into unprotected page: {self.start + offset:#x}"
        )

    def get_slice(self, offset, length):
        return self.mem[offset : offset + length]

    def load_instruction(self, offset):
        raise RuntimeError(
            f"cannot load instruction from unprotectecd page: {self.start + offset:#x}"
        )


class ProtectedPage:
    def __init__(self, start):
        self.mem = [None] * (PAGE_SIZE // INST_SIZE)
        self.start = start

    def preload_data(self, offset, a, b, c, d):
        raise RuntimeError(
            f"cannot preload data into protected page: {self.start + offset:#x}"
        )

    def preload_instruction(self, offset, inst):
        assert (
            offset % INST_SIZE == 0
        ), f"instruction address not align to {INST_SIZE}: {self.start + offset:#x}"
        index = offset // INST_SIZE
        assert (
            self.mem[index] is None
        ), f"override instruction at {self.start + offset:#x}"
        self.mem[index] = inst

    def get_slice(self, offset, length):
        raise RuntimeError(
            f"illegal access to protected page: {self.start + offset:#x}"
        )

    def load_instruction(self, offset):
        assert (
            offset % INST_SIZE == 0
        ), f"instruction address not align to {INST_SIZE}: {self.start + offset:#x}"
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
            assert (
                page_index in self.page_table
            ), f"segmentation fault: {page_index * PAGE_SIZE:#x}"
            slice += self.page_table[page_index].get_slice(
                page_offset, length - len(slice)
            )
            page_index += 1
            page_offset = 0
        return slice

    def load_instruction(self, address):
        page_index, page_offset = address // PAGE_SIZE, address % PAGE_SIZE
        assert page_index in self.page_table, f"segmentation fault: {address:#x}"
        return self.page_table[page_index].load_instruction(page_offset)


class Computer:
    def __init__(self):
        self.memory = Memory()
        self.rega, self.regb, self.regc, self.regd = 0, 0, 0, 0
        self.pointer = 0x400000
        self.is_running = False
        self.descriptor_table = {0: stdin, 1: stdout, 2: stderr}

    def preload_program(self, inst_list):
        for address, inst in inst_list:
            if inst["code"] == ".data":
                a, b, c, d = inst["data"]
                self.memory.preload_data(address, a, b, c, d)
            else:
                self.memory.preload_instruction(address, inst)

    def open_file(self, descriptor, file_type, path):
        if file_type == "infile":
            file = open(path, mode="r")
        elif file_type == "outfile":
            file = open(path, mode="w")
        elif file_type == "socket":
            raise NotImplementedError()
        else:
            raise RuntimeError(f"unsupported file type: {file_type}")
        self.descriptor_table[descriptor] = file

    def run(self):
        self.is_running = True
        while self.is_running:
            inst = self.memory.load_instruction(self.pointer)
            assert inst is not None, f"illegal instruction access at {self.pointer:#x}"
            self.pointer += INST_SIZE
            code, operand = inst["code"], inst.get("operand", None)
            if code == "shiftl":
                self.rega %= 2 ** (64 - operand)
                self.rega *= 2 ** operand
            elif code == "imm":
                self.rega -= self.rega % (2 ** 24)
                self.rega += operand
            elif code == "storeb":
                self.regb = self.rega
            elif code == "storec":
                self.regc = self.rega
            elif code == "int":
                self.interrupt(operand)
            else:
                raise RuntimeError(f"illegal instruction: {code}")

    def interrupt(self, opcode):
        if opcode == 0:
            self.is_running = False
            # TODO save exit code
        elif opcode == 1:
            raise NotImplementedError()
        elif opcode == 2:
            desc, address, length = self.rega, self.regb, self.regc
            slice = self.memory.get_slice(address, length)
            self.descriptor_table[desc].write(bytes(slice).decode())
        else:
            raise RuntimeError(f"illegal interrupt operation: {opcode}")


def parse_program(source):
    address = None
    for line in source:
        line = line.split(";")[0].strip()
        if len(line) == 0:
            continue

        if line.startswith("0x"):
            address = int(line, base=16)
            continue

        if line.split()[0] == ".data":
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
        elif len(line.split()) == 1:
            inst = {"code": line}
        else:
            code, operand = line.split()
            inst = {"code": code, "operand": int(operand, base=16)}

        # TODO verify instruction

        assert address is not None, "not specify address for first instruction"
        yield address, inst
        address += INST_SIZE


if __name__ == "__main__":
    cfg = ConfigParser()
    cfg.read(argv[1])
    computer = Computer()
    for source_path in cfg["program"]["sources"].splitlines():
        source_path = source_path.strip()
        if len(source_path) == 0:
            continue
        with open(source_path) as source:
            prog = parse_program(source)
            computer.preload_program(prog)
    for key, section in cfg.items():
        if key in {"DEFAULT", "program"}:
            continue
        if key.startswith("descriptor"):
            _, desc = key.split(".")
            desc = int(desc, base=16)
            computer.open_file(desc, section["type"], section["path"])

    computer.run()
