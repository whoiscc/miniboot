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
from json import loads as unquote


SEGMENT_SIZE = 2 ** 24
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

    def set_slice(self, offset, slice):
        assert offset + len(slice) <= PAGE_SIZE
        self.mem[offset : offset + len(slice)] = slice

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

    def set_slice(self, offset, slice):
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

    def set_slice(self, address, slice):
        page_index, page_offset = address // PAGE_SIZE, address % PAGE_SIZE
        while len(slice) > 0:
            assert (
                page_index in self.page_table
            ), f"segmentation fault: {page_index * PAGE_SIZE:#x}"
            self.page_table[page_index].set_slice(
                page_offset, slice[: PAGE_SIZE - page_offset]
            )
            slice = slice[PAGE_SIZE - page_offset :]
            page_index += 1
            page_offset = 0

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
        self.next_alloc = 0 + 1 * SEGMENT_SIZE
        self.exit_code = None
        self.nb_inst = 0
        self.nb_data = 0

    def preload_program(self, inst_list):
        for address, inst in inst_list:
            if inst["code"] == ".data":
                a, b, c, d = inst["data"]
                self.memory.preload_data(address, a, b, c, d)
                self.nb_data += 4
            else:
                self.memory.preload_instruction(address, inst)
                self.nb_inst += 1

            self.next_alloc = max(
                self.next_alloc, SEGMENT_SIZE * (address // SEGMENT_SIZE + 1)
            )

    def open_file(self, descriptor, file_type, path):
        if file_type == "readfile":
            file = open(path, mode="rb")
        elif file_type == "writefile":
            file = open(path, mode="wb")
        elif file_type == "appendfile":
            file = open(path, mode="ab")
        elif file_type == "socket":
            raise NotImplementedError()
        else:
            raise RuntimeError(f"unsupported file type: {file_type}")
        self.descriptor_table[descriptor] = file

    def summary(self):
        return {
            "Total page number": len(self.memory.page_table),
            "Protected page number": sum(
                1
                for page in self.memory.page_table.values()
                if isinstance(page, ProtectedPage)
            ),
            "Instruction number": self.nb_inst,
            "Data size (bytes)": self.nb_data,
            "Next allocate address": f"{self.next_alloc:#x}",
            "Exit code": self.exit_code,
        }

    def run(self):
        self.is_running = True
        while self.is_running:
            inst = self.memory.load_instruction(self.pointer)
            assert inst is not None, f"illegal instruction access at {self.pointer:#x}"
            self.pointer += INST_SIZE
            # print(
            #     f"A: {self.rega:#12x} B: {self.regb:#12x} "
            #     f"C: {self.regc:#12x} D: {self.regd:#12x}"
            # )
            # print(inst)
            code, operand = inst["code"], inst.get("operand", None)
            if code == "imm":
                self.rega -= self.rega % (2 ** 24)
                self.rega += operand
            elif code == "ldb":
                self.rega = self.regb
            elif code == "ldc":
                self.rega = self.regc
            elif code == "ldd":
                self.rega = self.regd
            elif code == "stb":
                self.regb = self.rega
            elif code == "stc":
                self.regc = self.rega
            elif code == "std":
                self.regd = self.rega
            elif code == "ld":
                address = self.regb
                assert address % 8 == 0, "ld address not align to 8"
                slice = self.memory.get_slice(address, 8)
                self.rega = sum(slice[i] * (2 ** (i * 8)) for i in range(8))
            elif code == "st64":
                data, address = self.rega, self.regb
                assert address % 8 == 0, "st64 address not align to 8"
                slice = [data // (2 ** (i * 8)) % (2 ** 8) for i in range(8)]
                self.memory.set_slice(address, slice)

            elif code == "shl":
                self.rega %= 2 ** (64 - operand)
                self.rega *= 2 ** operand
            elif code == "add":
                self.rega += self.regb
                self.rega %= 2 ** 64
            elif code == "neg":
                self.rega = -self.rega

            elif code == "jmp":
                self.pointer = self.regb
            elif code == "int":
                self.interrupt(operand)
            else:
                raise RuntimeError(f"illegal instruction: {code}")

    def interrupt(self, opcode):
        if opcode == 0:
            self.is_running = False
            self.exit_code = self.rega
        elif opcode == 1:
            raise NotImplementedError()
        elif opcode == 2:
            nb_page = self.rega
            self.regb = self.next_alloc
            for _ in range(nb_page):
                self.memory.touch_page(self.next_alloc // PAGE_SIZE, False)
                self.next_alloc += PAGE_SIZE
        elif opcode == 3:
            max_length, address, desc = self.rega, self.regb, self.regc
            if "b" not in self.descriptor_table[desc].mode:
                raise NotImplementedError()
            slice = self.descriptor_table[desc].read(max_length)
            self.memory.set_slice(address, list(slice))
            self.rega = len(slice)
        elif opcode == 4:
            length, address, desc = self.rega, self.regb, self.regc
            slice = bytes(self.memory.get_slice(address, length))
            self.descriptor_table[desc].write(
                "b" in self.descriptor_table[desc].mode and slice or slice.decode()
            )
            # update %A if not write all
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

        assert address is not None, "not specify address for first instruction"
        code, *operand = [s.strip() for s in line.split(maxsplit=1)]
        if code.startswith("$"):
            for inst in expand_macro(code, operand and operand[0], address):
                yield address, inst
                address += INST_SIZE
        else:
            if code == ".data":
                a, b, c, d = [int(x, base=16) for x in operand[0].split()]
                inst = {
                    "code": ".data",
                    "data": (a, b, c, d),
                }
            elif len(operand) == 0:
                inst = {"code": line}
            else:
                inst = {"code": code, "operand": int(operand[0], base=16)}

            # TODO verify instruction
            yield address, inst
            address += INST_SIZE


def expand_macro(code, operand, address):
    if code == "$.str":
        byte_list = list(unquote(operand).encode()) + [0] * 4
        return [
            {
                "code": ".data",
                "data": (
                    byte_list[i + 0],
                    byte_list[i + 1],
                    byte_list[i + 2],
                    byte_list[i + 3],
                ),
            }
            for i in range(0, len(byte_list) - 4, 4)
        ]
    if code == "$ret":
        return [
            {"code": "ldd"},
            {"code": "stb"},
            {"code": "shl", "operand": 64},
            {"code": "imm", "operand": 8},
            {"code": "neg"},
            {"code": "add"},
            {"code": "stb"},
            {"code": "ld"},
            {"code": "stb"},
            {"code": "jmp"},
        ]
    if code == "$call":
        target = int(operand, base=16)
        imm_inst = {"code": "imm", "operand": "?"}
        inst_list = [
            {"code": "ldd"},
            {"code": "stb"},
            {"code": "shl", "operand": 64},
            {"code": "imm", "operand": 248},
            {"code": "add"},
            {"code": "stb"},
            {"code": "shl", "operand": 64},
            imm_inst,
            {"code": "st64"},
            {"code": "ldd"},
            {"code": "stb"},
            {"code": "shl", "operand": 64},
            {"code": "imm", "operand": 256},
            {"code": "add"},
            {"code": "std"},
            {"code": "shl", "operand": 64},
            {"code": "imm", "operand": target},
            {"code": "stb"},
            {"code": "jmp"},
        ]
        imm_inst["operand"] = address + len(inst_list) * INST_SIZE
        return inst_list + [
            {"code": "ldd"},
            {"code": "stb"},
            {"code": "shl", "operand": 64},
            {"code": "imm", "operand": 256},
            {"code": "neg"},
            {"code": "add"},
            {"code": "std"},
        ]
    if code == "$lds":
        offset = int(operand, base=16)
        return [
            {"code": "ldd"},
            {"code": "add"},
            {"code": "stb"},
            {"code": "shl", "operand": 64},
            {"code": "imm", "operand": offset},
            {"code": "add"},
            {"code": "stb"},
            {"code": "ld"},
        ]
    if code.startswith("$sts"):
        assert code in {"$sts8", "$sts16", "$sts32", "$sts64"}
        offset = int(operand, base=16)
        return [
            {"code": "stc"},
            {"code": "ldd"},
            {"code": "add"},
            {"code": "stb"},
            {"code": "shl", "operand": 64},
            {"code": "imm", "operand": offset},
            {"code": "add"},
            {"code": "stb"},
            {"code": "ldc"},
            {"code": code.replace("$sts", "st")},
        ]

    raise RuntimeError(f"unknown macro: {code}")


def print_summary(summary, items):
    for item, value in summary.items():
        if item not in items:
            continue
        print(f"* {item:24}: {value}")


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
    print("** SUMMARY")
    print_summary(
        computer.summary(),
        {
            "Total page number",
            "Protected page number",
            "Instruction number",
            "Data size (bytes)",
            "Next allocate address",
        },
    )

    print("** PROGRAM START")
    computer.run()

    print("** PROGRAM END")
    print_summary(
        computer.summary(),
        {
            "Total page number",
            "Next allocate address",
            "Exit code",
        },
    )
