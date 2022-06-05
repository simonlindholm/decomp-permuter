#!/usr/bin/env python3
from dataclasses import dataclass, field
import os
import re
import string
import subprocess
import sys
from typing import List, Match, Pattern, Set, Tuple, Optional


# Ignore registers, for cleaner output. (We don't do this right now, but it can
# be useful for debugging.)
ign_regs = False

# Don't include branch targets in the output. Assuming our input is semantically
# equivalent skipping it shouldn't be an issue, and it makes insertions have too
# large effect.
ign_branch_targets = True

# Skip branch-likely delay slots. (They aren't interesting on IDO.)
skip_bl_delay_slots = True

skip_lines = 1
re_int = re.compile(r"[0-9]+")
re_int_full = re.compile(r"\b[0-9]+\b")


@dataclass
class Line:
    row: str
    mnemonic: str
    has_symbol: bool


@dataclass
class ArchSettings:
    name: str
    objdump: List[str]
    re_comment: Pattern[str]
    re_reg: Pattern[str]
    re_sprel: Pattern[str]
    re_includes_sp: Pattern[str]
    reloc_str: str
    branch_instructions: Set[str]
    forbidden: Set[str] = field(default_factory=lambda: set(string.ascii_letters + "_"))
    branch_likely_instructions: Set[str] = field(default_factory=set)


MIPS_BRANCH_LIKELY_INSTRUCTIONS = {
    "beql",
    "bnel",
    "beqzl",
    "bnezl",
    "bgezl",
    "bgtzl",
    "blezl",
    "bltzl",
    "bc1tl",
    "bc1fl",
}
MIPS_BRANCH_INSTRUCTIONS = {
    "b",
    "j",
    "beq",
    "bne",
    "beqz",
    "bnez",
    "bgez",
    "bgtz",
    "blez",
    "bltz",
    "bc1t",
    "bc1f",
}.union(MIPS_BRANCH_LIKELY_INSTRUCTIONS)

PPC_BRANCH_INSTRUCTIONS = {
    "b",
    "beq",
    "beq+",
    "beq-",
    "bne",
    "bne+",
    "bne-",
    "blt",
    "blt+",
    "blt-",
    "ble",
    "ble+",
    "ble-",
    "bdnz",
    "bdnz+",
    "bdnz-",
    "bge",
    "bge+",
    "bge-",
    "bgt",
    "bgt+",
    "bgt-",
}

PPC_BRANCH_LIKELY_INSTRUCTIONS: Set[str] = set()

MIPS_SETTINGS: ArchSettings = ArchSettings(
    name="mips",
    re_comment=re.compile(r"<.*?>"),
    re_reg=re.compile(
        r"\$?\b(a[0-3]|t[0-9]|s[0-8]|at|v[01]|f[12]?[0-9]|f3[01]|k[01]|fp|ra)\b"  # leave out $zero
    ),
    re_sprel=re.compile(r"(?<=,)([0-9]+|0x[0-9a-f]+)\((sp|s8)\)"),
    re_includes_sp=re.compile(r"\b(sp|s8)\b"),
    reloc_str="R_MIPS_",
    objdump=["mips-linux-gnu-objdump", "-drz", "-m", "mips:4300"],
    branch_likely_instructions=MIPS_BRANCH_LIKELY_INSTRUCTIONS,
    branch_instructions=MIPS_BRANCH_INSTRUCTIONS,
)


PPC_SETTINGS: ArchSettings = ArchSettings(
    name="ppc",
    re_includes_sp=re.compile(r"\b(r1)\b"),
    re_comment=re.compile(r"(<.*>|//.*$)"),
    re_reg=re.compile(r"\$?\b([rf][0-9]+)\b"),
    re_sprel=re.compile(r"(?<=,)(-?[0-9]+|-?0x[0-9a-f]+)\(r1\)"),
    reloc_str="R_PPC_",
    objdump=["powerpc-eabi-objdump", "-dr", "-EB", "-mpowerpc", "-M", "broadway"],
    branch_instructions=PPC_BRANCH_INSTRUCTIONS,
    branch_likely_instructions=PPC_BRANCH_LIKELY_INSTRUCTIONS,
)


def get_arch(o_file: str) -> ArchSettings:
    # https://refspecs.linuxfoundation.org/elf/gabi4+/ch4.eheader.html
    with open(o_file, "rb") as f:
        data = f.read(20)
    if data[5] == 2:
        arch = (data[18] << 8) + data[19]
    else:
        arch = (data[19] << 8) + data[18]
    if arch == 8:
        return MIPS_SETTINGS
    if arch == 20:
        return PPC_SETTINGS
    # TODO: support ARM (0x28)
    raise Exception("Bad ELF")


def parse_relocated_line(line: str) -> Tuple[str, str, str]:
    for c in ",\t ":
        if c in line:
            ind2 = line.rindex(c)
            break
    else:
        raise Exception(f"failed to parse relocated line: {line}")
    before = line[: ind2 + 1]
    after = line[ind2 + 1 :]
    ind2 = after.find("(")
    if ind2 == -1:
        imm, after = after, ""
    else:
        imm, after = after[:ind2], after[ind2:]
    if imm == "0x0":
        imm = "0"
    return before, imm, after


def pre_process(mnemonic: str, args: str, next_row: Optional[str]) -> Tuple[str, str]:

    if next_row and "R_PPC_EMB_SDA21" in next_row:
        # With sda21 relocs, the linker transforms `r0` into `r2`/`r13`, and
        # we may encounter this in either pre-transformed or post-transformed
        # versions depending on if the .o file comes from compiler output or
        # from disassembly. Normalize, to make sure both forms are treated as
        # equivalent.
        args = args.replace("(r2)", "(0)")
        args = args.replace("(r13)", "(0)")
        args = args.replace(",r2,", ",0,")
        args = args.replace(",r13,", ",0,")

        # We want to convert li and lis with an sda21 reloc,
        # because the r0 to r2/r13 transformation results in
        # turning an li/lis into an addi/addis with r2/r13 arg
        # our preprocessing normalizes all versions to addi with a 0 arg

        if mnemonic in {"li", "lis"}:
            mnemonic = mnemonic.replace("li", "addi")
            args_parts = args.split(",")
            args = args_parts[0] + ",0," + args_parts[1]

    return mnemonic, args


def process_reloc(reloc_row: str, prev: str) -> Optional[str]:
    if prev == "<skipped>":
        return None

    before, imm, after = parse_relocated_line(prev)
    repl = reloc_row.split()[-1]
    # As part of ignoring branch targets, we ignore relocations for j
    # instructions. The target is already lost anyway.
    if imm == "<target>":
        assert ign_branch_targets
        return None

    if "R_PPC_" in reloc_row:

        assert any(
            r in reloc_row for r in ["R_PPC_REL24", "R_PPC_ADDR16", "R_PPC_EMB_SDA21"]
        ), f"unknown relocation type '{reloc_row}' for line '{prev}'"

        if "R_PPC_REL24" in reloc_row:
            # function calls
            pass
        elif "R_PPC_ADDR16_HI" in reloc_row:
            # absolute hi of addr
            repl = f"{repl}@h"
        elif "R_PPC_ADDR16_HA" in reloc_row:
            # adjusted hi of addr
            repl = f"{repl}@ha"
        elif "R_PPC_ADDR16_LO" in reloc_row:
            # lo of addr
            repl = f"{repl}@l"
        elif "R_PPC_ADDR16" in reloc_row:
            # 16-bit absolute addr
            if "+0x7" in repl:
                # remove the very large addends as they are an artifact of (label-_SDA(2)_BASE_)
                # computations and are unimportant in a diff setting.
                if int(repl.split("+")[1], 16) > 0x70000000:
                    repl = repl.split("+")[0]
        elif "R_PPC_EMB_SDA21" in reloc_row:
            # sda21 relocations; r2/r13 --> 0 swaps are performed in an earlier processing step
            repl = f"{repl}@sda21"

        return before + repl + after

    if "R_MIPS_" in reloc_row:
        # Sometimes s8 is used as a non-framepointer, but we've already lost
        # the immediate value by pretending it is one. This isn't too bad,
        # since it's rare and applies consistently. But we do need to handle it
        # here to avoid a crash, by pretending that lost imms are zero for
        # relocations.
        if imm != "0" and imm != "imm" and imm != "addr":
            repl += "+" + imm if int(imm, 0) > 0 else imm
        if any(
            reloc in reloc_row
            for reloc in ["R_MIPS_LO16", "R_MIPS_LITERAL", "R_MIPS_GPREL16"]
        ):
            repl = f"%lo({repl})"
        elif "R_MIPS_HI16" in reloc_row:
            # Ideally we'd pair up R_MIPS_LO16 and R_MIPS_HI16 to generate a
            # correct addend for each, but objdump doesn't give us the order of
            # the relocations, so we can't find the right LO16. :(
            repl = f"%hi({repl})"
        else:
            assert "R_MIPS_26" in reloc_row, f"unknown relocation type '{reloc_row}'"
        return before + repl + after

    raise Exception(f"unknown relocation type: {reloc_row}")


def simplify_objdump(
    input_lines: List[str], arch: ArchSettings, *, stack_differences: bool
) -> List[Line]:
    output_lines: List[Line] = []
    nops = 0
    skip_next = False
    for index, row in enumerate(input_lines):
        if index < skip_lines:
            continue
        row = row.rstrip()
        if ">:" in row or not row:
            continue

        row = re.sub(arch.re_comment, "", row)
        row = row.rstrip()
        row = "\t".join(row.split("\t")[2:])  # [20:]
        if not row:
            continue

        if "\t" in row:
            row_parts = row.split("\t", 1)
        else:
            # powerpc-eabi-objdump doesn't use tabs
            row_parts = [part.lstrip() for part in row.split(" ", 1)]

        mnemonic = row_parts[0].strip()
        args = row_parts[1].strip() if len(row_parts) >= 2 else ""

        next_line = input_lines[index + 1] if index + 1 < len(input_lines) else None
        mnemonic, args = pre_process(mnemonic, args, next_line)
        row = mnemonic + "\t" + args.replace("\t", "  ")

        if arch.reloc_str in row:
            # Process Relocations, modify the previous line and do not add this line to output
            modified_prev = process_reloc(row, output_lines[-1].row)
            if modified_prev:
                output_lines[-1].row = modified_prev
                output_lines[-1].has_symbol = True

            continue

        if skip_next:
            skip_next = False
            row = "<skipped>"
        if ign_regs:
            row = re.sub(arch.re_reg, "<reg>", row)

        if not stack_differences:
            if mnemonic == "addiu" and arch.re_includes_sp.search(args):
                row = re.sub(re_int_full, "imm", row)
        if mnemonic in arch.branch_instructions:
            if ign_branch_targets:
                instr_parts = args.split(",")
                instr_parts[-1] = "<target>"
                args = ",".join(instr_parts)
                row = f"{mnemonic}\t{args}"
            # The last part is in hex, so skip the dec->hex conversion
        else:

            def fn(pat: Match[str]) -> str:
                full = pat.group(0)
                if len(full) <= 1:
                    return full
                start, end = pat.span()
                if start and row[start - 1] in arch.forbidden:
                    return full
                if end < len(row) and row[end] in arch.forbidden:
                    return full
                return hex(int(full))

            row = re.sub(re_int, fn, row)
        if mnemonic in arch.branch_likely_instructions and skip_bl_delay_slots:
            skip_next = True
        if not stack_differences:
            row = re.sub(arch.re_sprel, "addr(sp)", row)
        # row = row.replace(',', ', ')
        if row == "nop":
            # strip trailing nops; padding is irrelevant to us
            nops += 1
        else:
            for _ in range(nops):
                output_lines.append(Line(row="nop", has_symbol=False, mnemonic="nop"))
            nops = 0
            output_lines.append(Line(row=row, has_symbol=False, mnemonic=mnemonic))

    return output_lines


def objdump(
    o_filename: str, arch: ArchSettings, *, stack_differences: bool = False
) -> List[Line]:
    output = subprocess.check_output(arch.objdump + [o_filename])
    lines = output.decode("utf-8").splitlines()
    return simplify_objdump(lines, arch, stack_differences=stack_differences)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} file.o", file=sys.stderr)
        sys.exit(1)

    if not os.path.isfile(sys.argv[1]):
        print(f"Source file {sys.argv[1]} is not readable.", file=sys.stderr)
        sys.exit(1)

    lines = objdump(sys.argv[1], MIPS_SETTINGS)
    for line in lines:
        print(line.row)
