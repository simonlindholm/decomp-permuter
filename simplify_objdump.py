#!/usr/bin/env python3
import sys
import re
import string

ign_regs = False
ign_branch_targets = True
num_re = re.compile(r'[0-9]+')
comments = re.compile(r'<.*?>')
regs = re.compile(r'\b(a[0-3]|t[0-9]|s[0-7]|at|v[01])\b')
sprel = re.compile(r',([1-9][0-9]*|0x[1-9a-f][0-9a-f]*)\((sp|s8)\)')
includes_sp = re.compile(r'\b(sp|s8)\b')
forbidden = set(string.ascii_letters + '_')
skip_lines = 1
branch_likely_instructions = [
    'beql', 'bnel', 'beqzl', 'bnezl', 'bgezl', 'bgtzl', 'blezl', 'bltzl',
    'bc1tl', 'bc1fl'
]
branch_instructions = [
    'b', 'beq', 'bne', 'beqz', 'bnez', 'bgez', 'bgtz', 'blez', 'bltz',
    'bc1t', 'bc1f'
] + branch_likely_instructions

def fn(pat):
    full = pat.group(0)
    if len(full) <= 1:
        return full
    start, end = pat.span()
    if start and row[start - 1] in forbidden:
        return full
    if end < len(row) and row[end] in forbidden:
        return full
    return hex(int(full))

def parse_relocated_line(line):
    try:
        ind2 = line.rindex(',')
    except ValueError:
        ind2 = line.rindex('\t')
    before = line[:ind2+1]
    after = line[ind2+1:]
    ind2 = after.find('(')
    if ind2 == -1:
        imm, after = after, ''
    else:
        imm, after = after[:ind2], after[ind2:]
    if imm == '0x0':
        imm = '0'
    return before, imm, after

output = []
nops = 0
for index, row in enumerate(sys.stdin):
    if index < skip_lines:
        continue
    row = row.rstrip()
    if '>:' in row or not row:
        continue
    if 'R_MIPS_' in row:
        prev = output[-1]
        before, imm, after = parse_relocated_line(prev)
        repl = row.split()[-1]
        if imm != '0':
            repl += '+' + imm if int(imm,0) > 0 else imm
        if 'R_MIPS_LO16' in row:
            repl = f'%lo({repl})'
        elif 'R_MIPS_HI16' in row:
            # Ideally we'd pair up R_MIPS_LO16 and R_MIPS_HI16 to generate a
            # correct addend for each, but objdump doesn't give us the order of
            # the relocations, so we can't find the right LO16. :(
            repl = f'%hi({repl})'
        else:
            assert 'R_MIPS_26' in row, f"unknown relocation type '{row}'"
        output[-1] = before + repl + after
        continue
    row = re.sub(comments, '', row)
    row = row.rstrip()
    row = '\t'.join(row.split('\t')[2:]) # [20:]
    if not row:
        continue
    if ign_regs:
        row = re.sub(regs, '<reg>', row)
    row_parts = row.split('\t')
    if len(row_parts) == 1:
        row_parts.append('')
    mnemonic, instr_args = row_parts
    if mnemonic == 'addiu' and includes_sp.search(instr_args):
        row = re.sub(num_re, 'imm', row)
    if mnemonic in branch_instructions:
        if ign_branch_targets:
            instr_parts = instr_args.split(',')
            instr_parts[-1] = '<target>'
            instr_args = ','.join(instr_parts)
            row = f'{mnemonic}\t{instr_args}'
        # The last part is in hex, so skip the dec->hex conversion
    else:
        row = re.sub(num_re, fn, row)
    row = re.sub(sprel, ',addr(sp)', row)
    # row = row.replace(',', ', ')
    if row == 'nop':
        # strip trailing nops; padding is irrelevant to us
        nops += 1
    else:
        for _ in range(nops):
            output.append('nop')
        nops = 0
        output.append(row)

for row in output:
    print(row)
