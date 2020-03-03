#!/usr/bin/env python3
# usage: ./import.py path/to/file.c path/to/asm.s [make flags]
import sys
import os
import re
import subprocess
import shutil
import argparse
import shlex

from strip_other_fns import strip_other_fns_and_write


ASM_PRELUDE = """
.set noat
.set noreorder
.set gp=64
.macro glabel label
    .global \label
    .type \label, @function
    \label:
.endm
"""
DEFAULT_AS_CMDLINE = ["arm-none-eabi-as", "-march=armv4t", "-mthumb-interwork"]


def formatcmd(cmdline):
    return " ".join(shlex.quote(arg) for arg in cmdline)


def parse_asm(asm_file):
    func_name = None
    asm_lines = []
    try:
        with open(asm_file) as f:
            cur_section = ".text"
            for line in f:
                if line.strip().startswith(".section"):
                    cur_section = line.split()[1]
                elif line.strip() in [
                    ".text",
                    ".rdata",
                    ".rodata",
                    ".late_rodata",
                    ".bss",
                    ".data",
                ]:
                    cur_section = line.strip()
                if cur_section == ".text":
                    if func_name is None and line.strip().startswith("glabel "):
                        func_name = line.split()[1]
                    asm_lines.append(line)
    except OSError as e:
        print("Could not open assembly file:", e, file=sys.stderr)
        sys.exit(1)

    if func_name is None:
        print(
            "Missing function name in assembly file! The file should start with 'glabel function_name'.",
            file=sys.stderr,
        )
        sys.exit(1)

    if not re.fullmatch(r"[a-zA-Z0-9_$]+", func_name):
        print(f"Bad function name: {func_name}", file=sys.stderr)
        sys.exit(1)

    return func_name, "".join(asm_lines)


def create_directory(func_name):
    os.makedirs(f"nonmatchings/", exist_ok=True)
    ctr = 0
    while True:
        ctr += 1
        dirname = f"{func_name}-{ctr}" if ctr > 1 else func_name
        dirname = f"nonmatchings/{dirname}"
        try:
            os.mkdir(dirname)
            return dirname
        except FileExistsError:
            pass


def find_makefile_dir(filename):
    old_dirname = None
    dirname = os.path.abspath(os.path.dirname(filename))
    while dirname and (not old_dirname or len(dirname) < len(old_dirname)):
        for fname in ["makefile", "Makefile"]:
            if os.path.isfile(os.path.join(dirname, fname)):
                return dirname
        old_dirname = dirname
        dirname = os.path.dirname(dirname)

    print(f"Missing makefile for file {filename}!", file=sys.stderr)
    sys.exit(1)


def fixup_build_command(parts, ignore_part):
    res = []
    skip_count = 0
    assembler = None
    for part in parts:
        if skip_count > 0:
            skip_count -= 1
            continue
        if part in ["-MF", "-o"]:
            skip_count = 1
            continue
        if part == ignore_part:
            continue
        res.append(part)

    try:
        ind0 = min(
            i
            for i, arg in enumerate(res)
            if any(
                cmd in arg
                for cmd in ["asm_processor", "asm-processor", "preprocess.py"]
            )
        )
        ind1 = res.index("--", ind0 + 1)
        ind2 = res.index("--", ind1 + 1)
        assembler = res[ind1 + 1 : ind2]
        res = res[ind0 + 1 : ind1] + res[ind2 + 1 :]
    except ValueError:
        pass

    return res, assembler


def find_build_command_line(c_file, make_flags):
    makefile_dir = find_makefile_dir(os.path.abspath(os.path.dirname(c_file)))
    rel_c_file = os.path.relpath(c_file, makefile_dir)
    make_cmd = ["make", "--always-make", "--dry-run", "--debug=j"] + make_flags
    debug_output = (
        subprocess.check_output(make_cmd, cwd=makefile_dir).decode("utf-8").split("\n")
    )
    output = []
    close_match = False

    assembler = DEFAULT_AS_CMDLINE
    for line in debug_output:
        while "//" in line:
            line = line.replace("//", "/")
        while "/./" in line:
            line = line.replace("/./", "/")
        if rel_c_file not in line:
            continue
        close_match = True
        parts = shlex.split(line)
        if rel_c_file not in parts:
            continue
        if "-o" not in parts:
            continue
        if "-fsyntax-only" in parts:
            continue
        cmdline, asmproc_assembler = fixup_build_command(parts, rel_c_file)
        if asmproc_assembler:
            assembler = asmproc_assembler
        output.append(cmdline)

    if not output:
        close_extra = (
            "\n(Found one possible candidate, but didn't match due to "
            "either spaces in paths, having -fsyntax-only, or missing an -o flag.)"
            if close_match
            else ""
        )
        print(
            "Failed to find compile command from makefile output. "
            f"Please ensure 'make -Bn --debug=j {formatcmd(make_flags)}' "
            f"contains a line with the string '{rel_c_file}'.{close_extra}",
            file=sys.stderr,
        )
        sys.exit(1)

    if len(output) > 1:
        output_lines = "\n".join(output)
        print(
            f"Error: found multiple compile commands for {rel_c_file}:\n{output_lines}\n"
            "Please modify the makefile such that if PERMUTER = 1, "
            "only a single compile command is included.",
            file=sys.stderr,
        )
        sys.exit(1)

    return output[0], assembler, makefile_dir


def import_c_file(compiler, cwd, in_file):
    in_file = os.path.relpath(in_file, cwd)
    include_next = 0
    cpp_command = ["cpp", "-P"]
    for arg in compiler:
        if include_next > 0:
            include_next -= 1
            cpp_command.append(arg)
            continue
        if arg in ["-D", "-U", "-I"]:
            cpp_command.append(arg)
            include_next = 1
            continue
        if (
            arg.startswith("-D")
            or arg.startswith("-U")
            or arg.startswith("-I")
            or arg in ["-nostdinc"]
        ):
            cpp_command.append(arg)

    cpp_command.extend(
        [
            "-undef",
            "-D__sgi",
            "-D_LANGUAGE_C",
            "-DNON_MATCHING",
            "-D_Static_assert(x, y)=",
            "-D__attribute__(x)=",
        ]
    )
    cpp_command.append(in_file)

    try:
        return subprocess.check_output(cpp_command, cwd=cwd, encoding="utf-8")
    except subprocess.CalledProcessError:
        print(
            "Failed to preprocess input file, when running command:\n"
            + formatcmd(cpp_command),
            file=sys.stderr,
        )
        sys.exit(1)


def write_compile_command(compiler, cwd, out_file):
    with open(out_file, "w") as f:
        f.write("#!/usr/bin/env bash\n")
        f.write('INPUT="$(readlink -f "$1")"\n')
        f.write('OUTPUT="$(readlink -f "$3")"\n')
        f.write(f"cd {shlex.quote(cwd)}\n")
        f.write(formatcmd(compiler) + ' "$INPUT" -o "$OUTPUT"\n')
    os.chmod(out_file, 0o755)


def write_asm(asm_cont, out_file):
    with open(out_file, "w") as f:
        f.write(ASM_PRELUDE)
        f.write(asm_cont)


def compile_asm(assembler, cwd, in_file, out_file):
    in_file = os.path.abspath(in_file)
    out_file = os.path.abspath(out_file)
    cmdline = assembler + [in_file, "-o", out_file]
    try:
        subprocess.check_call(cmdline, cwd=cwd)
    except subprocess.CalledProcessError:
        print(
            f"Failed to assemble .s file, command line:\n{formatcmd(cmdline)}",
            file=sys.stderr,
        )
        sys.exit(1)


def compile_base(compile_script, in_file, out_file):
    in_file = os.path.abspath(in_file)
    out_file = os.path.abspath(out_file)
    compile_cmd = [compile_script, in_file, "-o", out_file]
    try:
        subprocess.check_call(compile_cmd)
    except subprocess.CalledProcessError:
        print(
            "Warning: failed to compile .c file, you'll need to adjust it manually. "
            f"Command line:\n{formatcmd(compile_cmd)}"
        )


def try_strip_other_fns_and_write(source, func_name, base_c_file):
    try:
        strip_other_fns_and_write(source, func_name, base_c_file)
    except Exception:
        trackback.print_exc()
        print(
            "Warning: failed to remove other functions. Edit {base_c_file} and remove them manually."
        )
        with open(base_c_file, "w") as f:
            f.write(source)


def main():
    parser = argparse.ArgumentParser(
        description="Import a function for use with the permuter. "
        "Will create a new directory nonmatchings/<funcname>-<id>/."
    )
    parser.add_argument(
        "c_file",
        help="File containing the function. "
        "Assumes that the file can be built with 'make' to create an .o file.",
    )
    parser.add_argument(
        "asm_file",
        help="File containing assembly for the function. "
        "Must start with 'glabel <function_name>' and contain no other functions.",
    )
    parser.add_argument(
        "make_flags",
        nargs="*",
        help="Arguments to pass to 'make'. PERMUTER=1 will always be passed.",
    )
    parser.add_argument(
        "--keep", action="store_true", help="Keep the directory on error."
    )
    args = parser.parse_args()

    make_flags = args.make_flags + ["PERMUTER=1"]

    func_name, asm_cont = parse_asm(args.asm_file)
    print(f"Function name: {func_name}")

    compiler, assembler, cwd = find_build_command_line(args.c_file, make_flags)
    print(f"Compiler: {formatcmd(compiler)} {{input}} -o {{output}}")
    print(f"Assembler: {formatcmd(assembler)} {{input}} -o {{output}}")

    source = import_c_file(compiler, cwd, args.c_file)

    dirname = create_directory(func_name)
    base_c_file = f"{dirname}/base.c"
    base_o_file = f"{dirname}/base.o"
    target_s_file = f"{dirname}/target.s"
    target_o_file = f"{dirname}/target.o"
    compile_script = f"{dirname}/compile.sh"

    try:
        try_strip_other_fns_and_write(source, func_name, base_c_file)
        write_compile_command(compiler, cwd, compile_script)
        write_asm(asm_cont, target_s_file)
        compile_asm(assembler, cwd, target_s_file, target_o_file)
        compile_base(compile_script, base_c_file, base_o_file)
    except:
        if not parser.keep:
            print(f"\nDeleting directory {dirname} (run with --keep to preserve it).")
            shutil.rmtree(dirname)
        raise

    print(f"\nDone. Imported into {dirname}")


if __name__ == "__main__":
    main()
