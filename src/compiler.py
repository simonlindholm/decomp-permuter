from typing import Optional
import tempfile
import subprocess
import shutil

from .helpers import try_remove


class Compiler:
    def __init__(
        self, compile_cmd: str, *, show_errors: bool, debug_mode: bool
    ) -> None:
        self.compile_cmd = compile_cmd
        self.show_errors = show_errors
        self.debug_mode = debug_mode

    def compile(self, source: str, *, show_errors: bool = False) -> Optional[str]:
        """Try to compile a piece of C code. Returns the filename of the resulting .o
        temp file if it succeeds."""
        show_errors = show_errors or self.show_errors or self.debug_mode
        with tempfile.NamedTemporaryFile(
            prefix="permuter", suffix=".c", mode="w", delete=False
        ) as f:
            c_name = f.name
            f.write(source)

        if self.debug_mode:
            debug_filepath = "./debug_source.c"
            print(
                "DEBUG MODE: Saving a full copy of base candidate source to ",
                debug_filepath,
            )
            with open(debug_filepath, "w") as f_copy:
                f_copy.write(source)

        with tempfile.NamedTemporaryFile(
            prefix="permuter", suffix=".o", delete=False
        ) as f2:
            o_name = f2.name

        try:
            stderr = 2 if show_errors else subprocess.DEVNULL
            subprocess.check_call(
                [self.compile_cmd, c_name, "-o", o_name],
                stdout=stderr,
                stderr=stderr,
            )
        except subprocess.CalledProcessError:
            if not show_errors:
                try_remove(c_name)
            try_remove(o_name)
            return None
        except KeyboardInterrupt:
            # If Ctrl+C happens during this call, make a best effort in
            # removing the .c and .o files. This is totally racy, but oh well...
            try_remove(c_name)
            try_remove(o_name)
            raise

        if self.debug_mode:
            debug_filepath = "./debug_compiled_object.o"
            print(
                "DEBUG MODE: Saving the base candidate o file to ", debug_filepath, "\n"
            )
            shutil.copyfile(o_name, debug_filepath)

        try_remove(c_name)
        return o_name
