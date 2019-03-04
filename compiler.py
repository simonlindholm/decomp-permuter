from typing import Optional
import tempfile
import subprocess
import os

class Compiler:
    def __init__(self, compile_cmd: str, display_errors: bool=False) -> None:
        self.compile_cmd = compile_cmd
        self.display_errors = display_errors

    def compile(self, source: str) -> Optional[str]:
        with tempfile.NamedTemporaryFile(prefix='permuter', suffix='.c', mode='w', delete=False) as f:
            c_name = f.name
            f.write(source)

        with tempfile.NamedTemporaryFile(prefix='permuter', suffix='.o', delete=False) as f:
            o_name = f.name

        try:
            stderr = None if self.display_errors else subprocess.DEVNULL
            subprocess.check_call(self.compile_cmd + " " + c_name + " -o " + o_name, shell=True, stderr=stderr)
        except subprocess.CalledProcessError:
            if not self.display_errors:
                os.remove(c_name)
            return None

        os.remove(c_name)
        return o_name
