import os
import re
import shlex
import subprocess
import tempfile
from typing import List, Optional


def preprocess(filename: str, cpp_args: List[str] = [], directory: Optional[str] = None) -> str:
    # Kero-local patch: this project only ships MWCC (mwcceppc.exe), not a
    # standalone `cpp`/gcc-style preprocessor, so the upstream `cpp -P`
    # invocation below never resolves on Windows. When `directory` is given
    # and it holds an MWCC-flavored compile.sh (as written by
    # tools/permuter_new.py), reuse that same compiler + flags with `-EP`
    # (MWCC's "preprocess and strip #line directives" mode, the closest
    # equivalent to cpp's `-P`) instead.
    if directory is not None:
        mwcc_pp = _mwcc_preprocess(filename, directory)
        if mwcc_pp is not None:
            return mwcc_pp
    return subprocess.check_output(
        ["cpp"] + cpp_args + ["-P", "-nostdinc", "-DPERMUTER", filename],
        universal_newlines=True,
        encoding="utf-8",
    )


def _mwcc_preprocess(filename: str, directory: str) -> Optional[str]:
    compile_sh = os.path.join(directory, "compile.sh")
    if not os.path.isfile(compile_sh):
        return None
    with open(compile_sh, encoding="utf-8") as f:
        script = f.read()
    if "mwcceppc" not in script:
        return None

    mwcc_match = re.search(r'MWCC="([^"]+)"', script)
    if not mwcc_match:
        return None
    # project_root is 3 levels up from a permuter_work/<func> compile.sh
    # (see tools/permuter_new.py's `cd "$(dirname "$0")/../../.."`), so the
    # relative MWCC path in the script is relative to that root, not to cwd.
    project_root = os.path.abspath(os.path.join(directory, "..", "..", ".."))
    mwcc_exe = os.path.join(project_root, mwcc_match.group(1))
    if not os.path.isfile(mwcc_exe):
        return None

    # The shared flag block sits between the `"$MWCC"` invocation and the
    # trailing `-c "$IN" -o "$OUT"` - grab it verbatim so this stays in sync
    # with whatever tools/permuter_new.py generates, rather than
    # re-hardcoding the flag list a second time here.
    flags_match = re.search(r'"\$MWCC"\s*(.*?)\s*-c "\$IN" -o "\$OUT"', script, re.DOTALL)
    if not flags_match:
        return None
    # Line-continuation backslashes may be followed by \r\n (git autocrlf can
    # convert compile.sh to CRLF on checkout) - strip the backslash plus
    # whatever line ending follows it before doing a shell-aware split, so
    # quoted multi-word args like `-pragma "cats off"` survive as one token.
    flag_text = re.sub(r"\\\r?\n", " ", flags_match.group(1))
    # The regex boundary above can strand a trailing continuation backslash
    # with no newline left to match (the `\s*` just before `-c` in the outer
    # pattern already consumed it) - drop any leftover trailing backslash.
    flag_text = re.sub(r"\\\s*$", "", flag_text)
    flags = shlex.split(flag_text)

    with tempfile.NamedTemporaryFile(suffix=".i", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        subprocess.run(
            [mwcc_exe] + flags + ["-DPERMUTER", "-EP", os.path.abspath(filename), "-o", tmp_path],
            check=True,
            cwd=project_root,
            capture_output=True,
        )
        with open(tmp_path, encoding="utf-8") as f:
            return f.read()
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
