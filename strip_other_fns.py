import sys
import re
from pathlib import Path

def _find_bracket_end(input):
    level = 1
    i = 1
    assert(input[0] == '{')
    while i < len(input):
        if input[i] == '{':
            level += 1
        elif input[i] == '}':
            level -= 1
            if level == 0:
                break
        i += 1
    
    return i

def strip_other_fns(source, keep_fn_name):
    result = ''
    remain = source
    while True:
        fn_regex = re.compile(r'^.*\s+(\w+)\(.*\)\s*?{', re.M)
        fn = re.search(fn_regex, remain)
        if fn == None:
            result += remain
            remain = ''
            break

        fn_name = fn.group(1)
        bracket_end = (fn.end() - 1) + _find_bracket_end(remain[fn.end() - 1:])
        if fn_name == keep_fn_name:
            result += remain[:bracket_end+1]
        else:
            result += remain[:fn.start()]
        
        remain = remain[bracket_end+1:]

    return result

def strip_other_fns_and_write(source, fn_name, out_name = None):
    if out_name == None:
        out_name = filename

    stripped = strip_other_fns(source, fn_name)

    with open(out_name, 'w') as f:
        f.write(stripped)

if __name__ == "__main__":
    filename = sys.argv[1]
    fn_name = sys.argv[2]
    
    source = Path(filename).read_text()
    strip_other_fns_and_write(source, fn_name)
    pass
