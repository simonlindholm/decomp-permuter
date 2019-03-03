import perm
import re

perm_create = {
    'PERM_GENERAL' : lambda args : perm.GeneralPerm(*args),
    'PERM_RANDOMIZE' : lambda args : perm.RandomizerPerm(*args),
}

def get_parenthesis_args(s):
    level = 0
    current = ''
    remain = ''
    args = []
    for i, c in enumerate(s):
        # Find individual args
        if c == ',' and level == 1:
            args.append(current)
            current = ''
        # Track parenthesis level
        else:
            if c == '(':
                level += 1
                if level == 1: # Ignore first parenthesis
                    continue
            elif c == ')':
                level -= 1
                if level == 0: # Last closing parenthesis; get remaining and finish
                    args.append(current)
                    if i + 1 < len(s):
                        remain = s[i+1:]
                    break
            current += c
    assert(level == 0, "Error, no closing parenthesis found")
    return args, remain

def perm_gen(input):
    remain = input
    head_perm = None
    cur_perm = None
    
    def append_perm(p):
        nonlocal head_perm, cur_perm
        if head_perm == None:
            head_perm = p
        else:
            cur_perm.next_perm = p

        cur_perm = p

    while len(remain) > 0:
        match = re.search(r'(PERM_.+?)\(', remain)

        # No match found; return remaining
        if match == None:
            text_perm = perm.TextPerm(remain)
            append_perm(text_perm)
            break

        # Get perm type and args
        perm_type = match.group(1)
        if not perm_type in perm_create:
            raise 'Could not evaluate expression:' + perm_type
        text = remain[:match.start()]
        args, remain = get_parenthesis_args(remain[match.end() - 1:])

        # Create text perm
        if text != '':
            text_perm = perm.TextPerm(text)
            append_perm(text_perm)
        
        # Create new perm
        new_perm = perm_create[perm_type](args)
        append_perm(new_perm)

    return head_perm
