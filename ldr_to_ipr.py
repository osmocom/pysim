#!/usr/bin/python3

from lark import Lark, Transformer, Token, Tree
import sys

from format_ldr import ScriptFormatLDR
from format_ipr import ScriptFormatIPR

def split_hex(value):
    """ split a string of hex digits into groups (bytes) of two digits. """
    return ' '.join(value[i:i+2] for i in range(0, len(value), 2))

def expand_cmd(cmd):
    ret = ""
    for e in cmd:
        if e[0] == 'hexstr':
            ret += e[1]
        else:
            raise ValueError("Unsupported '%s'" % (e[0]))
    return ret


def ldr_stmt_to_ipr(s):
    """ translate a single LDR statement to IPR format. """
    if s == None:
        None
    elif s == 'reset':
        print("RESET")
        print("")
    elif s[0] == 'rem':
        print("//\t%s" % s[1])
    elif s[0] == 'cmd':
        cmd = s[1]
        req = cmd['req']
        rsp = cmd['rsp']
        print("I: %s" % split_hex(expand_cmd([req])))
        if rsp != None and len(rsp) != 1:
            if rsp[0] != 'swmatch' or len(rsp[1]) != 1:
                raise ValueError("Unsupported '%s'" % (rsp))
            print("O: %s" % rsp[1][0])
        else:
            print("O:")
        print("")
    else:
        print("Unknown %s" % (s.pretty()))
        raise ValueError()


test_text = '''
RST
CMD     E0 CA DF 1F 13
CMD E0 CA DF 1F (90 00)
CMD E0 CA DF 1F (61 XX, 90 00)
REM foo bar
CMD     E4 DA DF 20 09 EA 53 F8 D7 64 1E D9 88 00 \\
        (90 00 , 6B 00)
'''


def run_statement(s):
    print(s)

def fii(s):
    if s.data == 'rst':
        print("=> RESET")
        # FIXME: actually perform card reset
    elif s.data == 'rem':
        print(s)
    elif s.data == 'cmd':
        #print(s)
        cmd = s.children[0]
        print(s.pretty())
        # FIXME: if swmatch: match all contained swpattern
    else:
        print("Unknown %s" % (s.pretty()))
        raise ValueError()


#process_ldr(test_text, run_statement)
#process_ldr(test_text, ldr_stmt_to_ipr)

fmt = ScriptFormatLDR()
fmt.parse_process_file(sys.argv[1], ldr_stmt_to_ipr)
#fmt.parse_process_file(sys.argv[1], run_statement)
