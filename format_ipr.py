from lark import Lark, Transformer, Token, Tree
from script_format import ScriptFormat
from format_ldr import LdrXfrm

class IprXfrm(LdrXfrm):
    """ transform the parse tree into a more easily consumable form """
    def key(self, items):
        return ('key', ''.join(list(items)))
    def req(self, items):
        return items[:-1]
    def rsp(self, items):
        return items[:-1]
    #def NEWLINE(self, items):
        #return None


class ScriptFormatIPR(ScriptFormat):
    # parser for the IPR file format as used by the SIM card factory
    ipr_parser = Lark(r"""
        script: statement*
        ?statement: cmd | rst | rem | NEWLINE

        NONL: /[^\n]/+
        rem: "//" NONL? NEWLINE

        ALNUM: DIGIT | LETTER | "_"
        key: "[" ALNUM+ "]"

        cmd: req rsp

        req: "I:" [hexstr|key]+ NEWLINE
        hexstr: HEX_ITEM+
        HEX_ITEM: HEXDIGIT ~ 2

        rsp: "O:" swpattern? NEWLINE
        swpattern: HEX_OR_X ~ 4
        HEX_OR_X: HEXDIGIT | "X" | "x"

        rst: "RESET" NEWLINE

        %import common.ESCAPED_STRING -> STRING
        %import common.WS_INLINE
        %import common.HEXDIGIT
        %import common.DIGIT
        %import common.LETTER
        %import common.NEWLINE
        %ignore WS_INLINE

        """, start='script', parser='lalr')#, lexer='standard')

    def parse_xform(self, text):
        tree = self.ipr_parser.parse(text)
        #print(tree.pretty())
        p = IprXfrm().transform(tree)
        return p
