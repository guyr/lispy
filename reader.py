import re
import StringIO

from lispy.runtime import symbol

__all__ = ["read"]

#-----------------------------------------------------------------------

def mkSyntaxError(msg, filename, lineno, offset, linetext, completable=False):
    e = SyntaxError(msg, (filename, lineno, offset, linetext))
    e.completable = completable
    return e

#-----------------------------------------------------------------------
# tokenization - loosely based on the standard module tokenize

def either(*choices): return '(' + '|'.join(choices) + ')'
def maybe(*choices): return either(*choices) + '?'
def some(*choices): return either(*choices) + '*'
def dispatch(*choices):
    return '|'.join(['(?P<'+k+'>'+v+')'
                     for k,v in zip(choices[::2], choices[1::2])])

Whitespace = either(r'[ \f\t]+', r'\r?\n')
Comment = r'#[^\r\n]*'
Ignore = either(Whitespace, Comment)

# TODO: consider to add @ to symbol chars
SymbolInitialChar = r'[a-zA-Z_+\-*/%&|^=<>?!~$:;.]'
SymbolChars = some(SymbolInitialChar, r'[0-9]')
Symbol = SymbolInitialChar + SymbolChars

Hexnumber = r'0[xX][\da-fA-F]+[lL]?'
Octnumber = r'(0[oO][0-7]+)|(0[0-7]*)[lL]?'
Binnumber = r'0[bB][01]+[lL]?'
Decnumber = r'[1-9]\d*[lL]?'
Intnumber = either(Hexnumber, Binnumber, Octnumber, Decnumber)
Exponent = r'[eE][-+]?\d+'
Pointfloat = either(r'\d+\.\d*', r'\.\d+') + maybe(Exponent)
Expfloat = r'\d+' + Exponent
Floatnumber = either(Pointfloat, Expfloat)
Imagnumber = either(r'\d+[jJ]', Floatnumber + r'[jJ]')
Number = r'[-+]*' + either(Imagnumber, Floatnumber, Intnumber)

# strings terminology:
#    single:
#       single-single: '...'
#       single-double: "..."
#    triple:
#       triple-single: '''...'''
#       triple-double: """..."""
# NOTE: strings are double-quoted only until meaning of ' is decided
SingleStringHead = '([bB]|[uU])?[rR]?"'
TripleStringHead = '([bB]|[uU])?[rR]?"""'
#SingleStringHead = either("([bB]|[uU])?[rR]?'", '([bB]|[uU])?[rR]?"')
#TripleStringHead = either("([bB]|[uU])?[rR]?'''", '([bB]|[uU])?[rR]?"""')
SingleSingleStringTail = r"[^'\\]*(?:\\.[^'\\]*)*'"
SingleDoubleStringTail = r'[^"\\]*(?:\\.[^"\\]*)*"'
TripleSingleStringTail = r"[^'\\]*(?:(?:\\.|'(?!''))[^'\\]*)*'''"
TripleDoubleStringTail = r'[^"\\]*(?:(?:\\.|"(?!""))[^"\\]*)*"""'

Bracket = '[][(){}]'
Quote = either(',@', r'[,`]')
Macro = either(Bracket, Quote)

Token = dispatch(
    "ignore", Ignore,
    "triple_string", TripleStringHead,
    "single_string", SingleStringHead,
    "number", Number,
    "symbol", Symbol,
    "macro", Macro)

token_prog = re.compile(Token)
single1tail_prog = re.compile(SingleSingleStringTail)
single2tail_prog = re.compile(SingleDoubleStringTail)
triple1tail_prog = re.compile(TripleSingleStringTail)
triple2tail_prog = re.compile(TripleDoubleStringTail)
tail_progs = {"'": single1tail_prog, '"': single2tail_prog,
              "r'": single1tail_prog, 'r"': single2tail_prog,
              "b'": single1tail_prog, 'b"': single2tail_prog,
              "u'": single1tail_prog, 'u"': single2tail_prog,
              "br'": single1tail_prog, 'br"': single2tail_prog,
              "ur'": single1tail_prog, 'ur"': single2tail_prog,
              "'''": triple1tail_prog, '"""': triple2tail_prog,
              "r'''": triple1tail_prog, 'r"""': triple2tail_prog,
              "b'''": triple1tail_prog, 'b"""': triple2tail_prog,
              "u'''": triple1tail_prog, 'u"""': triple2tail_prog,
              "br'''": triple1tail_prog, 'br"""': triple2tail_prog,
              "ur'''": triple1tail_prog, 'ur"""': triple2tail_prog}

class Token:
    def __init__(self, type, text, line_no, col, linetext):
        self.type = type
        self.text = text
        self.line_no = line_no
        self.col = col + 1  # 1 is the first offset when printing tracebacks
        self.linetext = linetext
    def __repr__(self):
        return "%d,%d:\t%s\t%r" % \
            (self.line_no, self.col, self.type, self.text)

# token types: end, symbol, number, string, macro
def iter_tokens(readline, filename):
    line_no, pos = 0, 0
    contstr, needcont = '', 0

    # loop over lines in stream
    while 1:
        try:
            line = readline()
        except StopIteration:
            line = ''
        line_no += 1
        pos, max = 0, len(line)

        # continued string
        if contstr:
            if not line:
                raise mkSyntaxError("EOF in multi-line string",
                                    filename, strline, strpos, contline,
                                    completable=True)
            tail_match = tail_prog.match(line)
            if tail_match:
                pos = end = tail_match.end(0)
                yield Token("string", contstr + line[:end], strline, strpos, contline)
                contstr, needcont = '', 0
            elif needcont and line[-2:] != '\\\n' and line[-3:] != '\\\r\n':
                raise mkSyntaxError("EOL while scanning string literal",
                                    filename, strline, strpos, contline)
            else:
                contstr = contstr + line
                contline = contline + line
                continue

        if not line: break

        # scan for tokens
        while pos < max:
            match = token_prog.match(line, pos)
            if match:
                token_type = match.lastgroup
                start, pos = match.span(token_type)
                token = line[start:pos]
                
                # skip whitespace and comments
                if token_type == "ignore":
                    continue

                # handle (potentially) multi-line strings
                if token_type in ["single_string", "triple_string"]:
                    tail_prog = tail_progs[token.lower()]
                    tail_match = tail_prog.match(line, pos)
                    if tail_match:
                        # all on one line
                        token_type = "string"
                        pos = tail_match.end(0)
                        token = line[start:pos]
                    else:
                        # multiple lines
                        if token_type == "single_string":
                            if line[-2:] != '\\\n' and line[-3:] != '\\\r\n':
                                raise mkSyntaxError("EOL while scanning string literal",
                                                    filename, line_no, start, line)
                            needcont = 1
                        strline, strpos = line_no, start
                        contstr = line[start:]
                        contline = line
                        break
                
                yield Token(token_type, token, line_no, start, line)
            else:
                raise SyntaxError, ("invalid syntax", line_no, pos)

    yield Token("end", '', line_no, pos, "")

#-----------------------------------------------------------------------

# TODO: support encoding specification
class Reader:
    def __init__(self, file, filename="<unknown>"):
        self.filename = filename
        self.tokens = iter_tokens(file.readline, filename)
        self.macro_funcs = {
            "(": self.read_seq,
            ")": self.read_unmatched,
            "[": self.read_seq,
            "]": self.read_unmatched,
            "{": self.read_seq,
            "}": self.read_unmatched,
            "`": self.read_quasiquote,
            ",": self.read_unquote,
            ",@": self.read_unquote_splicing}

    def read(self):
        forms = []
        while 1:
            token = self.tokens.next()
            if token.type == "end":
                break
            else:
                forms.append(self.read_token(token))

        if len(forms) == 0:
            return None
        if len(forms) == 1:
            return forms[0]
        return (symbol("__lispy__:do"),) + tuple(forms)

    def read_token(self, token):
        """turns a Token into a lispy form"""
        if token.type == "symbol":
            return symbol(token.text)
        elif token.type in ["number", "string"]:
            return eval(token.text)
        elif token.type == "macro":
            return self.macro_funcs[token.text](token)
        assert False, "unexpected token type %r" % token.type

    seq_end_delims = {"(":")", "[":"]", "{":"}"}
    seq_names = {"(":"tuple", "[":"list", "{":"dict"}

    def read_seq(self, token0):
        delim = token0.text
        end_delim = self.seq_end_delims[delim]
        result = []
        while 1:
            token = self.tokens.next()
            if token.text == end_delim:
                break
            elif token.type == "end":
                raise mkSyntaxError("EOF while reading %s" % self.seq_names[delim],
                                    self.filename, token.line_no, token.col,
                                    token.linetext, completable=True)
            else:
                result.append(self.read_token(token))
        if delim == "(":
            return tuple(result)
        elif delim == "[":
            return result
        else: # "{"
            if len(result) % 2 != 0:
                raise mkSyntaxError("dict with uneven number of elements",
                                    self.filename, token.line_no, token.col,
                                    token.linetext)
            return dict(zip(result[::2], result[1::2]))

    def read_unmatched(self, token):
        raise mkSyntaxError("unmatched delimiter \"%s\"" % token.text,
                            self.filename, token.line_no, token.col,
                            token.linetext)

    def read_quasiquote(self, token):
        token = self.tokens.next()
        if token.type == "end":
            raise mkSyntaxError("EOF after \"`\" (quasiquote)",
                                self.filename, token.line_no, token.col,
                                token.linetext, completable=True)
        return (symbol("__lispy__:quasiquote"),
                self.read_token(token))

    def read_unquote(self, token):
        token = self.tokens.next()
        if token.type == "end":
            raise mkSyntaxError("EOF after \",\" (unquote)",
                                self.filename, token.line_no, token.col,
                                token.linetext, completable=True)
        return (symbol("__lispy__:unquote"),
                self.read_token(token))

    def read_unquote_splicing(self, token):
        token = self.tokens.next()
        if token.type == "end":
            raise mkSyntaxError("EOF after \",@\" (unquote-splicing)",
                                self.filename, token.line_no, token.col,
                                token.linetext, completable=True)
        return (symbol("__lispy__:unquote-splicing"),
                self.read_token(token))

def read(file_or_text, filename=None):
    """accepts string or file object, returns lispy form"""
    if isinstance(file_or_text, (str,unicode)):
        file = StringIO.StringIO(file_or_text)
        if filename is None:
            filename = "<string>"
    else:
        file = file_or_text
        if filename is None:
            if hasattr(file, "name"):
                filename = file.name
            else:
                filename = "<unknown>"

    try:
        reader = Reader(file, filename)
        return reader.read()
    #TODO?: re-raise syntax error to crop reader-internal part of stack?
    finally:
        if hasattr(file, "close"):
            file.close()

#-----------------------------------------------------------------------

# testing
if __name__ == '__main__':                     
    import sys
    from pprint import pprint

    if len(sys.argv) > 1:
        file = open(sys.argv[1])
    else:
        file = sys.stdin

    # tokenizer-only test
    if 0:
        for token in iter_tokens(file.readline):
            print token

    # full reader test
    if 1:
        pprint(read(file))
