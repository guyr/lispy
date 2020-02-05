import sys
import traceback

import lispy
from lispy.compiler import eval_
from lispy.reader import read

__all__ = ["interact"]

#-----------------------------------------------------------------------

PROMPT1 = "lispy> "
PROMPT2 = "lispy... "

# loosely based on the standard module code
#TODO: get rid of references to stdin and stdout! (i.e. work directly with file objects?)
#TODO: improve trackbacks (like in std module code)
#TODO?: combination of stdout/stderr?
#TODO?: alternative interface which will receive one line at a time
#TODO?: receive the prompts as args
#TODO?: help, etc. (something equivalent to python's "... for more information")
#TODO?: better (more lispy) autocomplete?
def interact(banner=None, readfunc=None, writefunc=None, locals=None, filename="<console>"):
    """interactive Lispy interpreter.

    banner -- the banner to print before the first interaction.
    readfunc -- writes a prompt and reads a line (like raw_input).
    writefunc -- writes the given text (like a file object's write).
    locals -- the dictionary in which code will be executed.
    filename -- the name of the input stream; will show up in tracebacks.
    """
    if readfunc is None:
        try:
            import readline
            import rlcompleter
            readline.parse_and_bind("tab: complete")
            # XXX this is just a hack to disable rlcompleter's
            # annoying added parentheses.
            class Completer(rlcompleter.Completer):
                def _callable_postfix(self, val, word):
                    return word
            readline.set_completer(Completer().complete)
        except ImportError:
            pass
        readfunc = raw_input
    if writefunc is None:
        writefunc = sys.stdout.write
    if locals is None:
        locals = {"__name__": "__console__", "__doc__": None}

    if banner is None:
        writefunc("Lispy %s on Python %s on %s\n" % \
                    (lispy.version,
                     sys.version,
                     #".".join(map(str, sys.version_info[:3])),
                     sys.platform))
    else:
        writefunc("%s\n" % str(banner))

    buffer = []
    more = 0
    while 1:
        if more: prompt = PROMPT2
        else:    prompt = PROMPT1

        try:
            line = readfunc(prompt)
            # Can be None if sys.stdin was redefined
            encoding = getattr(sys.stdin, "encoding", None)
            if encoding and not isinstance(line, unicode):
                line = line.decode(encoding)
        except EOFError:
            writefunc("\n")
            break
        except KeyboardInterrupt:
            writefunc("\nKeyboardInterrupt\n")
            buffer = []
            more = 0
        else:
            buffer.append(line)

            try:
                form = read("\n".join(buffer), filename)
            except SyntaxError, e:
                if getattr(e, "completable", False):
                    more = 1
                else:
                    more = 0
                    buffer = []

                    lst = traceback.format_exception_only(type(e), e)
                    map(writefunc, lst)
            else:
                more = 0
                buffer = []

                try:
                    result = eval_(form, locals)
                except SystemExit:
                    raise
                except:
                    lst = traceback.format_exception(*sys.exc_info())
                    map(writefunc, lst)
                else:
                    if getattr(sys.stdout, "softspace", 0):
                        writefunc("\n")

                    if result is not None:
                        writefunc("%s\n" % repr(result))
                    locals["_"] = result

#-----------------------------------------------------------------------
