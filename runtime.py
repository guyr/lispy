# run-time infrasructure

import sys
import types

__all__ = "symbol gensym issymbol iskeyword isdotted isqualified " \
          "qualify split_qualified unqualify mk_macro ismacro " \
          "macroexpand_star macroexpand_1_star macroexpand " \
          "macroexpand_1 mk_unwrap_metaclass mk_getattr_macro " \
          "_eval_symbol _init_envs ".split()

#-----------------------------------------------------------------------
# the symbol type

class symbol(str):
    def __repr__(self):
        return 'symbol(%s)' % self

gensym_counter = 0
def gensym(suffix=None):
    global gensym_counter
    s = symbol("_gs#%d%s" % (gensym_counter,
                             suffix and "-"+suffix or ""))
    gensym_counter += 1
    return s

def issymbol(obj):
    return isinstance(obj, symbol)

def iskeyword(obj):
    return issymbol(obj) and obj.startswith(":")

def isdotted(sym):
    if not issymbol(sym):
        return False
    sym = unqualify(sym)
    return "." in sym and \
           "" not in sym.split(".")[1:]

def isqualified(sym):
    if not issymbol(sym):
        return False
    return ":" in sym and "" not in sym.partition(":")

def qualify(sym, globals={}, locals={}):
    if not issymbol(sym):
        raise TypeError, "qualify argument must be a symbol, not \"%s\" object" % type(sym).__name__

    # already qualified?
    if isqualified(sym):
        return sym

    # properly handle names with . (only first part in module)
    if len(sym) > 1 and "." in sym and \
       not sym.startswith(".") and \
       not sym.endswith("."):
        name = sym.split(".")[0]
    else:
        name = sym

    # qualify module globals
    if "__name__" in globals and \
       name in globals and \
       (globals is locals or name not in locals):
        return symbol(globals["__name__"] + ":" + sym)
        
    # qualify lispy builtins (__lispy__ module needed)
    import __lispy__
    if hasattr(__lispy__, name) and \
       (__lispy__.__dict__ is locals or name not in locals):
        return symbol("__lispy__:" + sym)

    # qualify python builtins
    import __builtin__
    if hasattr(__builtin__, name) and \
       (__builtin__.__dict__ is locals or name not in locals):
        return symbol("__builtin__:" + sym)

    # don't qualify
    return sym

def split_qualified(sym):
    if not issymbol(sym):
        raise TypeError, "split_qualified argument must be a symbol, not \"%s\" object" % type(sym).__name__
    
    if isqualified(sym):
        parts = sym.partition(":")
        return (symbol(parts[0]), symbol(parts[2]))
    else:
        return (symbol(""), sym)

def unqualify(sym):
    if isqualified(sym):
        return split_qualified(sym)[1]
    return sym

#-----------------------------------------------------------------------
# macros

def mk_macro(func):
    func.lispy_macro = True
    return func

def ismacro(obj):
    return callable(obj) and \
           getattr(obj, "lispy_macro", False)

def _init_envs(globals, locals, inherit=True):
    if globals is None:
        if inherit:
            prevf = sys._getframe(2)
            globals = prevf.f_globals
            locals = prevf.f_locals
        else:
            globals = {}
    if locals is None:
        locals = globals
    return globals, locals

# this is only for macro expansion, so py builtins are not checked (for now)
def _eval_symbol(sym, globals=None, locals=None):
    if not issymbol(sym):
        raise TypeError, "eval_symbol argument must be a symbol, not \"%s\" object" % type(sym).__name__
    globals, locals = _init_envs(globals, locals)

    # TODO: validate symbols if I really want to complain when they're "illegal"
    # handle keywords
    if sym.startswith(":"):
        return sym
    # handle qualified symbols
    if isqualified(sym):
        modname, name = split_qualified(sym)
        if "__name__" in globals and globals["__name__"] == modname:
            moddict = globals
        else:
            try: mod = sys.modules[modname]
            except KeyError:
                raise NameError, "module \"%s\" is not imported" % modname
            moddict = mod.__dict__
        try: return _eval_symbol(name, moddict)
        except NameError:
            raise NameError, "name \"%s\" is not defined in module \"%s\"" % (name, modname)
    # handle dots in name
    if isdotted(sym):
        names = sym.split(".")
        if names[0] == "":
            return mk_getattr_macro(*names[1:])
        else:
            names[0] = _eval_symbol(symbol(names[0]), globals, locals)
            return reduce(getattr, names)
    # emulate python's name resolution
    if sym in locals:
        return locals[sym]
    if sym in globals:
        return globals[sym]
    import __lispy__
    if hasattr(__lispy__, sym):
        return getattr(__lispy__, sym)
    raise NameError, "name \"%s\" is not defined" % sym

def macroexpand_1_star(form, globals=None, locals=None):
    globals, locals = _init_envs(globals, locals)

    if not isinstance(form, tuple) or \
       not len(form) >= 1:
           return form, False
    if not issymbol(form[0]):
        return form, False
    try:
        func = _eval_symbol(form[0], globals, locals)
    except NameError:
        return form, False
    if not ismacro(func):
        return form, False
    args = form[1:]
    return func(*args), True

def macroexpand_star(form, globals=None, locals=None):
    globals, locals = _init_envs(globals, locals)

    expanded = False
    while 1:
        form, expanded_again = macroexpand_1_star(form, globals, locals)
        expanded = expanded or expanded_again
        if not expanded_again:
            return form, expanded

def macroexpand_1(form, globals=None, locals=None):
    globals, locals = _init_envs(globals, locals)
    return macroexpand_1_star(form,globals,locals)[0]

def macroexpand(form, globals=None, locals=None):
    globals, locals = _init_envs(globals, locals)
    return macroexpand_star(form,globals,locals)[0]

#-----------------------------------------------------------------------
# helpers for compiled code
# (should probably be turned into inline code)

def get_docstring(form):
    if isinstance(form, (str, unicode)):
        return form
    elif isinstance(form, tuple) and \
         len(form) > 1 and \
         issymbol(form[0]) and \
         form[0] == "do":
        return get_docstring(form[1])
    else:
        return None

def mk_unwrap_metaclass(tmp_name):
    def unwrapping_metaclass(name, bases, dict):
        return dict[tmp_name]
    return unwrapping_metaclass

# TODO: remove
def rename_func(func, name):
    code = func.func_code
    new_code = types.CodeType(code.co_argcount,
                              code.co_nlocals,
                              code.co_stacksize,
                              code.co_flags,
                              code.co_code,
                              code.co_consts,
                              code.co_names,
                              code.co_varnames,
                              code.co_filename,
                              name,     #<-- this is what appears in trackebacks
                              code.co_firstlineno,
                              code.co_lnotab,
                              code.co_freevars,
                              code.co_cellvars)
    return types.FunctionType(new_code,
                              func.func_globals,
                              name,     #<-- this is what appears in string repr
                              func.func_defaults,
                              func.func_closure)

# used by compiled code to evaluate partially dotted symbols
def mk_getattr_macro(*names):
    def bound_getattr(form, *args):
        for arg in names:
            form = (symbol("__builtin__:getattr"), form, str(arg))
        return (form,) + args
    bound_getattr = rename_func(bound_getattr, "." + ".".join(names))
    bound_getattr = mk_macro(bound_getattr)
    return bound_getattr

#-----------------------------------------------------------------------
# __lispy__ builtins

# TODO: think of better name?
class DynamicInvocationError(RuntimeError):
    """Special form or macro invoked dynamically (probably as a callback)."""

def _special(func):
    func.lispy_special = True
    return func

def isspecial(obj):
    return callable(obj) and \
           getattr(obj, "lispy_special", False)

def py_exec(text, globals=None, locals=None):
    globals, locals = _init_envs(globals, locals)
    exec text in globals, locals

# TODO: docstrings

@_special
def eval_when(situations, *forms):
    raise DynamicInvocationError, "eval-when can't be invoked dynamically"

@_special
def quote(form):
    raise DynamicInvocationError, "quote can't be invoked dynamically"

@_special
def quasiquote(form):
    raise DynamicInvocationError, "quasiquote can't be invoked dynamically"

@_special
def unquote(form):
    raise DynamicInvocationError, "unquote can't be invoked dynamically"

@_special
def unquote_splicing(form):
    raise DynamicInvocationError, "unquote-splicing can't be invoked dynamically"

@_special
def do(*forms):
    raise DynamicInvocationError, "do can't be invoked dynamically"

@_special
def global_(*names):
    raise DynamicInvocationError, "special form \"global\" can't be invoked dynamically"

@_special
def assign_star(name, value):
    raise DynamicInvocationError, "=* can't be invoked dynamically"

@_special
def del_star(form):
    raise DynamicInvocationError, "del* can't be invoked dynamically"

@_special
def if_star(test, body, orelse):
    raise DynamicInvocationError, "if* can't be invoked dynamically"

@_special
def while_star(test, body, orelse):
    raise DynamicInvocationError, "while* can't be invoked dynamically"

# XXX should be special and raise an exception?
# alternatively - may not be compiled
def pass_():
    pass

@_special
def continue_():
    raise DynamicInvocationError, "continue can't be invoked dynamically"

@_special
def break_():
    raise DynamicInvocationError, "break can't be invoked dynamically"

@_special
def func(name, args, *body):
    raise DynamicInvocationError, "special form \"func\" can't be invoked dynamically"

@_special
def macro(name, args, *body):
    raise DynamicInvocationError, "special form \"macro\" can't be invoked dynamically"

@_special
def return_star(value):
    raise DynamicInvocationError, "return* can't be invoked dynamically"

@_special
def yield_star(value):
    raise DynamicInvocationError, "yield* can't be invoked dynamically"

@_special
def class_star(name, bases, *body):
    raise DynamicInvocationError, "class* can't be invoked dynamically"

@_special
def try_finally(body, finalbody):
    raise DynamicInvocationError, "try-finally can't be invoked dynamically"

@_special
def try_except(body, handlers, orelse):
    raise DynamicInvocationError, "try-except can't be invoked dynamically"

def raise_(type=None, value=None, traceback=None):
    if type is None:
        type, value, traceback = sys.exc_info()
    raise type, value, traceback

#-----------------------------------------------------------------------
# the __lispy__ module

# this initializes the __lispy__ module with builtins from the following
# sources:
#   this file, reader.py, compiler.py, loader.py, importlib,
#   core.lpy, more.lpy
def init_lispy():
    mk_module = type(sys)
    __lispy__ = mk_module("__lispy__", "lispy builtins")
    sys.modules["__lispy__"] = __lispy__

    __lispy__.__dict__.update({
        "py-compile": compile,
        "py-eval": eval,
        "py-exec": py_exec,

        "symbol": symbol,
        "symbol?": issymbol,
        "keyword?": iskeyword,
        "dotted?": isdotted,
        "qualified?": isqualified,
        "qualify": qualify,
        "unqualify": unqualify,
        "split-qualified": split_qualified,
        "gensym": gensym,

        "macro?": ismacro,
        "macroexpand*": macroexpand_star,
        "macroexpand-1*": macroexpand_1_star,
        "macroexpand": macroexpand,
        "macroexpand-1": macroexpand_1,

        "special?": isspecial,
        "DynamicInvocationError": DynamicInvocationError,
        "eval-when": eval_when,
        "quote": quote,
        "quasiquote": quasiquote,
        "unquote": unquote,
        "unquote-splicing": unquote_splicing,

        "pass": pass_,
        "global": global_,
        "=*": assign_star,
        "del*": del_star,
        "eval-when": eval_when,
        "do": do,
        "if*": if_star,
        "break": break_,
        "continue": continue_,
        "while*": while_star,
        "return*": return_star,
        "yield*": yield_star,
        "func": func,
        "macro": macro,
        "raise": raise_,
        "try-finally": try_finally,
        "try-except": try_except,
        "class*": class_star,
    })

    from lispy.reader import read
    from lispy.compiler import compile_, eval_, eval_str, eval_file
    from lispy.importlib import __import__, import_module

    __lispy__.__dict__.update({
        "__import__": __import__,
        "read": read,
        "compile": compile_,
        "eval": eval_,
        "eval-str": eval_str,
        "eval-file": eval_file,
    })

    # XXX this is required for the import mechanism (implemented by
    # lispy.importlib) to support lispy files, using sys.import_suffix_hooks.
    # This doesn't influence python's import statement due to being
    # separately implemented, but in the future there should be a single
    # implementation (which the standard importlib aims to be). When this
    # happens, and this single implementation supports sys.import_suffix_hooks,
    # it should be possible to have _separate instances_ of the import
    # mechanism (as opposed to completle independent implementations),
    # each with its own configuration (corresponding to the configuration
    # currently residing in sys), so that imports from python don't
    # support lispy files by default, and imports from lispy do.
    import loader
    loader.install()
 
    # add all symbols from core and more to __lispy__.
    # currently using the lispy.importlib mechanism. In the future should
    # explicitly use a dedicated lispy instance of the import mechanism
    # configuration.

    core = import_module("lispy.core")
    for name in core.__all__:
        setattr(__lispy__, name, getattr(core, name))

    more = import_module("lispy.more")
    for name in more.__all__:
        setattr(__lispy__, name, getattr(more, name))
