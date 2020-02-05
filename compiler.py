import sys
from warnings import warn
from types import NoneType, EllipsisType
from copy import deepcopy
from itertools import chain

from lispy.runtime import *
from lispy.astutils import *
from lispy.loader import update_deps_info, deps_info_to_str
import __lispy__

#-----------------------------------------------------------------------
# public API

# TODO: optionally return the ast (ast.PyCF_ONLY_AST)
# TODO: support __future__ and its flags, and dont_inherit
# TODO?: accept toplevel flag
def compile_(form, filename="<unknown>", globals=None, locals=None,
             with_deps_info=False):
    globals, locals = _init_envs(globals, locals, inherit=False)

    compiler = Compiler(filename, globals, locals,
                        with_deps_info=with_deps_info)
    ast = compiler.compile(form)
    return compile(ast, filename, "exec")

# TODO?: accept toplevel flag
# TODO?: if compile_ will have eval mode in the future, make use of it
def eval_(form, globals=None, locals=None, filename="<lispy-form>"):
    globals, locals = _init_envs(globals, locals)

    compiler = Compiler(filename, globals, locals)
    ast = compiler.compile(form, store_result=True)
    code = compile(ast, filename, "exec")
    #from dis import dis
    #dis(code)
    #print "CODE: %r" % marshal.dumps(code)
    exec code in globals, locals

    result = locals[compiler.result_sym]
    del locals[compiler.result_sym] # not sure if this is always allowed
    return result

# TODO?: accept toplevel flag
def eval_str(text, globals=None, locals=None, filename="<lispy-string>"):
    from lispy.reader import read
    globals, locals = _init_envs(globals, locals)
    return eval_(read(text), globals, locals)

# TODO?: accept toplevel flag
# TODO: support "loader-macros"!
def eval_file(file, globals=None, locals=None, filename=None):
    from lispy.reader import read
    globals, locals = _init_envs(globals, locals)

    if isinstance(file, (str,unicode)):
        file = open(file,"U")
    if not filename:
        if hasattr(file, "name"):
            filename = file.name
        else:
            filename = "<lispy-file>"

    form = read(file)
    return eval_(form, globals, locals, filename)

#-----------------------------------------------------------------------
# argument-processing helpers for functions and macros

def flatten(seq):
    seq = list(seq)
    result = []
    while seq:
        x = seq.pop(0)
        if isinstance(x, (tuple,list)):
            seq[0:0] = x
        else:
            result.append(x)
    return result

def process_func_call_args(raw_args):
    """returns unevaluated (args,kwargs,star,dstar) for function invocation"""
    # this check is not necessary since this never happens
    if not isinstance(raw_args, (tuple,list)):
        raise SyntaxError, "function arguments must be a tuple or list"

    raw_args = list(raw_args)
    ERR_PREFIX = "in function call: "
    args, kwargs, star, dstar = [], [], None, None
    seen = {}
    expect = ("arg","kw","&*","&**")
    last = ""

    while raw_args:
        arg = raw_args.pop(0)

        # process &**
        if issymbol(arg) and arg == "&**":
            if "&**" not in expect:
                raise SyntaxError, ERR_PREFIX + "&** after %s" % last
            if not raw_args:
                raise SyntaxError, ERR_PREFIX + "nothing after &**"
            dstar = raw_args.pop(0)
            expect = ()
            last = "&**"

        # process &*
        elif issymbol(arg) and arg == "&*":
            if "&*" not in expect:
                raise SyntaxError, ERR_PREFIX + "&** after %s" % last
            if not raw_args:
                raise SyntaxError, ERR_PREFIX + "nothing after &*"
            star = raw_args.pop(0)
            expect = ("&**")
            last = "&*"

        # process keyword arguments
        elif iskeyword(arg):
            if "kw" not in expect:
                raise SyntaxError, ERR_PREFIX + "keyword argument \"%s\" after %s" % (arg, last)
            if not raw_args:
                raise SyntaxError, ERR_PREFIX + "nothing after keyword \"%s\"" % arg
            arg = arg[1:]
            if arg in seen:
                raise SyntaxError, ERR_PREFIX + "multiple values for keyword argument \"%s\"" % arg
            seen[arg] = True
            kwargs.append((arg, raw_args.pop(0)))
            expect = ("kw", "&*", "&**")
            last = "keyword argument"

        # process normal arguments
        else:
            if "arg" not in expect:
                raise SyntaxError, ERR_PREFIX + "normal argument after %s" % last
            args.append(arg)

    return args, kwargs, star, dstar

def process_func_def_args(raw_args):
    """returns unevaluated (args,defaults,star,dstar) for function definition"""
    if not isinstance(raw_args, (tuple,list)):
        raise SyntaxError, "function arguments must be a tuple or list"

    raw_args = list(raw_args)
    ERR_PREFIX = "in function definition: "
    args, defaults, star, dstar = [], [], None, None
    expect = ("arg","kw","&*","&**")
    last = ""

    while raw_args:
        arg = raw_args.pop(0)

        # process &**
        if issymbol(arg) and arg == "&**":
            if "&**" not in expect:
                raise SyntaxError, ERR_PREFIX + "&** after %s" % last
            if not raw_args:
                raise SyntaxError, ERR_PREFIX + "nothing after &**"
            dstar = raw_args.pop(0)
            if not issymbol(dstar):
                raise SyntaxError, ERR_PREFIX + "\"%s\" object after &**, symbol expected" % type(dstar).__name__
            dstar = str(dstar)
            expect = ()
            last = "&**"

        # process &*
        elif issymbol(arg) and arg == "&*":
            if "&*" not in expect:
                raise SyntaxError, ERR_PREFIX + "&** after %s" % last
            if not len(raw_args):
                raise SyntaxError, ERR_PREFIX + "nothing after &*"
            star = raw_args.pop(0)
            if not issymbol(star):
                raise SyntaxError, ERR_PREFIX + "\"%s\" object after &*, symbol expected" % type(star).__name__
            star = str(star)
            expect = ("&**")
            last = "&*"

        # process keyword arguments (arguments with defaults)
        elif iskeyword(arg):
            if "kw" not in expect:
                raise SyntaxError, ERR_PREFIX + "keyword argument \"%s\" after %s" % (arg, last)
            if not raw_args:
                raise SyntaxError, ERR_PREFIX + "nothing after keyword \"%s\"" % arg
            args.append(arg[1:])
            defaults.append(raw_args.pop(0))
            expect = ("kw", "&*", "&**")
            last = "keyword argument"

        # process normal arguments
        elif issymbol(arg):
            if "arg" not in expect:
                raise SyntaxError, ERR_PREFIX + "argument \"%s\" after %s" % (arg, last)
            args.append(str(arg))

        # process sequences of arguments
        # TODO: should prevent subclasses of tuple and list?
        elif isinstance(arg, (tuple,list)):
            if "arg" not in expect:
                raise SyntaxError, ERR_PREFIX + "argument seqence after %s" % last
            # make sure seq contains only symbols or nested seqs of symbols
            # and turn symbols into strings
            def process_seq(x):
                if isinstance(x, (tuple,list)):
                    return [process_seq(y) for y in x]
                if not issymbol(x):
                    raise SyntaxError, ERR_PREFIX + "\"%s\" object in nested argument list" % type(x).__name__
                return str(x)
            arg = process_seq(arg)
            args.append(arg)

        else:
            raise SyntaxError, ERR_PREFIX + "\"%s\" object in argument list" % type(arg).__name__

    # find duplicates
    names = flatten(args)
    if star is not None: names.append(star)
    if dstar is not None: names.append(dstar)
    seen = {}
    for n in names:
        if n in seen:
            raise SyntaxError, ERR_PREFIX + "duplicate argument \"%s\"" % n
        seen[n] = True

    return args, defaults, star, dstar

#-----------------------------------------------------------------------
# the compiler

# eval modes
COMPILE_TIME_TOO = 0
NOT_COMPILE_TIME = 1

# mechanism to avoid double evaluation. used when sub-forms of a form
# are at the same level and may be evaluated if top-level, so they
# should not be evaluated again in the context of the containing form.
def dont_eval(ast):
    ast.dont_eval = True
    return ast
def should_eval(ast):
    return not getattr(ast, "dont_eval", False)

class Scope(dict):
    # an environment dictionary (globals/locals) for compile-time
    # compilation and evaluation.
    
    def __init__(self, prev_scope=None, inheritable=True, terminal=False):
        #print "new scope", inheritable, terminal
        self.parent_scope = self._get_parent_scope(prev_scope, terminal)
        self.inheritable = inheritable
        self.terminal = terminal
        self.globals = []

    def _get_parent_scope(self, prev_scope, terminal):
        # finds the closest inheritable scope, or None if there is no
        # inheriable scope.
        if terminal:
            # this is a special case for user globals/locals which are
            # wrapped by a Scope instances, which later act as the
            # compilation environment.
            return prev_scope
        if prev_scope.inheritable:
            # inherit from prev_scope
            return prev_scope
        if prev_scope.terminal:
            # a terminal non-inheritable scope is reached
            return None
        # inherit from prev_scope's parent, which must be an inheritable
        # scope or None.
        return prev_scope.parent_scope

    def defs(self, name):
        # for py3 support this condition should also include nonlocals
        if name not in self.globals:
            if not self.really_has_key(name):
                # There is a small problem with this: trying to, for example
                # run a previously-defined function inside a macro,
                # forgetting to eval the function definition during
                # compilation, will result in a "'NoneType' object is not
                # callable" error instead of the expected NameError.
                self[name] = None

    def global_(self, name):
        if not self.really_has_key(name):
            self.globals.append(name)

    # fall back to the enclosing environment
    # TODO?: support other access methods (e.g. iter)?
    def __missing__(self, key):
        if key not in self.globals and \
           self.parent_scope is not None:
            return self.parent_scope[key]
        raise KeyError, key
    def really_has_key(self, key):
        return dict.__contains__(self, key)
    def __contains__(self, key):
        return self.really_has_key(key) or \
            self.parent_scope is not None and \
            key in self.parent_scope
    has_key = __contains__


class Compiler:

    # table for dispatching by type
    dispatch_by_type = {
        symbol:       "compile_symbol",
        tuple:        "compile_tuple",
        list:         "compile_list",
        dict:         "compile_dict",
        # TODO: only if these names exist
        #set:          "compile_set",
        #frozenset:    "compile_frozenset",
        int:          "compile_num",
        long:         "compile_num",
        float:        "compile_num",
        complex:      "compile_num",
        str:          "compile_str",
        unicode:      "compile_str",
        # TODO?: buffer (as str)?
        bool:         "compile_num",  # happily, this works!
        NoneType:     "compile_None",
        EllipsisType: "compile_num",  # happily, this works!
        }

    # table for dispatching special forms
    dispatch_by_func = {
        vars(__lispy__)["eval-when"]:   "compile_eval_when",
        vars(__lispy__)["quote"]:       "compile_quote",
        vars(__lispy__)["quasiquote"]:  "compile_quasiquote",
        vars(__lispy__)["do"]:          "compile_do",
        vars(__lispy__)["global"]:      "compile_global",
        vars(__lispy__)["=*"]:          "compile_assign_star",
        vars(__lispy__)["del*"]:        "compile_del_star",
        vars(__lispy__)["if*"]:         "compile_if_star",
        vars(__lispy__)["while*"]:      "compile_while_star",
        vars(__lispy__)["pass"]:        "compile_pass",
        vars(__lispy__)["continue"]:    "compile_continue",
        vars(__lispy__)["break"]:       "compile_break",
        vars(__lispy__)["func"]:        "compile_func",
        vars(__lispy__)["return*"]:     "compile_return_star",
        vars(__lispy__)["yield*"]:      "compile_yield_star",
        vars(__lispy__)["macro"]:       "compile_macro",
        vars(__lispy__)["class*"]:      "compile_class_star",
        vars(__lispy__)["try-finally"]: "compile_try_finally",
        vars(__lispy__)["try-except"]:  "compile_try_except",
        }
    
    # table for global gensyms (ggs) - gensyms (as strings) that are
    # always used in the compiled code for the same values.
    global_gensyms = {}

    def __init__(self, filename, globals, locals, toplevel=True, with_deps_info=False):
        self.filename = filename
        self.globals = Scope(globals, inheritable=False, terminal=True)
        if locals is globals:
            self.locals = self.globals
        else:
            self.locals = Scope(locals, inheritable=False, terminal=True)
        self.level = not toplevel and 1 or 0
        self.scopes = []
        self.eval_mode = NOT_COMPILE_TIME
        self.used_ggs = {}
        self.do_deps = with_deps_info
        self.deps = {}
        self.result_sym = None

    def compile(self, form, store_result=False):
        # entry point to the compilation process
        ast = self.compile_form(form, levelup=False)
        ast = self.prepare_ast(ast, store_result, self.do_deps)
        return ast

    def prepare_ast(self, ast, store_result=False, do_deps=False):
        # prepare for py-compilation
        if store_result:
            self.result_sym = str(gensym("eval-result"))
            ast = Assign([Name(self.result_sym, Store())], ast)
        else:
            ast = Expr(ast)

        if do_deps:
            # embed the dependencies info in the code object to be
            # (it would be the last string const)
            deps_str = deps_info_to_str(self.deps)
            body = [ast,
                    Assign([Name(str(gensym("deps-info")), Store())],
                           Str(deps_str))]
        else:
            body = [ast]

        ast = Module(self.header() + body)
        #print "BEFORE:", dump(ast)
        unroll_ast(ast)
        #print "AFTER:", dump(ast)
        #print "AST:", dump(ast)
        fix_missing_locations(ast)
        return ast

    known_ggs = (
        # ggs name              module name      name to import
        ("__lispy__",           "__lispy__",     None),
        ("None",                "__builtin__",   "None"),
        ("str",                 "__builtin__",   "str"),
        ("tuple",               "__builtin__",   "tuple"),
        ("list",                "__builtin__",   "list"),
        ("dict*",               "__lispy__",     "dict*"),
        ("globals",             "__builtin__",   "globals"),
        ("sys-modules",         "sys",           "modules"),
        ("symbol",              "lispy.runtime", "symbol"),
        ("gensym",              "lispy.runtime", "gensym"),
        ("mk-unwrap-metaclass", "lispy.runtime", "mk_unwrap_metaclass"),
        ("mk-macro",            "lispy.runtime", "mk_macro"),
        ("mk-getattr-macro",    "lispy.runtime", "mk_getattr_macro"),
        ("chain",               "itertools",     "chain"))

    def header(self):
        # generates initialization code (list of statements) that will
        # be run before the compiled code. used after form compilation.
        def gen_import(modname, str_sym):
            return [Global([str_sym]),
                    Import([alias(modname, str_sym)])]
        def gen_import_from(modname, name, str_sym):
            return [Global([str_sym]),
                    ImportFrom(modname, [alias(name, str_sym)], 0)]

        stmts = []
        for ggs, modname, name in self.known_ggs:
            if ggs in self.used_ggs:
                if not name:
                    stmts += gen_import(modname, self.get_ggs(ggs))
                else:
                    stmts += gen_import_from(modname, name, self.get_ggs(ggs))
        return stmts

    def get_ggs(self, name):
        self.used_ggs[name] = True
        if name not in self.global_gensyms:
            self.global_gensyms[name] = str(gensym(name))
        return self.global_gensyms[name]

    def push_scope(self, inheritable=True):
        self.scopes.append(self.locals)
        self.locals = Scope(self.locals, inheritable)

    def pop_scope(self):
        self.locals = self.scopes.pop()

    def eval_symbol(self, sym):
        if not issymbol(sym):
            return None
        try:
            # this may cause trouble in the future in case symbol-
            # macros will be implemented.
            return _eval_symbol(sym, self.globals, self.locals)
        except:
            return None

    def compile_form(self, form, levelup=True):
        # dispatch according to form type
        form_type = type(form)
        try:
            fname = self.dispatch_by_type[form_type]
        except KeyError:
            raise SyntaxError, "unsupported form type \"%s\"" % form_type.__name__

        # possibly raise level
        if levelup:
            self.level += 1
        try:
            # create ast
            ast = getattr(self, fname)(form)

            # evaluate top-level forms if needed
            if self.level == 0 and self.eval_mode == COMPILE_TIME_TOO and \
               should_eval(ast):
                ast_copy = deepcopy(ast)
                ast_copy = self.prepare_ast(ast_copy)
                code = compile(ast_copy, self.filename, "exec")
                exec code in self.globals, self.locals
        finally:
            if levelup:
                self.level -= 1

        return ast

    def compile_num(self, n):
        return Num(n)

    def compile_str(self, s):
        return Str(s)

    def compile_None(self, none=None):
        return Name(self.get_ggs("None"), Load())

    # TODO?: break into functions?
    def compile_symbol(self, sym):
        # keywords
        if iskeyword(sym):
            return Call(
                Name(self.get_ggs("symbol"), Load()),
                [Str(str(sym))],
                [], None, None)

        # dotted symbols
        elif isdotted(sym):
            # partially dotted symbols
            if sym.startswith("."):
                # this could possibly be replaced by the ast of a direct
                # macro definition (i.e. do mk-getattr-macro inline).
                names = sym.split(".")[1:]
                return Call(
                    Name(self.get_ggs("mk-getattr-macro"), Load()),
                    map(Str, names),
                    [], None, None)
            # normal dotted symbols
            name, dummy, attr = sym.rpartition(".")
            return Attribute(self.compile_symbol(symbol(name)),
                             attr, Load())

        # qualified symbols
        elif isqualified(sym):
            # TODO?: unify exceptions raised by each case?
            modname, name = map(str, split_qualified(sym))
            # special treatment for qualified symbols belonging to
            # the module currently being compiled (which may not yet
            # exist in sys.modules)
            if "__name__" in self.globals and \
               modname == self.globals["__name__"]:
                return Subscript(
                    Call(
                        Name(self.get_ggs("globals"), Load()),
                        [], [], None, None),
                    Index(Str(name)),
                    Load())
            # normal treatment
            return Attribute(
                Subscript(
                    Name(self.get_ggs("sys-modules"), Load()),
                    Index(Str(modname)),
                    Load()),
                name, Load())

        # lispy builtins (__lispy__)
        elif hasattr(__lispy__, sym) and \
             sym not in self.locals and \
             sym not in self.globals:
            return Attribute(Name(self.get_ggs("__lispy__"), Load()),
                             str(sym), Load())

        # normal symbols
        # TODO?: update scope?
        return Name(str(sym), Load())

    def compile_list(self, lst):
        return List(
            [self.compile_form(form) for form in lst],
            Load())

    def compile_dict(self, dct):
        keys = []
        values = []
        for k,v in dct.iteritems():
            keys.append(self.compile_form(k))
            values.append(self.compile_form(v))
        return Dict(keys, values)

    def compile_tuple(self, form):
        if not form:
            return Tuple([], Load())

        real_func = self.eval_symbol(form[0])

        # handle special forms (and optimizations)
        if real_func in self.dispatch_by_func:
            fname = self.dispatch_by_func[real_func]
            return getattr(self, fname)(form[1:])

        # handle macro calls
        elif ismacro(real_func):
            return self.compile_macro_call(form, real_func)

        # handle normal function calls
        else:
            return self.compile_func_call(form)

    def compile_macro_call(self, form, real_func):
        # add macro's source module to code dependencies
        if self.do_deps:
            update_deps_info(self.deps, real_func)

        # expand the macro form and compile the resulting form
        form = macroexpand(form, self.globals, self.locals)
        return dont_eval(self.compile_form(form, levelup=False))

    def compile_func_call(self, form):
        func = form[0]
        args, kwargs, star, dstar = process_func_call_args(form[1:])

        return Call(
            self.compile_form(func),
            [self.compile_form(arg) for arg in args],
            [keyword(k, self.compile_form(v)) for k,v in kwargs],
            star is not None and self.compile_form(star) or None,
            dstar is not None and self.compile_form(dstar) or None)

    def compile_do(self, args, levelup=False):
        if len(args) == 0:
            raise SyntaxError, "empty do"
        stmts, tail = args[:-1], args[-1]

        return dont_eval(Do(
            # wrap all the subforms except the last one in Expr to turn
            # them into python statements (Expr is a statement).
            [Expr(self.compile_form(stmt, levelup)) for stmt in stmts] + \
            # the tail is left as an expression.
            [self.compile_form(tail, levelup)]))

    valid_situations = (":compile-toplevel", ":run")

    def compile_eval_when(self, args):
        if len(args) < 2:
            raise SyntaxError, "eval-when takes at least 2 arguments (%d given)" % len(args)
        situations, body = args[0], args[1:]
        if not isinstance(situations, (tuple, list)):
            raise SyntaxError, "eval-when: situations must be a tuple or list, not \"%s\" object" % type(situations).__name__
        #if not situations:
        #    raise SyntaxError, "eval-when: no situations specified"
        for situation in situations:
            if not issymbol(situation) or situation not in self.valid_situations:
                raise SyntaxError, "eval-when: invalid situation"

        compile_toplevel = ":compile-toplevel" in situations
        run              = ":run"              in situations

        # determine whether to process the form (i.e. compile and eval
        # if needed), whether to discard the ast (i.e. if not needed in
        # run-time), and the new eval mode, according to these rules:
        #
        #    mode level CT R  ->  process? discard? new mode
        #    -----------------------------------------------
        #    NCT  0     1  0      1        1        CTT
        #    NCT  0     1  1      1        0        CTT
        #    NCT  > 0   1  0      0        1        -
        #    NCT  > 0   1  1      1        0        NCT
        #    NCT  -     0  1      1        0        NCT
        #    CTT  -     1  0      0        1        -
        #    CTT  -     -  1      1        0        CTT
        #
        if run and self.eval_mode == COMPILE_TIME_TOO or \
           compile_toplevel and self.level == 0 and \
           self.eval_mode == NOT_COMPILE_TIME:
            process = True
            discard = not run
            new_mode = COMPILE_TIME_TOO
        elif run:
            process = True
            discard = False
            new_mode = NOT_COMPILE_TIME
        else:
            process = False

        # process body (compile and potentially eval)
        if process:
            old_mode = self.eval_mode
            self.eval_mode = new_mode
            try:
                ast = self.compile_do(body)
            finally:
                self.eval_mode = old_mode

            if not discard:
                return ast

        # the form will not be run at run-time, so return None
        return self.compile_None()

    def compile_quote(self, args):
        if len(args) != 1:
            raise SyntaxError, "quote takes exactly 1 argument (%d given)" % len(args)
        form = args[0]
        if not hasattr(self, "quoter"):
            self.quoter = QuotingCompiler(self)
        return self.quoter.compile_form(form)

    def compile_quasiquote(self, args):
        if len(args) != 1:
            raise SyntaxError, "quasiquote takes exactly 1 argument (%d given)" % len(args)
        form = args[0]
        # XXX quasiquoter has a state (auto-gensyms) that should either
        # be purged or managed (allowing some sort of inheritence)
        if 1:#not hasattr(self, "quasiquoter"):
            self.quasiquoter = QuasiQuotingCompiler(self)
        return self.quasiquoter.compile_form(form)

    def compile_global(self, args):
        if not args:
            raise SyntaxError, "global takes at least 1 argument (0 given)"
        for name in args:
            if not issymbol(name):
                raise SyntaxError, "global argument must be a symbol, not \"%s\" object" % type(name).__name__

        # update scope
        for name in args:
            self.locals.global_(str(name))

        return Do([
            Global([str(name) for name in args]),
            self.compile_None()])

    # TODO?: raise exception on assignment to qualified names
    #        (and unqualify them in =) (the purpose is to simplify the
    #        behavior)
    def compile_assign_star(self, args):
        if len(args) != 2:
            raise SyntaxError, "=* takes exactly 2 arguments (%d given)" % len(args)
        name, value = args
        if not issymbol(name):
            raise SyntaxError, "can't assign to \"%s\" form" % type(name).__name__
        name = str(unqualify(name))

        # update scope
        self.locals.defs(name)

        return Do([
            Assign([Name(name, Store())],
                   self.compile_form(value)),
            Name(name, Load())
            ])

    def compile_del_star(self, args):
        if not args:
            raise SyntaxError, "del* takes at least 1 argument (0 given)"
        for name in args:
            if not issymbol(name):
                raise SyntaxError, "del* argument must be a symbol, not \"%s\" object" % type(name).__name__

        return Do([
            Delete([Name(str(name), Del()) for name in args]),
            self.compile_None()])

    def compile_if_star(self, args):
        if len(args) < 2:
            raise SyntaxError, "if* takes at least 2 arguments (%d given)" % len(args)
        if len(args) > 3:
            raise SyntaxError, "if* takes at most 3 arguments (%d given)" % len(args)
        if len(args) == 2:
            test, body = args
            orelse = None
        else:
            test, body, orelse = args

        result = str(gensym("if-result"))

        return Do([
            If(
                self.compile_form(test),
                [Assign([Name(result, Store())],
                        self.compile_form(body))],
                [Assign([Name(result, Store())],
                        self.compile_form(orelse))]),
            Name(result, Load())])

    def compile_while_star(self, args):
        if len(args) < 2:
            raise SyntaxError, "while* takes at least 2 arguments (%d given)" % len(args)
        if len(args) > 3:
            raise SyntaxError, "while* takes at most 3 arguments (%d given)" % len(args)
        if len(args) == 2:
            test, body = args
            orelse = None
        else:
            test, body, orelse = args

        not_done = str(gensym("not-done"))

        # the test is evaluated explicitly as part of the body to
        # prevent it from being turned into a name by the unroller, in
        # which case it will have been evaluated only once (the first
        # time).
        return Do([
            Assign([Name(not_done, Store())],
                   self.compile_num(True)),
            While(
                Name(not_done, Load()),
                # test explicitly
                [If(
                    self.compile_form(test),
                    [Pass()],
                    # break is avoided to preserve orelse semantics
                    [Assign([Name(not_done, Store())],
                            self.compile_num(False)),
                     Continue()]),
                 Expr(self.compile_form(body))],
                orelse is not None and [Expr(self.compile_form(orelse))] or []),
            self.compile_None()])

    def compile_pass(self, args):
        if args:
            raise SyntaxError, "pass takes no arguments (%d given)" % len(args)
        return Do([
            Pass(),
            self.compile_None()])

    def compile_continue(self, args):
        if args:
            raise SyntaxError, "continue takes no arguments (%d given)" % len(args)
        return Do([
            Continue(),
            self.compile_None()])

    def compile_break(self, args):
        if args:
            raise SyntaxError, "break takes no arguments (%d given)" % len(args)
        return Do([
            Break(),
            self.compile_None()])

    def compile_func_arg(self, arg):
        if isinstance(arg, (tuple, list)):
            return Tuple([self.compile_func_arg(a) for a in arg], Store())
        # otherwise must be a string
        return Name(arg, Store())

    def compile_func_body(self, name, body, args, star, dstar):
        self.push_scope()
        try:
            # update scope with local vars
            for arg in flatten(args):
                self.locals.defs(arg)
            if star:  self.locals.defs(star)
            if dstar: self.locals.defs(dstar)

            ast = self.compile_do(body, levelup=True)
            if name == "__init__" or has_yield(ast):
                # this is a generator or an __init__, don't return implicitly
                return Expr(ast)
            else:
                # if this a normal function, an implicit return is added
                return Return(ast)
        finally:
            self.pop_scope()

    def compile_func(self, full_args):
        if len(full_args) < 3:
            raise SyntaxError, "special form \"func\" takes at least 3 arguments (%d given)" % len(full_args)
        (name, raw_args), body = full_args[:2], full_args[2:]
        if not issymbol(name):
            raise SyntaxError, "function name must be a symbol, not \"%s\" object" % type(name).__name__
        name = str(unqualify(name))
        if not isinstance(raw_args, (tuple, list)):
            raise SyntaxError, "function arguments must be a tuple or list, not \"%s\" object" % type(raw_args).__name__
        args, defaults, star, dstar = process_func_def_args(raw_args)

        # a unique symbol is used to prevent overriding a local name.
        tmp_name = str(gensym(name))

        # function and class definitions are wrapped in a temporary class
        # to avoid cluttering the namespace, but still use the correct
        # name in the inner function/class. a metaclass unwraps the outer
        # class and causes the correctly-named inner function/class to be
        # assigned to the temporary name of the outer class.
        return Do([
            ClassDef(
                tmp_name, [], [
                    FunctionDef(
                        name,
                        arguments(
                            [self.compile_func_arg(arg) for arg in args],
                            star,
                            dstar,
                            [self.compile_form(d) for d in defaults]),
                        [self.compile_func_body(name, body, args, star, dstar)],
                        []),
                    Assign([Name(tmp_name, Store())],
                        Name(name, Load())),
                    Assign([Name("__metaclass__", Store())],
                           Call(Name(self.get_ggs("mk-unwrap-metaclass"), Load()),
                                [Str(tmp_name)],
                                [], None, None))],
                []),
            Name(tmp_name, Load())])

    def compile_macro(self, full_args):
        # TODO: support &env
        if len(full_args) < 3:
            raise SyntaxError, "special form \"macro\" takes at least 3 arguments (%d given)" % len(full_args)
        name = full_args[0]
        if not issymbol(name):
            raise SyntaxError, "macro name must be a symbol, not \"%s\" object" % type(name).__name__
        name = str(unqualify(name))

        # a unique symbol is used to prevent overriding a local name.
        tmp_name = str(gensym(name))

        return Do([
            Assign([Name(tmp_name, Store())],
                   self.compile_func(full_args)),
            # turn func into a macro
            Assign([Name(tmp_name, Store())],
                   Call(Name(self.get_ggs("mk-macro"), Load()),
                        [Name(tmp_name, Load())],
                        [], None, None)),
            Name(tmp_name, Load())])

    def compile_return_star(self, args):
        if len(args) != 1:
            raise SyntaxError, "return* takes exactly 1 argument (%d given)" % len(args)
        return Do([
            Return(self.compile_form(args[0])),
            self.compile_None()])

    def compile_yield_star(self, args):
        if len(args) != 1:
            raise SyntaxError, "yield* takes exactly 1 argument (%d given)" % len(args)
        return Yield(self.compile_form(args[0]))

    def compile_class_body(self, body):
        self.push_scope(inheritable=False)
        try:
            return Expr(self.compile_do(body, levelup=True))
        finally:
            self.pop_scope()

    def compile_class_star(self, args):
        if len(args) < 3:
            raise SyntaxError, "class* takes at least 3 arguments (%d given)" % len(args)
        (name, bases), body = args[:2], args[2:]
        if not issymbol(name):
            raise SyntaxError, "class name must be a symbol, not \"%s\" object" % type(name).__name__
        name = str(unqualify(name))
        if issymbol(bases):
            bases = [bases]
        if not isinstance(bases, (tuple, list)):
            raise SyntaxError, "class base must be a symbol, tuple or list, not \"%s\" object" % type(bases).__name__

        # a unique symbol is used to prevent overriding a local name.
        tmp_name = str(gensym(name))

        # function and class definitions are wrapped in a temporary class
        # to avoid cluttering the namespace, but still use the correct
        # name in the inner function/class. a metaclass unwraps the outer
        # class and causes the correctly-named inner function/class to be
        # assigned to the temporary name of the outer class.
        return Do([
            ClassDef(
                tmp_name, [], [
                    ClassDef(
                        name,
                        [self.compile_form(base) for base in bases],
                        [self.compile_class_body(body)],
                        []),
                    Assign([Name(tmp_name, Store())],
                        Name(name, Load())),
                    Assign([Name("__metaclass__", Store())],
                           Call(Name(self.get_ggs("mk-unwrap-metaclass"), Load()),
                                [Str(tmp_name)],
                                [], None, None))],
                []),
            Name(tmp_name, Load())])

    def compile_try_finally(self, args):
        if len(args) != 2:
            raise SyntaxError, "try-finally takes exactly 2 arguments (%d given)" % len(args)
        body, finalbody = args

        result = str(gensym("try-finally-result"))

        return Do([
            TryFinally(
                [Assign([Name(result, Store())],
                        self.compile_form(body))],
                [Expr(self.compile_form(finalbody))]),
            Name(result, Load())])

    def compile_except_handler(self, result, handler):
        if not isinstance(handler, (tuple, list)):
            raise SyntaxError, "try-except handler clause must be a tuple or list, not \"%s\" object" % type(handler).__name__
        if len(handler) != 3:
            raise SyntaxError, "try-except handler clause must have exactly 3 members (%d given)" % len(handler)
        type_, name, body = handler
        if not issymbol(name) and name is not None:
            raise SyntaxError, "try-except: exception name must be a symbol or None, not \"%s\" object" % type(name).__name__
        if issymbol(type_) and unqualify(type_) == "None":
            # TODO: make the stack relevant
            warn("try-except: symbol \"None\" given as exception type", SyntaxWarning)
        if issymbol(name):
            if unqualify(name) == "None":
                # TODO: make the stack relevant
                warn("try-except: symbol \"None\" given as exception name", SyntaxWarning)
            # update scope
            self.locals.defs(name)

        return ExceptHandler(
            type_ is not None and self.compile_form(type_) or None,
            name is not None and Name(str(name), Store()) or None,
            [Assign([Name(result, Store())],
                    self.compile_form(body))])

    def compile_try_except(self, args):
        if len(args) < 2:
            raise SyntaxError, "try-except takes at least 2 arguments (%d given)" % len(args)
        if len(args) > 3:
            raise SyntaxError, "try-except takes at most 3 arguments (%d given)" % len(args)
        if len(args) == 2:
            body, handlers = args
            orelse = None
        else:
            body, handlers, orelse = args
        if not isinstance(handlers, (tuple, list)):
            raise SyntaxError, "try-except handlers must be a tuple or list, not \"%s\" object" % type(handlers).__name__

        result = str(gensym("try-except-result"))

        return Do([
            TryExcept(
                [Assign([Name(result, Store())],
                        self.compile_form(body))],
                [self.compile_except_handler(result, h) for h in handlers],
                orelse is not None and \
                    [Assign([Name(result, Store())],
                            self.compile_form(orelse))] or \
                    []),
            Name(result, Load())])

#-----------------------------------------------------------

class QuotingCompiler:
    def __init__(self, compiler):
        # "inheritence"
        self.dispatch_by_type = compiler.dispatch_by_type
        self.get_ggs = compiler.get_ggs
        self.compile_num = compiler.compile_num
        self.compile_str = compiler.compile_str
        self.compile_None = compiler.compile_None

    def compile_form(self, form):
        # dispatch according to form type
        form_type = type(form)
        try:
            fname = self.dispatch_by_type[form_type]
        except KeyError:
            raise SyntaxError, "unsupported form type \"%s\"" % form_type.__name__
        return getattr(self, fname)(form)

    def compile_symbol(self, sym):
        return Call(
            Name(self.get_ggs("symbol"), Load()),
            [Str(str(sym))],
            [], None, None)

    def compile_tuple(self, tpl):
        return Tuple(
            [self.compile_form(form) for form in tpl],
            Load())

    def compile_list(self, lst):
        return List(
            [self.compile_form(form) for form in lst],
            Load())

    def compile_dict(self, dct):
        keys = []
        values = []
        for k,v in dct.iteritems():
            keys.append(self.compile_form(k))
            values.append(self.compile_form(v))
        return Dict(keys, values)

#-----------------------------------------------------------

# TODO?: awareness to gensyms in wrapping forms, even if separately quasiquoted
class QuasiQuotingCompiler:
    # dispatch tables for quoting-related special forms
    dispatch_by_func = {
        vars(__lispy__)["quasiquote"]:       "compile_quasiquote",
        vars(__lispy__)["unquote"]:          "compile_unquote",
        vars(__lispy__)["unquote-splicing"]: "compile_unquote_splicing",
        }
    dispatch_by_func_in_seq = {
        vars(__lispy__)["quasiquote"]:       "compile_quasiquote_in_seq",
        vars(__lispy__)["unquote"]:          "compile_unquote_in_seq",
        vars(__lispy__)["unquote-splicing"]: "compile_unquote_splicing_in_seq",
        }

    def __init__(self, compiler):
        self.compiler = compiler
        self.quote_level = 0
        self.auto_gensyms_dict_name = None
        self.auto_gensyms = {}
        # "inheritence"
        self.dispatch_by_type = compiler.dispatch_by_type
        self.eval_symbol = compiler.eval_symbol
        self.get_ggs = compiler.get_ggs
        self.compile_num = compiler.compile_num
        self.compile_str = compiler.compile_str
        self.compile_None = compiler.compile_None

    def compile_form(self, form):
        ast = self.compile_internal_form(form)
        if self.auto_gensyms_dict_name:
            # if needed, generate auto-gensyms dictionary per invocation
            # (in runtime), since the gensyms must be different for each
            # invocation.
            ast = Do([
                Assign([Name(self.auto_gensyms_dict_name, Store())],
                        Dict([],[])),
                ast])
        return ast

    def compile_internal_form(self, form):
        # dispatch according to form type
        form_type = type(form)
        try:
            fname = self.dispatch_by_type[form_type]
        except KeyError:
            raise SyntaxError, "unsupported form type \"%s\"" % form_type.__name__
        return getattr(self, fname)(form)

    def compile_symbol(self, sym):
        # handle auto-gensyms
        if self.quote_level == 0 and \
           sym[0] == sym[-1] == "." and sym.count(".") != len(sym):

            if not self.auto_gensyms_dict_name:
                self.auto_gensyms_dict_name = str(gensym("auto-gensyms-dict"))
            # lookup the auto-gensym name in runtime, since it must be
            # different for each invocation.
            sym_ast = Do([
                If(
                    Compare(
                        Str(str(sym)),
                        [NotIn()],
                        [Name(self.auto_gensyms_dict_name, Load())]),
                    [Assign(
                        [Subscript(
                            Name(self.auto_gensyms_dict_name, Load()),
                            Index(Str(str(sym))),
                            Store())],
                        Call(
                            Name(self.get_ggs("str"), Load()),
                            [Call(
                                Name(self.get_ggs("gensym"), Load()),
                                [Str(str(sym[1:-1]))],
                                [], None, None)],
                            [], None, None)
                        )],
                    []),
                Subscript(
                    Name(self.auto_gensyms_dict_name, Load()),
                    Index(Str(str(sym))),
                    Load())])

        # qualify symbol
        else:
            sym_ast = Str(str(qualify(sym, self.compiler.globals, self.compiler.locals)))

        return Call(
            Name(self.get_ggs("symbol"), Load()),
            [sym_ast],
            [], None, None)

    def compile_list(self, lst):
        return Call(
            Name(self.get_ggs("list"), Load()),
            [self.compile_seq(lst)],
            [], None, None)

    def compile_dict(self, dct):
        items = chain(*dct.iteritems())
        return Call(
            Name(self.get_ggs("dict*"), Load()),
            [], [],
            self.compile_seq(items, is_dict=True), None)

    def compile_tuple(self, tpl):
        if not tpl:
            return Tuple([], Load())

        real_func = self.eval_symbol(tpl[0])

        # handle special quoting forms
        if real_func in self.dispatch_by_func:
            fname = self.dispatch_by_func[real_func]
            return getattr(self, fname)(tpl)

        # quote normally
        return Call(
            Name(self.get_ggs("tuple"), Load()),
            [self.compile_seq(tpl)],
            [], None, None)

    def compile_seq(self, seq, is_dict=False):
        # this could be improved in terms of run-time performance when
        # unquote-splicing is not used (e.g. in dictionaries), since the
        # resulting sequence can be created in compile-time.
        iterables = []
        for form in seq:
            if type(form) == tuple and form:
                # handle special quoting forms
                real_func = self.eval_symbol(form[0])
                if real_func in self.dispatch_by_func_in_seq:
                    fname = self.dispatch_by_func_in_seq[real_func]
                    sub_seq = getattr(self, fname)(form, is_dict)
                    iterables.append(sub_seq)
                    continue

            # quote normally
            sub_seq = Tuple([self.compile_internal_form(form)], Load())
            iterables.append(sub_seq)

        return Call(
            Name(self.get_ggs("chain"), Load()),
            iterables,
            [], None, None)

    def quote_special_tuple(self, tpl, level_change):
        self.quote_level += level_change
        try:
            return Tuple(
                [self.compile_internal_form(form) for form in tpl],
                Load())
        finally:
            self.quote_level -= level_change

    def compile_quasiquote(self, tpl):
        # keep quoting, but increase level
        return self.quote_special_tuple(tpl, 1)

    def compile_quasiquote_in_seq(self, tpl, is_dict):
        # wrap the form in a tuple for splicing
        result = self.compile_quasiquote(tpl)
        return Tuple([result], Load())

    def compile_unquote(self, tpl):
        if self.quote_level == 0:
            # do the unquote
            if len(tpl) != 2:
                raise SyntaxError, "unquote takes exactly 1 argument (%d given)" % (len(tpl)-1)
            return self.compiler.compile_form(tpl[1])
        else:
            # keep quoting, but decrease level
            return self.quote_special_tuple(tpl, -1)

    def compile_unquote_in_seq(self, tpl, is_dict):
        # wrap the result in a tuple for splicing
        result = self.compile_unquote(tpl)
        return Tuple([result], Load())

    def compile_unquote_splicing(self, tpl):
        if self.quote_level == 0:
            raise SyntaxError, "unquote-splicing not in sequence"
        else:
            # keep quoting, but decrease level
            return self.quote_special_tuple(tpl, -1)

    def compile_unquote_splicing_in_seq(self, tpl, is_dict):
        if self.quote_level == 0:
            # do the unquote
            if is_dict:
                raise SyntaxError, "unquote-splicing not allowed in dictionary"
            if len(tpl) != 2:
                raise SyntaxError, "unquote-splicing takes exactly 1 argument (%d given)" % (len(tpl)-1)
            return self.compiler.compile_form(tpl[1])
        else:
            # wrap the form in a tuple for splicing
            result = self.compile_unquote_splicing(tpl)
            return Tuple([result], Load())

#-----------------------------------------------------------------------
# testing

if __name__ == "__main__":
    import __builtin__
    from traceback import format_exception_only
    from lispy.reader import read

    def exc_text():
        return format_exception_only(sys.exc_type, sys.exc_value)[0].rstrip()

    def eval_text(text):
        globals, locals = _init_envs(None, None)
        try:    result = eval_(read(text), globals, locals)
        except: print "%r => *** %s ***" % (text, exc_text())
        else:   print "%r => %r" % (text, result)
        sys.stdout.flush()

    def eval_form(form):
        globals, locals = _init_envs(None, None)
        try:    result = eval_(form, globals, locals)
        except: print "%r => *** %s ***" % (form, exc_text())
        else:   print "%s => %r" % (form, result)
        sys.stdout.flush()

    print "constants:"
    eval_text("3")
    eval_text("3L")
    eval_text("3.5")
    eval_text("3j")
    eval_text('"a string"')
    eval_text('u"a string"')
    eval_form(True)
    eval_form(False)
    eval_form(None)
    eval_form(__builtin__.Ellipsis)
    eval_text("[1 2 3 4]")
    eval_text("{1 2 3 4}")
    # errors:
    print "constants errors:"
    eval_form(eval_form)

    print "\nsymbols:"
    eval_text(":keyword")
    eval_text(".startswith")
    eval_text("len.__name__")
    eval_text("len.__class__.__name__")
    eval_text("__builtin__:len")
    eval_text("__builtin__:len.__name__") # XXX
    eval_text("os.path:join")
    eval_text("os.path:join.__name__")
    eval_text("do")
    eval_text("len")
    eval_text("...")
    eval_text("(=* len 5) (print len) (del* len)")
    print "symbols errors:"
    eval_text("noname")
    eval_text("noname.__name__")
    eval_text("len.noattr")
    eval_text("__builtin__:noname")
    eval_text("__main__:noname")
    eval_text("nomodule:noname")
    eval_text("__builtin__:.startswith")

    print "\nfunction calls:"
    eval_text("(min 1 2 3)")
    eval_text('(min "aaa" "bb" "c" :key len)')
    eval_text('(min :key len &* ["aaa" "bb" "c"])')
    eval_text('(min &* ["aaa" "bb" "c"] &** {"key" len})')
    # TODO: nested args
    # errors: TODO

    print "\neval-when:"
    # top-level
    eval_text('(eval-when [:compile-toplevel] (print "COMPILE-TIME") 1)')
    eval_text('(eval-when [:run] (print "RUN-TIME") 1)')
    eval_text('(eval-when [:compile-toplevel :run] (print "COMPILE-TIME OR RUN-TIME") 1)')
    # non-top-level
    eval_text('(if* 1 (eval-when [:compile-toplevel] (print "NEVER") 1))')
    eval_text('(if* 1 (eval-when [:run] (print "RUN-TIME") 1))')
    eval_text('(if* 1 (eval-when [:compile-toplevel :run] (print "RUN-TIME") 1))')
    # nested, top-level
    eval_text('(eval-when [:compile-toplevel] (eval-when [:compile-toplevel] (print "NEVER") 1))')
    eval_text('(eval-when [:compile-toplevel] (eval-when [:run] (print "COMPILE-TIME") 1))')
    eval_text('(eval-when [:compile-toplevel] (eval-when [:compile-toplevel :run] (print "COMPILE-TIME") 1))')
    eval_text('(eval-when [:run] (eval-when [:compile-toplevel] (print "COMPILE-TIME") 1))')
    eval_text('(eval-when [:run] (eval-when [:run] (print "RUN-TIME") 1))')
    eval_text('(eval-when [:run] (eval-when [:compile-toplevel :run] (print "COMPILE-TIME OR RUN-TIME") 1))')
    eval_text('(eval-when [:compile-toplevel :run] (eval-when [:compile-toplevel] (print "NEVER") 1))')
    eval_text('(eval-when [:compile-toplevel :run] (eval-when [:run] (print "COMPILE-TIME OR RUN-TIME") 1))')
    eval_text('(eval-when [:compile-toplevel :run] (eval-when [:compile-toplevel :run] (print "COMPILE-TIME OR RUN-TIME") 1))')
    # nested, non-top-level
    eval_text('(if* 1 (eval-when [:compile-toplevel] (eval-when [:compile-toplevel] (print "NEVER") 1)))')
    eval_text('(if* 1 (eval-when [:compile-toplevel] (eval-when [:run] (print "NEVER") 1)))')
    eval_text('(if* 1 (eval-when [:compile-toplevel] (eval-when [:compile-toplevel :run] (print "NEVER") 1)))')
    eval_text('(if* 1 (eval-when [:run] (eval-when [:compile-toplevel] (print "NEVER") 1)))')
    eval_text('(if* 1 (eval-when [:run] (eval-when [:run] (print "RUN-TIME") 1)))')
    eval_text('(if* 1 (eval-when [:run] (eval-when [:compile-toplevel :run] (print "RUN-TIME") 1)))')
    eval_text('(if* 1 (eval-when [:compile-toplevel :run] (eval-when [:compile-toplevel] (print "NEVER") 1)))')
    eval_text('(if* 1 (eval-when [:compile-toplevel :run] (eval-when [:run] (print "RUN-TIME") 1)))')
    eval_text('(if* 1 (eval-when [:compile-toplevel :run] (eval-when [:compile-toplevel :run] (print "RUN-TIME") 1)))')
    # errors:
    print "eval-when errors:"
    eval_text("(eval-when)")
    eval_text("(eval-when 1 2 3 4 5)")
    eval_text("(eval-when [] 1 2 3 4 5)")
    eval_text("(eval-when [:invalid] 1 2 3 4 5)")

    print "\ndo:"
    eval_text("(do 1 2 3 4 5)")
    # errors:
    print "do errors:"
    eval_text("(do)")
    
    print "\nquote:"
    eval_text("(quote name)")
    eval_text('(quote (print 1 2 3 "text"))')
    eval_text("(quote [a b c])")
    eval_text("(quote {a b c d})")
    # errors:
    print "quote errors:"
    eval_text("(quote 1 2 3)")

    print "\nquasiquote:"
    eval_text("`name")
    eval_text("`len")
    eval_text("`[.tmp. .tmp.]")
    eval_text('`(print 1 2 3 "text")')
    eval_text("`[a b c]")
    eval_text("`{a b c d}")
    eval_text("`(1 ,(+ 1 1) 3 ,@[4 5])")
    eval_text("`[,@(tuple [1 2 3 4 5])]")
    # nesting:
    eval_text('``,,"abcd"')
    eval_text('``,@,"abcd"')
    eval_text('``,[,@"abcd"]')
    # errors:
    print "quasiquote errors:"
    eval_text("(quasiquote 1 2 3)")
    eval_text("`(unquote 1 2 3)")
    eval_text("`,@form")
    eval_text("`{a b c ,@d}")
    eval_text("`[(unquote-splicing 1 2 3)]")
    eval_text("`[,@1]")

    print "\nassignment:"
    eval_text("(=* a 4)")
    eval_text("a")
    eval_text("(=* __builtin__:b 5)")
    eval_text("b")
    # errors:
    print "assignment errors:"
    eval_text("__builtin__:b")
    eval_text("(=* 3 4)")
    eval_text("(=* 3 4 5)")

    print "\ndel*:"
    eval_text("(del* a)")
    eval_text("a")
    print "del* errors:"
    eval_text("(del*)")
    
    print "\nif*:"
    eval_text("(if* 1 2 3)")
    eval_text("(if* 0 2 3)")
    eval_text("(if* 1 2)")
    eval_text("(if* 0 2)")
    # errors:
    print "if* errors:"
    eval_text("(if* 1 2 3 4)")
    eval_text("(if* 1)")

    print "\nwhile*:"
    eval_text("(=* x 1) (while* (<= x 3) (do (print x) (=* x (+ x 1))))")
    eval_text("(=* x 1) (while* (<= x 2) (do (print x) (=* x (+ x 1))) (print 3))")
    eval_text("(while* 0 (print 1) (print 2))")
    eval_text("(while* 1 (do (print 1) (break)) (print 2))")
    eval_text("(=* x 0) (while* (<= x 3) (do (=* x (+ x 1)) (if* (not (% x 2)) (continue)) (print x)))")
    # (do) in the condition
    eval_text("(=* x 0) (while* (do (=* x (+ x 1)) (<= x 3)) (print x))")
    # errors:
    print "while* errors:"
    eval_text("(while* 1 2 3 4)")
    eval_text("(while* 1)")

    print "\npass:"
    eval_text("(pass)")
    # errors:
    print "pass errors:"
    eval_text("(pass 1 2 3)")

    print "\nfunction definition:"
    eval_text("(func f () 1)")
    eval_text("(func __metaclass__ () 1)")
    eval_text("(func nomodule:f () 1)")
    eval_text("((func f () 1))")
    eval_text("((func f [] 1))") # TODO: fix
    eval_text("((func f () 1 2))")
    eval_text("((func f () 1 (return* 2)))")
    eval_text("((func f (x) x) 3)")
    eval_text("((func f (x y) (+ x y)) 3 1)")
    eval_text("((func f (x :y 1) (+ x y)) 3)")
    eval_text("((func f (x :y 1) (+ x y)) 3 2)")
    eval_text("((func f ([x y] &* a) (+ x y)) [3 2])") # TODO: remove the &* a
    eval_text("((func f (&* args) (+ &* args)) 1 2 3)")
    eval_text("((func f (&** kwargs) kwargs) :a 1 :b 2 :c 3)")
    # errors:
    print "function definition errors:"
    eval_text("(func 1 () 1)")
    eval_text("(func f 1 1)")

    print "\ngenerator definition:"
    eval_text("((func g () (yield* 2)))")
    eval_text("(.next ((func g () (yield* 2))))")
    # errors: TODO
    #print "generator definition errors:"

    print "\nmacro definition:"
    eval_text("(macro m () `(+ 1 1))")
    eval_text("(macro? (macro m () `(+ 1 1)))")
    eval_text("(=* m (macro m () `(+ 1 1))) (__main__:macroexpand `(m))") # XXX
    eval_text("(=* m (macro m () `(+ 1 1))) (m)")
    # errors: TODO
    print "macro definition errors:"
    eval_text("((macro m () `(+ 1 1)))")

    print "\nclass definition:"
    eval_text("(class* C () (pass))")
    eval_text("(class* C [] (pass))")
    eval_text("(((class* C [] (=* __call__ (func __call__ (self) 1)))))")
    # TODO: test metaclass
    # errors:
    print "class definition errors:"
    eval_text("(class* 1 () (pass))")
    eval_text("(class* C 1 (pass))")

    print "\ntry-finally:"
    eval_text("(try-finally 1 2)")
    eval_text('(try-finally 1 (print "finally reached"))')
    eval_text('(try-finally (raise (RuntimeError "(not really)")) (print "finally reached"))')
    # errors:
    print "try-finally errors:"
    eval_text("(try-finally 1 2 3)")

    print "\ntry-except:"
    eval_text("(try-except 1 [])")
    eval_text("(try-except 1 [] 2)")
    eval_text("(try-except 1 [[RuntimeError e 2]] 3)")
    eval_text("(try-except (raise (RuntimeError)) [[RuntimeError e 2]] 3)")
    eval_text("(eval_ `(try-except (raise (RuntimeError)) [[RuntimeError e 2] [,None ,None 3]] 4))")
    eval_text("(eval_ `(try-except (raise (SyntaxError)) [[RuntimeError e 2] [,None ,None 3]] 4))")
    # errors:
    print "try-except errors:"
    eval_text("(try-except 1)")
    eval_text("(try-except 1 2)")
    eval_text("(try-except 1 2 3 4)")
    eval_text("(try-except 1 [2] 3)")
    eval_text("(try-except 1 [[2]] 3)")
    eval_text("(try-except 1 [[2 3 4]] 5)")
    eval_text("(try-except 1 [[None None 3]] 4)")

    #print "\nscopes:"
    #eval_text("((lambda () y))")
    #eval_text("(=*  y 1) ((lambda () y))")
    print "\nscopes: locals-is-globals:"
    eval_text("(=* z 1) `z")
    print "scopes: locals-is-not-globals:"
    def temp():
        eval_text("(=* z 1) `z")
    temp()
    # eval-when
    # eval-symbol (for primitives and macros)
    # macro expansion?

    print "\nscopes: qualification (effective):"
    #eval_text("`x")
    eval_text("((lambda () `x))")
    eval_text("((lambda () ((lambda () `x))))")
    eval_text("(class* C [] (print `x))")
    eval_text("(class* C [] (class* D [] (print `x)))")
    eval_text("(class* C [] (=* x 1) (class* D [] (print `x)))")
    eval_text("((lambda () (class* C [] (print `x))))")
    eval_text("(class* C [] ((lambda () (print `x))))")
    eval_text("(class* C [] (=* x 1) ((lambda () (print `x))))")

    print "\nscopes: qualification (shadowing):"
    eval_text("((lambda (x) `x) 1)")
    eval_text("((lambda () (=* x 1) `x))")
    eval_text("((lambda () (=* x 1) ((lambda () `x))))")
    eval_text("(class* C [] (=* x 1) (print `x))")
    eval_text("((lambda () (=* x 1) (class* C [] (print `x))))")

    print "\nscopes: global:"
    eval_text("((lambda () (global x) (=* x 1) `x))")
    eval_text("((lambda () (global x) (=* x 1) ((lambda () `x))))")
    eval_text("(class* C [] (global x) (=* x 1) (print `x))")
    eval_text("((lambda () (global x) (=* x 1) (class* C [] (print `x))))")

    # errors:
    print "\nscopes errors:"
    eval_text("(global)")
    #eval_text("((lambda () x (=*  x 1)))")
