#!/usr/bin/python
import sys
import getopt

from lispy import version

#-----------------------------------------------------------------------

USAGE1 = "usage: lispy [options] ... [-c prg | file | -] [arg] ..."
USAGE2 = "Try \"lispy -h\" for more information."
USAGE3 = """\
Options and arguments:
-c prg : program passed in as a string
-h     : print this help message and exit
-V     : print the Lispy version number and exit
file   : program read from script file
-      : program read from stdin
arg... : arguments passed to program in sys.argv[1:]"""

# TODO: support __doc__ when available
def _fix_main(filename=None):
    import __main__, __builtin__

    __main__.__dict__.clear()
    __main__.__name__ = "__main__"
    __main__.__doc__ = None
    __main__.__package__ = None
    __main__.__builtins__ = __builtin__
    if filename:
        __main__.__file__ = filename

    return __main__.__dict__

# TODO?: store the lispy script name (sys.argv[0]) somewhere?
def main():
    from lispy.compiler import eval_str, eval_file
    from lispy.repl import interact

    try:
        opts, args = getopt.getopt(sys.argv[1:], "c:hV")
    except getopt.GetoptError, e:
        # usage error
        print e
        print USAGE1
        print USAGE2
        return 2
        
    for opt, arg in opts:
        # program passed in as a string
        if opt == "-c":
            sys.argv = ["-c"] + sys.argv[3:]
            main_env = _fix_main()
            #TODO: improve trackbacks (like in std module code)
            eval_str(arg, main_env)
            return 0

        # print help message and exit
        elif opt == "-h":
            print USAGE1
            print USAGE3
            return 0

        # print the Lispy version number and exit
        elif opt == "-V":
            print "Lispy " + version
            return 0

    if len(args) == 0:
        # interactive mode
        sys.argv[0] = ""
        main_env = _fix_main()
        interact(locals = main_env)

    else:
        # run script
        filename = args[0]
        if filename == '-':
            f = sys.stdin
            filename = "<stdin>"
        else:
            f = open(filename,"U")

        sys.argv = sys.argv[1:]
        main_env = _fix_main(filename)
        #TODO: improve trackbacks (like in std module code)
        eval_file(f, main_env, filename="__main__")

    return 0

#-----------------------------------------------------------------------

if __name__ == '__main__':
    sys.exit(main())

