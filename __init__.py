"""
lispy (lispy python)

goals:
* lisp-like data-stucture representation of python code
* lisp-like macros

design points:
* share python's data model, functionalize control structures
* lisp-like syntax
* be as easy as possible to understand for python programmers
* python orthogonality (reflect underlying python behavior, capabilities and performance)
* minimal python "microcode"

started Dec.4.2009.
"""

version = "pre-0.1"
version_info = (0, 0, 0)

# this initializes the __lispy__ module
from lispy import runtime
runtime.init_lispy()
