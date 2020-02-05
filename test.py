import sys
import os
from lispy.runtime import get_docstring
from lispy.compiler import eval_

def load_file(file, name=None, full_import=True, loader=None):
    if isinstance(file, (str,unicode)):
        file = open(file,"U")

    if hasattr(file, "name"):
        # TODO?: apparently abspath is not py behavior
        filename = os.path.abspath(file.name)
        is_init = filename.endswith("__init__.ly") or filename.endswith("__init__.lpy")
    else:
        filename = None
        is_init = False

    if name is None:
        if filename is not None:
            name = os.path.basename(filename)
            name = os.path.splitext(name)[0]

    from lispy.reader import read
    form = read(file)

    # initialize module object
    if full_import and name is not None and \
       sys.modules.has_key(name):
        module = sys.modules[name]
        assert hasattr(module, "__name__"), "module %s has no __name__!" % name
        module.__doc__ = get_docstring(form)
    else:
        make_module = type(sys)
        module = make_module(name or "<anonymous_lispy_module>",
                             get_docstring(form))
    # initialize module attrs
    module.__file__ = filename
    if loader is not None:
        module.__loader__ = loader
    if is_init:
        module.__path__ = [os.path.dirname(filename)]
        module.__package__ = name
    elif name is None and "." in name:
        module.__package__ = ".".join(name.split(".")[:-1])
    else:
        module.__package__ = None

    if full_import and name is not None:
        sys.modules[name] = module

    # evaluate module code
    eval_(form, module.__dict__)

    return module

#-----------------------------------------------------------------------

core = load_file("core.lpy")

import __lispy__
for name in core.__all__:
    setattr(__lispy__, name, getattr(core, name))

load_file("more.lpy")
