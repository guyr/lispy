import sys
import os
import marshal

from lispy.reader import read
from lispy.importlib import _find_module
from lispy.importlib.machinery import SourceLoader, FileLoaderMixin

#-----------------------------------------------------------------------
# cahed code dependencies

DEPS_INFO_PREFIX = "lispy-deps-info:"

def deps_info_to_str(deps):
    #print "DEPS: %r" % (DEPS_INFO_PREFIX + marshal.dumps(deps))
    return DEPS_INFO_PREFIX + marshal.dumps(deps)

def get_deps_info(code):
    """extract deps info from code object"""
    for const in reversed(code.co_consts):
        if isinstance(const, (str, unicode)):
            if const.startswith(DEPS_INFO_PREFIX):
                deps_str = const[len(DEPS_INFO_PREFIX):]
                try: return marshal.loads(deps_str)
                except:
                    raise ValueError, "bad deps info"
            else:
                break
    # code object has no deps info
    return {}

def cache_from_source(filename):
    # XXX make sure this reflects the py 3 imp.cache_from_source
    pos = filename.rfind(".")
    if pos:
        filename = filename[:pos]
    return filename + ".pyc"

def get_dep_module_info_from_loader(name, loader):
    if hasattr(loader, "get_filename") and \
       hasattr(loader, "path_mtime"):
        source_filename = loader.get_filename(name)
        cache_filename = cache_from_source(source_filename)

        try: source_mtime = loader.path_mtime(source_filename)
        except NotImplementedError:
            return None
        try: cache_mtime = loader.path_mtime(cache_filename)
        except NotImplementedError, OSError:
            cache_filename = cache_mtime = None

        return (source_filename, source_mtime, cache_filename, cache_mtime)
    return None

def get_dep_module_info_from_filename(filename):
    if os.path.exists(filename):
        try: mtime = int(os.stat(filename).st_mtime)
        except OSError:
            return None

        if filename[-4:].lower() in ('.pyc', '.pyo'):
            # TODO?: use imp.source_from_cache if available?
            cache_filename = filename
            cache_mtime = mtime
            source_filename = filename[:-4] + '.py'
            try: source_mtime = int(os.stat(source_filename).st_mtime)
            except OSError:
                source_filename = source_mtime = None
        else:
            source_filename = filename
            source_mtime = mtime
            cache_filename = cache_from_source(source_filename)
            try: cache_mtime = int(os.stat(cache_filename).st_mtime)
            except OSError:
                cache_filename = cache_mtime = None

        return (source_filename, source_mtime, cache_filename, cache_mtime)

def get_dep_module_info(name):
    if name in sys.modules:
        module = sys.modules[name]
        # try getting filename info from loader (for modules loaded
        # with importlib)
        if hasattr(module, "__loader__"):
            loader = module.__loader__
            info = get_dep_module_info_from_loader(name, loader)
            if info:
                return info
        # assume file-system python module
        if hasattr(module, "__file__"):
            return get_dep_module_info_from_filename(module.__file__)
    return None

def get_parent_path(name):
    parent = name.rpartition('.')[0]
    if parent and parent in sys.modules:
        parent_module = sys.modules[parent]
        if hasattr(parent_module, "__path__"):
            return parent_module.__path__
    return None

def update_deps_info(deps, func):
    if func.__module__ is not None:
        name = func.__module__
        if name not in deps:
            info = get_dep_module_info(name)
            if info:
                deps[name] = info + (get_parent_path(name),)
                #print "MACRO", func.__name__, "from", name,
                #print "->", filename, mtime, get_parent_path(name)

def verify_code_deps(code):
    # TODO?: raise ImportError on bad deps-info?
    deps_info = get_deps_info(code)
    #print "DEPS-INFO:",deps_info

    for name, info in deps_info.iteritems():
        #print "verifying",name
        source_filename, source_mtime, cache_filename, cache_mtime, path = info

        # check modules that are already imported
        info2 = get_dep_module_info(name)
        if info2:
            source_filename2, source_mtime2, cache_filename2, cache_mtime2 = info2
            if source_filename2:
                if source_filename != source_filename2 or source_mtime != source_mtime2:
                    return False
            if cache_filename2:
                if cache_filename != cache_filename2 or cache_mtime != cache_mtime2:
                    return False

        # check modules that are not yet imported
        else:
            try: loader = _find_module(name, path)
            except ImportError:
                # XXX should force re-compilation?
                pass
            else:
                info2 = get_dep_module_info_from_loader(name, loader)
                if info2:
                    source_filename2, source_mtime2, cache_filename2, cache_mtime2 = info2
                    if source_filename2:
                        if source_filename != source_filename2 or source_mtime != source_mtime2:
                            return False
                    if cache_filename2:
                        if cache_filename != cache_filename2 or cache_mtime != cache_mtime2:
                            return False
                    # check if this dependecy module would be recompiled
                    if cache_filename and hasattr(loader, "get_cached_code"):
                        try: dep_code = loader.get_cached_code(name)
                        except ImportError: pass
                        else:
                            if not dep_code:
                                return False
    return True

#-----------------------------------------------------------------------

LISPY_SUFFIX = ".lpy"

class LispyLoader(FileLoaderMixin, SourceLoader):

    def decode_source(self, source_bytes):
        raise NotImplementedError

    def verify_cache(self, code):
        result = verify_code_deps(code)
        #print "result:", result
        return result

    def compile_source(self, fullname, source_bytes, source_path):
        from lispy.compiler import compile_
        assert fullname in sys.modules
        module = sys.modules[fullname]
        # in the future, loader macros could, when specified, replace
        # read to generate the form from the text in a different way
        form = read(source_bytes)
        return compile_(form, source_path, module.__dict__, with_deps_info=True)

def _LispyFinderDetails():
    return {
        "suffixes": [LISPY_SUFFIX],
        "loader": LispyLoader,
        "supports_packages": True}

#-----------------------------------------------------------------------

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
def install():
    import sys
    #sys.dont_write_bytecode = True

    # TODO: replace only previous occurences (for reload) instead of overwriting
    if not hasattr(sys, "import_suffix_hooks"):
        sys.import_suffix_hooks = []
    sys.import_suffix_hooks = [_LispyFinderDetails()]
