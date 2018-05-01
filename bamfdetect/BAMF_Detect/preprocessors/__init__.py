from os.path import basename, dirname, abspath
from glob import glob
from importlib import import_module

__all__ = [basename(f)[:-3] for f in glob(dirname(abspath(__file__))+"/*.py")]
__all__ = [v for v in __all__ if not v == "__init__"]

for mod in __all__:
    import_module("BAMF_Detect.preprocessors." + mod)