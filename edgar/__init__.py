from os.path import dirname, basename, isfile
import glob
from .edgar import Edgar
from .txtml import TXTML
from .company import Company
from .xbrl import XBRL, XBRLElement
from .document import Document, Documents

__version__ = "5.4.2"

modules = glob.glob(dirname(__file__)+"/*.py")
__all__ = [ basename(f)[:-3] for f in modules if isfile(f) and not f.endswith('__init__.py')]
