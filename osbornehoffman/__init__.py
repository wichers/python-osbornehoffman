from importlib.metadata import PackageNotFoundError, version

try:
    dist_name = __name__
    __version__ = version(dist_name)
except PackageNotFoundError:
    __version__ = "unknown"
finally:
    del version, PackageNotFoundError

__author__ = "Alexander Wichers"
__copyright__ = "Alexander Wichers"
__license__ = "mit"

from .account import (
    InvalidAccountFormatError,
    InvalidAccountLengthError,
    InvalidPanelIDFormatError,
    InvalidPanelIDLengthError,
    OHAccount,
)
from .client import OHClient
from .event import OHEvent
from .keystore import OHKeyStore
from .server import MessageType, OHServer
