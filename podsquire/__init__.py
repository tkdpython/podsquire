"""podsquire: SPIFFE cert bootstrap, mTLS proxying, and subprocess supervision."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("podsquire")
except PackageNotFoundError:  # pragma: no cover - editable/uninstalled source tree
    __version__ = "0.0.0"

__all__ = ["__version__"]
