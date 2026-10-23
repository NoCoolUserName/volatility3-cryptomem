"""Extend Volatility's Windows plugin namespace without hiding native plugins."""
from pathlib import Path
import sys

__path__ = [str(Path(root) / "windows")
            for root in sys.modules[__name__.rsplit(".", 1)[0]].__path__]
