"""
src - Aliases para backwards compatibility
"""

from src.modules.shared import Base, Document
from src.modules.themis import NmapScanManager, NiktoScanManager, OpenVASScanManager

__all__ = [
    'Base',
    'Document',
    'NmapScanManager',
    'NiktoScanManager',
    'OpenVASScanManager',
]