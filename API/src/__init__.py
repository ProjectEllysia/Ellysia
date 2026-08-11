"""
src - Aliases para backwards compatibility
"""

from src.modules.shared import Base, Document
from src.modules.features.themis import NmapScanManager, NiktoScanManager

__all__ = [
    'Base',
    'Document',
    'NmapScanManager',
    'NiktoScanManager',
]
