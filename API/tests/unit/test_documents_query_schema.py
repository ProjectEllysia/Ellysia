"""Test unitario de DocumentsQuerySchema (sin BD ni Flask).

Regresión: el filtro de /themis/documents validaba scan_type contra una lista
escrita a mano que nunca incluyó "lybra", así que un usuario no podía filtrar
su lista de documentos para ver solo sus informes de Lybra. Ahora se deriva
de ScanType, así que cualquier tipo futuro queda cubierto automáticamente.
"""

import pytest

from src.modules.themis.model import ScanType
from src.modules.themis.schemas import DocumentsQuerySchema

pytestmark = pytest.mark.unit


def test_accepts_every_scan_type_plus_all():
    schema = DocumentsQuerySchema()
    for value in [t.value for t in ScanType] + ["all"]:
        assert schema.load({"scan_type": value})["scan_type"] == value


def test_rejects_unknown_scan_type():
    schema = DocumentsQuerySchema()
    with pytest.raises(Exception):
        schema.load({"scan_type": "not-a-real-scanner"})
