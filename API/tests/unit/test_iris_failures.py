"""Clasificación del motivo por el que un análisis de Iris muere.

Un ``failed`` sin motivo no es accionable: quien lo mira no sabe si el
problema era su fichero o el motor. ``classify_failure`` es la costura que
separa esos dos casos, y estos tests fijan la parte que importa de verdad —
que el mensaje persistido nunca arrastre contenido del correo analizado.
"""

from __future__ import annotations

import pytest

from src.modules.features.iris.exceptions import IrisInvalidInputError
from src.modules.features.iris.services.failures import (
    FAILURE_INTERNAL_ERROR,
    FAILURE_INVALID_INPUT,
    classify_failure,
)

pytestmark = pytest.mark.unit


def test_invalid_input_keeps_its_own_message():
    """El mensaje de ``IrisInvalidInputError`` lo redacta el propio módulo a
    partir de un recuento de cabeceras, así que puede viajar tal cual."""
    failure = classify_failure(
        IrisInvalidInputError("Tras parsear se obtuvieron 0 cabeceras (mínimo: 2).")
    )

    assert failure.code == FAILURE_INVALID_INPUT
    assert "0 cabeceras" in failure.reason


def test_unexpected_error_never_leaks_the_exception_text():
    """El caso que motiva esta clasificación: un parser que revienta y arrastra en su
    ``str()`` el fragmento de entrada que no supo digerir."""
    leaked = "b'From: victima@banco.example\\r\\nAuthorization: Bearer s3cr3t'"
    failure = classify_failure(ValueError(f"cannot decode {leaked}"))

    assert failure.code == FAILURE_INTERNAL_ERROR
    assert "s3cr3t" not in failure.reason
    assert "victima@banco.example" not in failure.reason
    assert failure.reason  # hay algo que enseñar, no una cadena vacía


def test_reason_is_bounded():
    """Un traceback repr-eado de una librería de terceros puede ser enorme y
    no aporta nada más allá de la primera línea; la columna es Text, pero la
    respuesta de la API no debería serlo."""
    failure = classify_failure(IrisInvalidInputError("x" * 5000))

    assert len(failure.reason) <= 500
