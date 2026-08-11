"""Tests unitarios de AegisQuizData (validación de preguntas de quiz generadas por IA)."""

import pytest

import src.modules.system.config_reading as CR
from src.modules.features.aegis.exceptions import AegisValidationError
from src.modules.features.aegis.services.pills import AegisQuizData

pytestmark = pytest.mark.unit


@pytest.fixture
def options_amount(monkeypatch):
    """Fija ``features.aegis.optionsAmount``, el tope de opciones por pregunta."""
    def _set(amount: int):
        monkeypatch.setattr(CR, "aegis_config", lambda: CR.AegisConfig(options_amount=amount))
    return _set


def _valid_kwargs(**overrides):
    kwargs = dict(
        prompt="¿Qué deberías hacer al recibir un correo sospechoso?",
        options=["Hacer clic en el enlace", "Verificar el remitente", "Reenviarlo a un compañero"],
        correct_index=1,
    )
    kwargs.update(overrides)
    return kwargs


def test_accepts_valid_question():
    q = AegisQuizData(**_valid_kwargs())
    assert q.correct_index == 1
    assert len(q.options) == 3


def test_rejects_empty_prompt():
    with pytest.raises(AegisValidationError):
        AegisQuizData(**_valid_kwargs(prompt=""))


def test_rejects_prompt_too_long():
    with pytest.raises(AegisValidationError):
        AegisQuizData(**_valid_kwargs(prompt="x" * 301))


def test_rejects_fewer_than_two_options():
    with pytest.raises(AegisValidationError):
        AegisQuizData(**_valid_kwargs(options=["Única opción"], correct_index=0))


def test_rejects_more_options_than_the_configured_amount(options_amount):
    options_amount(4)
    with pytest.raises(AegisValidationError):
        AegisQuizData(**_valid_kwargs(options=["A", "B", "C", "D", "E"], correct_index=0))


def test_accepts_more_options_when_the_config_allows_them(options_amount):
    """El tope es ``features.aegis.optionsAmount``, no un 4 escrito a mano: subirlo
    en la configuración tiene que bastar para que quepan más respuestas."""
    options_amount(6)
    question = AegisQuizData(**_valid_kwargs(options=["A", "B", "C", "D", "E", "F"], correct_index=5))
    assert len(question.options) == 6


def test_rejects_empty_option_string():
    with pytest.raises(AegisValidationError):
        AegisQuizData(**_valid_kwargs(options=["A", ""], correct_index=0))


def test_rejects_correct_index_out_of_range():
    with pytest.raises(AegisValidationError):
        AegisQuizData(**_valid_kwargs(options=["A", "B"], correct_index=2))


def test_rejects_negative_correct_index():
    with pytest.raises(AegisValidationError):
        AegisQuizData(**_valid_kwargs(options=["A", "B"], correct_index=-1))
