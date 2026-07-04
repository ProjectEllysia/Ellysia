# Tests de la API Ellysia

Suite de tests con `pytest`. No requiere PostgreSQL, Redis ni herramientas de
escaneo: la base de datos se levanta en **SQLite** en un fichero temporal y los
servicios externos se mockean.

## Cómo ejecutar

Desde el directorio `API/`:

```bash
pip install -r requirements.txt -r requirements-dev.txt
pytest                      # toda la suite (unit + integration) con cobertura
pytest -m unit             # solo tests unitarios (rápidos, sin app ni BD)
pytest -m integration      # solo tests de integración (app + cliente HTTP)
pytest tests/integration/test_oauth.py -q   # un fichero concreto
```

## Estructura

```
tests/
├── conftest.py            # fixtures: app, client, BD SQLite, usuarios/tokens
├── unit/                  # funciones puras (reglas Iris, permisos, schemas, ...)
└── integration/           # endpoints reales por módulo vía test_client
```

## Marcadores

- `@pytest.mark.unit` — sin base de datos ni aplicación Flask.
- `@pytest.mark.integration` — arranca `create_app` y usa el cliente de pruebas.

## Notas

- Varios tests usan `xfail(strict=True)`: documentan bugs reales del código
  (p. ej. respuestas 500 donde deberían ser 404). Cuando el bug se corrija, el
  test pasará a XPASS y el marcador deberá retirarse. Ver
  [`IMPROVEMENTS.md`](IMPROVEMENTS.md).
- La adaptación a SQLite y los mocks viven exclusivamente en `tests/`; no se
  modifica `src/`.
