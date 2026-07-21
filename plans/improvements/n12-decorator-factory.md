# N12 — Factory de decoradores para endpoints de Themis (mejora futura, no urgente)

> Estado: **idea aparcada**, no priorizada. Se documenta para no perderla, no como tarea activa. Reconsiderar solo si se cumple la condición de la sección "Cuándo reconsiderarlo".

## Qué es hoy

Cada uno de los ~30 endpoints de `API/src/modules/features/themis/endpoints.py` (1252 líneas) repite el mismo "sándwich" de hasta 8 decoradores:

```python
@themis_blp.post("/nmap")
@themis_blp.arguments(NmapScanRequestSchema)
@themis_blp.response(201, ScanResponseSchema)
@themis_blp.alt_response(400, schema=ErrorSchema)
@themis_blp.alt_response(403, schema=ErrorSchema)
@limiter.limit("30 per hour")
@require_oauth_token
@require_attributes(AttributeType.THEMIS_CREATE)
@handle_exceptions(default_exception=ScanExecutionError, logger=logger)
def start_nmap_scan(args):
    ...
```

Multiplicado por ~30 endpoints, es mucho texto repetido con pequeñas variaciones (el schema, el rate limit, el atributo ABAC requerido).

## Por qué es discutible (no un "sí, hacerlo")

Es verboso, pero también **explícito y `grep`-eable**: quien lee un endpoint ve exactamente qué protecciones tiene sin seguir una indirección. Una factory tipo `@themis_endpoint(schema=..., attribute=..., rate="30 per hour")` lo comprimiría, pero:

- La indirección en la **capa de seguridad** tiene un coste real: es más fácil que un endpoint nuevo herede protecciones que no debía (copiar-pegar la llamada a la factory con un parámetro mal puesto) o le falte una sin que se note en el diff (un decorador que falta salta a la vista; un parámetro de factory que falta, no tanto).
- Los 8 decoradores no son homogéneos — varían en schema, código de estado, atributo ABAC, y algunos endpoints tienen decoradores extra (`@blp.alt_response` múltiples). Una factory que cubra todos los casos reales probablemente necesitaría casi tantos parámetros como decoradores tiene el sándwich hoy, con lo que el ahorro neto de legibilidad es menor de lo que parece a primera vista.

## Cuándo reconsiderarlo

Solo tiene sentido evaluarlo de nuevo si en algún momento se decide abordar **A7** (sacar la lógica de negocio que todavía queda en algunos endpoints de Themis hacia los managers) — ese trabajo ya obliga a releer cada endpoint de cerca, y es el único momento en que el coste de diseñar bien la factory (y decidir qué parámetros necesita de verdad, no en abstracto) se amortiza. Aun así, hacerlo con cautela: medir primero cuánta variación real hay entre los 30 endpoints antes de comprometerse a una única forma de factory.

**No abordar como cambio aislado.**
