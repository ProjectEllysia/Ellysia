#!/usr/bin/env python3
"""Censo de ingestibilidad del feed de plantillas de Nuclei (roadmap Fase U4).

**Qué decide este script.** La Fase R contempla ingerir plantillas de Nuclei al
runtime propio, pero eso solo vale la pena si la fracción ingerible es alta. El
entregable de U4 no es código de producto: es este número. Con él, la decisión
de la Fase R deja de ser una intuición.

**El umbral, fijado por escrito ANTES de la primera medición** (2026-07-31),
para que el resultado no se racionalice a posteriori:

    Se acomete la ingesta (Fase R) si al menos el **25 %** de las plantillas
    HTTP caen en el cubo `ingestible_now`, es decir, se traducen hoy tal cual
    sin construir extractors, payloads ni matchers nuevos.

    - Por encima → merece la pena: la migración del feed a YAML y la ingesta
      selectiva se acometen con el esquema de Nuclei como referencia.
    - Por debajo → la Fase R renuncia a ingerir, se queda con `network` y
      `script`, y sigue siendo un buen resultado. El feed propio puede migrar a
      YAML igualmente, por legibilidad, pero deja de ser una promesa de
      compatibilidad.

**No clona el repositorio upstream.** Lee el mismo árbol que el binario usa en
producción, vía ``config_reading.get_nuclei_templates_dir()``, porque Themis
tiene una sola copia de las plantillas. Consecuencia buscada: el número
corresponde a la versión que de verdad corre, no a `main` del día del clon.

**Se ejecuta a mano, nunca en CI**: el árbol upstream cambia a diario y este
número no debe poder romper un build.

Uso:
    python tools/nuclei_template_census.py
    python tools/nuclei_template_census.py --templates-dir /ruta/al/arbol
    python tools/nuclei_template_census.py --json censo.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Ejecutable como script suelto desde cualquier sitio: el paquete ``src`` vive
# en API/, dos niveles por encima de este fichero.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.modules.features.themis.lybra.ingest import (  # noqa: E402
    Bucket,
    classify_template,
    summarize,
)
from src.modules.features.themis.services.nuclei_templates import (  # noqa: E402
    NucleiTemplateStore,
)

# El umbral del docstring, en código para que el veredicto no dependa de que
# alguien lo lea bien.
HTTP_INGESTIBLE_THRESHOLD_PCT = 25.0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--templates-dir",
        type=Path,
        default=None,
        help="Árbol de plantillas a censar. Por defecto, el que resuelve la configuración.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        dest="json_output",
        help="Vuelca el censo completo (resumen + perfil por plantilla) a un fichero JSON.",
    )
    parser.add_argument(
        "--examples",
        type=int,
        default=5,
        help="Cuántos ids de ejemplo mostrar por cubo (0 para ninguno).",
    )
    return parser.parse_args()


def _print_report(summary: dict, examples: dict, store_path: Path, version: str) -> None:
    print(f"\nÁrbol censado : {store_path}")
    print(f"Versión       : {version}")
    print(f"Plantillas    : {summary['total']}\n")

    print("Reparto por cubo de ingestibilidad")
    print("-" * 62)
    for bucket in Bucket:
        count = summary["by_bucket"][bucket.value]
        pct = summary["by_bucket_pct"][bucket.value]
        print(f"  {bucket.value:<26} {count:>7}  ({pct:>5.2f} %)")
        for template_id in examples.get(bucket.value, []):
            print(f"      ej. {template_id}")

    print("\nReparto por protocolo")
    print("-" * 62)
    for protocol, count in summary["by_protocol"].items():
        print(f"  {protocol:<26} {count:>7}")

    print("\nObstáculos más frecuentes")
    print("-" * 62)
    for blocker, count in list(summary["blockers"].items())[:15]:
        print(f"  {blocker:<26} {count:>7}")

    http_total = summary["http_total"]
    http_pct = summary["http_ingestible_pct"]
    print("\n" + "=" * 62)
    print("EL NÚMERO QUE DECIDE LA FASE R")
    print("=" * 62)
    print(f"  Plantillas HTTP            : {http_total}")
    print(f"  Ingeribles hoy tal cual    : {summary['http_ingestible_now']}  ({http_pct:.2f} %)")
    print(f"  Umbral fijado de antemano  : {HTTP_INGESTIBLE_THRESHOLD_PCT:.2f} %")

    if http_pct >= HTTP_INGESTIBLE_THRESHOLD_PCT:
        print("\n  VEREDICTO: por encima del umbral — la ingesta merece la pena.")
        print("  La Fase R acomete la migración a YAML y la ingesta selectiva.")
    else:
        print("\n  VEREDICTO: por debajo del umbral — la ingesta NO merece la pena.")
        print("  La Fase R renuncia a ingerir y se queda con `network` y `script`.")
        print("  El feed propio puede migrar a YAML igualmente, por legibilidad.")
    print()


def main() -> int:
    args = _parse_args()
    store = NucleiTemplateStore(args.templates_dir)

    if not store.is_available:
        print(
            "No se encontró ningún árbol de plantillas de Nuclei.\n"
            "Este censo necesita el feed instalado: ejecútalo en la máquina que\n"
            "lo tenga (o pásale --templates-dir). Instalarlo: `nuclei -update-templates`.",
            file=sys.stderr,
        )
        return 1

    profiles = [classify_template(document) for _path, document in store.iter_templates()]
    if not profiles:
        print(f"El árbol {store.path} no contiene ninguna plantilla legible.", file=sys.stderr)
        return 1

    summary = summarize(profiles)
    examples = {}
    if args.examples > 0:
        for bucket in Bucket:
            ids = [p.template_id for p in profiles if p.bucket is bucket and p.template_id]
            examples[bucket.value] = ids[: args.examples]

    _print_report(summary, examples, store.path, store.version)

    if args.json_output:
        payload = {
            "templatesDir": str(store.path),
            "templatesVersion": store.version,
            "threshold": HTTP_INGESTIBLE_THRESHOLD_PCT,
            "summary": summary,
            "templates": [
                {
                    "id": p.template_id,
                    "protocol": p.protocol,
                    "severity": p.severity,
                    "bucket": p.bucket.value,
                    "matcherTypes": sorted(p.matcher_types),
                    "blockers": sorted(p.blockers),
                    "requestCount": p.request_count,
                }
                for p in profiles
            ],
        }
        args.json_output.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"Censo completo volcado a {args.json_output}\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
