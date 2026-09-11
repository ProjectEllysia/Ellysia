"""
Managers del módulo Iris (análisis de correo).

- ``IrisManager`` (``analysis.py``): ciclo de vida del análisis de
  cabeceras — crea el registro, encola la tarea, agrega puntuaciones y
  determina el veredicto.
- ``IrisReportManager`` (``reports.py``): ciclo de vida del ``IrisDocument``
  y generación asíncrona del PDF.
- ``IrisMailboxManager`` (``mailbox.py``): OAuth connect/callback, CRUD de
  conexiones y sondeo de buzones externos.
- ``IrisPhishingNotifyManager`` (``notifications.py``): correo de alerta
  cuando la ingesta automática de buzón clasifica un correo como Phishing.
- ``IrisNotificationPreferenceManager`` (``notifications.py``): lectura y
  escritura de las preferencias de notificación de un usuario.
- ``IrisFeedbackManager`` (``feedback.py``): correcciones del analista y
  métricas del detector calculadas a partir de ellas.
- ``IrisReplayManager`` (``replay.py``): simulador de reglas para
  administradores — compara políticas de puntuación sobre el corpus.
- ``IrisTrustPolicyManager`` (``trust.py``): excepciones de confianza por
  usuario (remitentes y dominios), con motivo, caducidad y revocación.
- ``IrisTriageManager`` (``triage.py``): vistas guardadas y etiquetas del
  historial de triaje.
- ``IrisCaseManager`` (``cases.py``): casos de analista con estado,
  prioridad, asignación, notas y timeline sobre uno o varios análisis.
- ``IrisBatchManager`` (``batch.py``): análisis por lotes de varios .eml o
  un ZIP, con límites, duplicados y back pressure.

Iris era el único módulo con
**dos** ficheros de managers en la raíz — ``managers.py`` (64 KB, el
segundo fichero más grande del repositorio) y ``mailbox_managers.py``,
este último además suelto mientras el resto del conector de buzón vivía
bajo ``services/mailbox/``. El propio docstring de ``mailbox_managers.py``
citaba a ``themis/managers/`` como precedente de lo que había que hacer.

Este ``__init__.py`` reexporta los nombres públicos para que
``from ...iris.managers import X`` siga funcionando, incluida la
resolución por atributo de módulo que hace RQ al despicklear los entry
points ya encolados.
"""

from .analysis import IrisManager
from .reports import IrisReportManager
from .mailbox import IrisMailboxManager
from .notifications import IrisPhishingNotifyManager, IrisNotificationPreferenceManager
from .feedback import IrisFeedbackManager
from .replay import IrisReplayManager
from .trust import IrisTrustPolicyManager
from .triage import IrisTriageManager
from .cases import IrisCaseManager
from .batch import IrisBatchManager

__all__ = [
    "IrisManager",
    "IrisTrustPolicyManager",
    "IrisTriageManager",
    "IrisCaseManager",
    "IrisBatchManager",
    "IrisFeedbackManager",
    "IrisReplayManager",
    "IrisReportManager",
    "IrisMailboxManager",
    "IrisPhishingNotifyManager",
    "IrisNotificationPreferenceManager",
]
