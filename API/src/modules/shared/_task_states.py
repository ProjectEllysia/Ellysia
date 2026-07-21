"""Estados compartidos de tareas cancelables (D5).

``CANCELLABLE_STATES`` estaba redefinido de forma idéntica en Themis (scans)
e Iris (analyses) — mismo significado (pending/running == "aún se puede
cancelar"), una sola fuente.
"""

CANCELLABLE_STATES = frozenset({"pending", "running"})
