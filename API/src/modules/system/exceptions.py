"""Excepciones específicas de lectura de logs del módulo de sistema."""


class LogNotFoundError(Exception):
    """El handler de logging todavía no ha creado el fichero."""


class LogSnapshotChangedError(Exception):
    """El fichero fue reemplazado o truncado durante una consulta paginada."""


class LogQueryError(Exception):
    """Los filtros solicitados son incompatibles o no son válidos."""
