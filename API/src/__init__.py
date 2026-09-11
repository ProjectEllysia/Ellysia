"""Paquete raíz del backend.

Vacío a propósito: Python ejecuta este fichero antes que cualquier
``src.modules.x.y``, así que todo lo que se importe aquí se carga en cada import
del proyecto. Un import de un módulo de dominio en este sitio arrastra la
aplicación entera y oculta ciclos de imports. Cada módulo se importa desde su
propia ruta (``src.modules.<módulo>``).
"""
