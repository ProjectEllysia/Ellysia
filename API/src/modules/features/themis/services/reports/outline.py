"""Marcadores PDF: el índice plegable que los visores pintan a un lado.

Un informe de Lybra puede pasar de las cien páginas, y hasta ahora se recorría
de la única forma que un PDF plano permite: bajando. Este módulo añade la otra,
que el formato sí ofrece y no se estaba usando — el **outline**, el árbol de
marcadores del panel lateral que Acrobat, Chrome, Firefox, Preview y Okular
saben pintar, y que se pliega y despliega por niveles.

Conviene decir qué **no** es, porque «colapsar» en un PDF suena a lo que hace
un navegador y no lo es. Plegar el contenido dentro de la página —que un bloque
desaparezca y lo de abajo suba— no existe en PDF: el documento es una
descripción de páginas ya compuestas, y el sitio que ocupa cada cosa quedó
decidido al generarlo. El estándar tiene capas ocultables (*optional content
groups*), pero ReportLab no las expone en ninguna API, y aun apagándolas
dejarían el hueco en blanco en vez de recomponer la página. El árbol de
marcadores es lo que sí se puede dar: no esconde el detalle, pero permite no
tener que atravesarlo.

El obstáculo práctico es que emitir un marcador necesita el *canvas*, y el
código que arma un informe no lo tiene: apila una lista de *flowables* y se la
entrega a ``SimpleDocTemplate.build()``, que sólo entonces crea el canvas. La
costura que sí existe es que a cada flowable se le inyecta ``self.canv`` antes
de dibujarlo — así que un flowable de altura cero puede intercalarse en la
lista como uno más y, cuando le toque el turno, emitir su marcador sabiendo ya
en qué página y a qué altura ha caído.
"""

from reportlab.platypus import Flowable


class OutlineEntry(Flowable):
    """Un marcador del índice lateral, sin ocupar espacio en la página.

    Se intercala en la lista de elementos justo antes de aquello que nombra
    (un título de sección, la cabecera de un grupo), y al dibujarse marca la
    posición exacta que ha acabado ocupando. Como no mide nada, no cambia la
    composición: un informe con marcadores y otro sin ellos pasan la página en
    el mismo sitio.

    Sobre ``level``: ReportLab exige que un nivel no supere en más de uno al
    del marcador anterior, así que los niveles hay que emitirlos en orden
    descendente por el árbol (un 2 tiene que ir precedido de un 1). No se
    valida aquí porque el error de ReportLab ya es explícito y llega en el
    momento de generar, no en el de leer el PDF.

    Attributes:
        title: El texto que se ve en el panel del visor.
        key: Identificador del destino, único en todo el documento. Dos
            marcadores con la misma clave apuntarían al mismo sitio.
        level: Profundidad en el árbol; 0 es la raíz.
        is_closed: Si el nodo nace plegado. Va a ``True`` por defecto porque
            el valor de un índice de cien grupos está en verlos todos de
            golpe, no en que se despliegue entero al abrir el documento.
    """

    def __init__(self, title: str, key: str, level: int = 0, is_closed: bool = True) -> None:
        super().__init__()
        self.title = title
        self.key = key
        self.level = level
        self.is_closed = is_closed
        self.width = 0
        self.height = 0

    def wrap(self, availWidth, availHeight):  # pylint: disable=invalid-name
        """Altura cero: el marcador no desplaza nada de lo que lo rodea."""
        return 0, 0

    def draw(self) -> None:
        """Anclar el destino en la posición actual y darlo de alta en el árbol.

        ``bookmarkHorizontal`` traduce la posición relativa del flowable a la
        absoluta de la página, así que el marcador cae donde el elemento ha
        quedado de verdad tras la paginación, no donde se pensó que caería.
        """
        self.canv.bookmarkHorizontal(self.key, 0, 0)
        self.canv.addOutlineEntry(self.title, self.key, level=self.level, closed=self.is_closed)

    def __repr__(self) -> str:
        return f"OutlineEntry({self.title!r}, key={self.key!r}, level={self.level})"
