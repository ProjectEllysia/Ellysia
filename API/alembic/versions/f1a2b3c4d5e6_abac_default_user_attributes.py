"""ABAC: los atributos de un usuario pasan a ser filas explicitas

Hasta ahora ROLE_PERMISSIONS[Role.USER] concedia un baseline implicito de
atributos a todo role_user. Eso tenia dos defectos que la capa de planes
(plans/feature/general/planes-y-organizaciones.md, §5.2) hace insostenibles:

  1. El baseline no incluia ningun *_create, asi que una cuenta nueva no podia
     guardar una credencial en Acheron ni analizar un correo en Iris. El plan
     gratuito era inservible.
  2. Lo que concede el baseline es IRREVOCABLE: require_attributes calcula
     `baseline | filas_explicitas` y remove_user_attributes solo borra filas.
     No hay tabla de denegacion. Ampliar el baseline para arreglar (1) habria
     dejado al administrador sin poder retirar nada a nadie.

A partir de aqui Role.USER va con baseline vacio y los atributos se escriben
como filas de UserAttribute en el alta. Esta migracion hace lo mismo con los
usuarios que ya existian, para que no convivan dos clases de cuenta.

La lista se congela aqui como literal y NO se importa de services.permissions:
una migracion tiene que seguir dando el mismo resultado dentro de un anyo,
cuando el enum AttributeType haya crecido con modulos que hoy no existen.

Revision ID: f1a2b3c4d5e6
Revises: 98b18ef22160
Create Date: 2026-08-06 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f1a2b3c4d5e6"
down_revision: Union[str, Sequence[str], None] = "98b18ef22160"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


#: Conjunto de atributos que recibe toda cuenta nueva, congelado a fecha de
#: esta migracion (= todos los AttributeType existentes entonces). Se conceden
#: todos a proposito: lo que distingue a un Freemium de un Gold son los topes
#: del plan, no el llavero (§5.1 del documento de disenyo).
_DEFAULT_ATTRIBUTES: tuple[str, ...] = (
    "aegis_create", "aegis_read", "aegis_update", "aegis_delete",
    "themis_create", "themis_read", "themis_update", "themis_delete",
    "themis_folder_create", "themis_folder_read",
    "themis_folder_update", "themis_folder_delete",
    "acheron_create", "acheron_read", "acheron_update", "acheron_delete",
    "iris_create", "iris_read", "iris_update", "iris_delete",
    "themis_schedule_create", "themis_schedule_read", "themis_schedule_delete",
    "hygeia_create", "hygeia_read", "hygeia_update", "hygeia_delete",
)


def upgrade() -> None:
    """Concede el conjunto por defecto a todos los role_user existentes.

    Un INSERT ... SELECT por atributo, con NOT EXISTS para saltar las filas que
    ya estuvieran. Es idempotente y portable (no depende de ON CONFLICT), y al
    no necesitar leer nada de vuelta funciona tambien en modo offline
    (``alembic upgrade --sql``).
    """
    for attribute in _DEFAULT_ATTRIBUTES:
        op.execute(
            f"""
            INSERT INTO "UserAttribute" (user_id, attribute_name)
            SELECT u.id, '{attribute}'
              FROM "User" u
             WHERE u.role = 'role_user'
               AND NOT EXISTS (
                   SELECT 1 FROM "UserAttribute" ua
                    WHERE ua.user_id = u.id
                      AND ua.attribute_name = '{attribute}'
               )
            """
        )


def downgrade() -> None:
    """Retira el conjunto por defecto de los role_user.

    Ojo: una fila de UserAttribute no recuerda quien la puso, asi que esto se
    lleva por delante tambien los atributos de esta lista que un administrador
    hubiera concedido a mano. Es inevitable y por eso el downgrade solo toca
    role_user y solo los nombres congelados arriba.
    """
    names = ", ".join(f"'{attribute}'" for attribute in _DEFAULT_ATTRIBUTES)
    op.execute(
        f"""
        DELETE FROM "UserAttribute"
         WHERE attribute_name IN ({names})
           AND user_id IN (SELECT id FROM "User" WHERE role = 'role_user')
        """
    )
