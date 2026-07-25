"""
Database models for Acheron encrypted vault module.

Cómo añadir un tipo nuevo de Storable
──────────────────────────────────────
Añadir la subclase aquí (siguiendo el patrón de ``Account``/``CreditCard``/...:
tabla propia, ``id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)``,
sus campos — todos ``String``/``Text``, nunca se descifran en el servidor — y
``__mapper_args__ = {"polymorphic_identity": "<kind>"}``) es solo el primer
paso. El resto del backend está deliberadamente **data-driven**: no hay que
tocar la lógica de negocio, solo describir el tipo nuevo en los sitios que la
alimentan.

1. **`storable_specs.py`** — añadir una entrada a ``STORABLE_SPECS`` con
   ``model`` (la subclase de arriba), ``json_list_key`` (la clave bajo la que
   vive en el JSON del vault, p.ej. ``"accounts"``) y ``fields`` (tupla de
   pares ``(atributo_python, claveJSON)``). Con esto ``managers.py`` ya sabe
   crear, actualizar, exportar y hacer *bulk update* del tipo nuevo —
   ``upsert_vault_from_json``, ``export_vault_to_json``, ``add_storable_to_vault``,
   ``update_storable`` y ``bulk_update_storables`` iteran ``STORABLE_SPECS``/
   ``SPEC_BY_MODEL``/``JSON_TO_ATTR`` en vez de tener un ``if kind == ...`` por
   tipo. **No hace falta tocar `managers.py`, `repositories.py` ni
   `endpoints.py`** — todos son genéricos sobre ``Storable`` y leen el tipo a
   través de esta spec. (Ignora ``VaultRepository.save_with_storables`` en
   `repositories.py`: construye `Account`/`CreditCard` a mano, es código
   legacy sin llamadores, no es el patrón a seguir.)

2. **`schemas.py`** — `StorableCreateSchema` es un único schema plano para
   los 7 tipos (no valida polimórficamente contra `storable_specs`, así que
   hay que tocarlo a mano en tres sitios):
   - añadir el nuevo `kind` al `validate.OneOf([...])` del campo `kind`;
   - declarar como `fields.String(allow_none=True)` cualquier campo camelCase
     que no exista ya en el schema (los nombres se comparten entre tipos —
     si el tipo nuevo reutiliza un nombre existente, p.ej. `password`, no
     hace falta duplicarlo);
   - añadir una entrada en `required_by_kind` (dentro de
     `validate_kind_fields`) con los campos camelCase obligatorios del tipo.

3. **Migración Alembic** — `alembic revision --autogenerate -m "add <Tipo>
   storable"` genera la tabla nueva.

4. **Frontend** (fuera de este módulo, pero necesario para que el tipo sea
   utilizable) — `web/app/src/acheron/storableTypes.js` y
   `storableFields.js` mapean cada `kind` a su formulario; sin una entrada
   ahí, `StorableFormModal.vue` no sabrá renderizar el tipo nuevo aunque el
   backend ya lo acepte.
"""

from sqlalchemy import (
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import relationship

from src.modules.shared import Base, utcnow_naive


# =========================================================================
# VAULT MODEL
# =========================================================================

class Vault(Base):
    """
    Encrypted vault for storing secrets.

    Each vault belongs to a user and contains encrypted storables.
    Stores cryptographic parameters used for encryption and key derivation.

    Attributes:
        id: Primary key, auto-incrementing integer.
        user_id: Foreign key to User.id.
        checker: URL used to verify vault access (obfuscated).
        vault_key: Encrypted vault master key.
        transformation: Encryption algorithm (e.g., "AES/GCM/NoPadding").
        kdf: Key derivation function (e.g., "Argon2").
        kdf_iterations: Number of KDF iterations.
        kdf_memory: Memory in KB for Argon2.
        kdf_parallelism: Parallel threads for Argon2.
        salt: Cryptographic salt (max 128 characters).
        metadata_version: Counter bumped on each master-password rotation
            (PATCH /acheron/vault); lets other clients detect the change.

    Relationships:
        user: User who owns the vault.
        storables: List of Storable objects in this vault.
    """
    __tablename__ = "Vault"

    id = Column(Integer, primary_key=True, autoincrement=True)

    user_id = Column(Integer, ForeignKey("User.id"), nullable=False, unique=True)

    checker = Column(String(512), nullable=False)
    vault_key = Column(String(512), nullable=False)

    transformation = Column(String(64), nullable=False)   # p.ej. "AES/GCM/NoPadding"
    kdf = Column(String(64), nullable=False)              # "Argon2"
    kdf_iterations = Column(Integer, nullable=False)
    kdf_memory = Column(Integer, nullable=False)
    kdf_parallelism = Column(Integer, nullable=False)
    salt = Column(String(128), nullable=False)

    # Se incrementa cada vez que se rotan los metadatos cripto (cambio de la
    # contraseña maestra vía PATCH /acheron/vault). Permite a otros clientes con
    # sesión activa detectar que la maestra cambió y forzar un re-desbloqueo.
    metadata_version = Column(Integer, nullable=False, default=1, server_default="1")

    user = relationship("User", back_populates="vaults", foreign_keys=[user_id])
    storables = relationship(
        "Storable",
        back_populates="vault",
        cascade="all, delete-orphan",
        foreign_keys="Storable.vault_id",
    )

    def __repr__(self) -> str:
        """
        Return a debug representation of the Vault instance.

        Returns:
            String with id and user_id.
        """
        return f"<Vault id={self.id} user_id={self.user_id}>"


# =========================================================================
# STORABLE MODELS
# =========================================================================

class Storable(Base):
    """
    Base class for storable secrets (polymorphic).

    Abstract base for different types of secrets that can be stored
    in a vault. Uses polymorphic inheritance for Account and CreditCard.

    Attributes:
        id: Primary key, auto-incrementing integer.
        internal_id: Optional internal identifier within the vault.
        title: Optional title/name for the storable.
        created_at: Creation timestamp (automatic).
        updated_at: Last update timestamp (automatic, updated on change).
        vault_id: Foreign key to Vault.id.
        type: Polymorphic discriminator for storable type.

    Relationships:
        vault: Vault containing this storable.

    Table Constraints:
        Unique constraint on (vault_id, internal_id).
        Unique constraint on (title, vault_id).
    """
    __tablename__ = "Storable"

    id = Column(Integer, primary_key=True, autoincrement=True)

    internal_id = Column(String(128), nullable=True)
    title = Column(String(128), nullable=True)

    created_at = Column(DateTime, nullable=False, default=utcnow_naive)
    updated_at = Column(
        DateTime,
        nullable=False,
        default=utcnow_naive,
        onupdate=utcnow_naive,
    )

    vault_id = Column(Integer, ForeignKey("Vault.id"), nullable=False)

    type = Column(String(50), nullable=False)

    vault = relationship("Vault", back_populates="storables")

    __mapper_args__ = {
        "polymorphic_on": type,
        "polymorphic_identity": "storable",
        "with_polymorphic": "*",
    }

    __table_args__ = (
        UniqueConstraint("vault_id", "internal_id", name="uq_storable_vault_internal"),
        UniqueConstraint("title", "vault_id", name="uq_storable_vault_title"),
    )

    def __repr__(self) -> str:
        """
        Return a debug representation of the Storable instance.

        Returns:
            String with id, type, and title.
        """
        return f"<Storable id={self.id} type={self.type} title={self.title!r}>"


class Account(Storable):
    """
    Username/password account credential.

    Inherits from Storable and adds fields for storing account
    authentication credentials.

    Attributes:
        id: Primary key (foreign key to Storable.id).
        username: Account username or email.
        domain: Service/domain the account belongs to.
        password: Encrypted password.
    """
    __tablename__ = "Account"

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    username = Column(String(512), nullable=False)
    domain = Column(String(512), nullable=False)
    password = Column(String(512), nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "account",
    }

    def __repr__(self) -> str:
        """
        Return a debug representation of the Account instance.

        Returns:
            String with id and username@domain.
        """
        return f"<Account id={self.id} {self.username}@{self.domain}>"


class CreditCard(Storable):
    """
    Credit card information.

    Inherits from Storable and adds fields for storing credit card
    payment information.

    Attributes:
        id: Primary key (foreign key to Storable.id).
        cardholder_name: Name on the card.
        card_number: Encrypted card number.
        expiration_date: Encrypted expiration date (MM/YY).
        postal_code: Encrypted billing postal code.
        cvv: Encrypted CVV/CVC code.
    """
    __tablename__ = "CreditCard"

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    cardholder_name = Column(String(512), nullable=False)
    card_number = Column(String(512), nullable=False)
    expiration_date = Column(String(512), nullable=False)
    postal_code = Column(String(512), nullable=False)
    cvv = Column(String(512), nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "creditcard",
    }

    def __repr__(self) -> str:
        """
        Return a debug representation of the CreditCard instance.

        Returns:
            String with id and cardholder name.
        """
        return f"<CreditCard id={self.id} holder={self.cardholder_name!r}>"


class SecureNote(Storable):
    """
    Free-form encrypted text note.

    Attributes:
        id: Primary key (foreign key to Storable.id).
        content: Encrypted note content.
    """
    __tablename__ = "SecureNote"

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    content = Column(Text, nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "securenote",
    }

    def __repr__(self) -> str:
        """
        Return a debug representation of the SecureNote instance.

        Returns:
            String with id.
        """
        return f"<SecureNote id={self.id}>"


class Identity(Storable):
    """
    Personal identity information.

    Attributes:
        id: Primary key (foreign key to Storable.id).
        full_name: Full legal name.
        email: Contact email.
        phone: Contact phone number.
        address: Street address.
        city: City of residence.
        country: Country of residence.
        document_id: Encrypted national/document ID number.
    """
    __tablename__ = "Identity"

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    full_name = Column(String(512), nullable=False)
    email = Column(String(512), nullable=False)
    phone = Column(String(512), nullable=False)
    address = Column(String(512), nullable=False)
    city = Column(String(512), nullable=False)
    country = Column(String(512), nullable=False)
    document_id = Column(String(512), nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "identity",
    }

    def __repr__(self) -> str:
        """
        Return a debug representation of the Identity instance.

        Returns:
            String with id and full name.
        """
        return f"<Identity id={self.id} {self.full_name!r}>"


class BankAccount(Storable):
    """
    Bank account information.

    Attributes:
        id: Primary key (foreign key to Storable.id).
        bank_name: Name of the bank.
        holder: Account holder name.
        iban: Encrypted IBAN.
        swift_bic: Encrypted SWIFT/BIC code.
        account_number: Encrypted account number.
    """
    __tablename__ = "BankAccount"

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    bank_name = Column(String(512), nullable=False)
    holder = Column(String(512), nullable=False)
    iban = Column(String(512), nullable=False)
    swift_bic = Column(String(512), nullable=False)
    account_number = Column(String(512), nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "bankaccount",
    }

    def __repr__(self) -> str:
        """
        Return a debug representation of the BankAccount instance.

        Returns:
            String with id and bank name.
        """
        return f"<BankAccount id={self.id} bank={self.bank_name!r}>"


class WifiNetwork(Storable):
    """
    Wi-Fi network credentials.

    Attributes:
        id: Primary key (foreign key to Storable.id).
        ssid: Network SSID.
        password: Encrypted network password.
        security_type: Security protocol (e.g. "WPA2").
    """
    __tablename__ = "WifiNetwork"

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    ssid = Column(String(512), nullable=False)
    password = Column(String(512), nullable=False)
    security_type = Column(String(512), nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "wifi",
    }

    def __repr__(self) -> str:
        """
        Return a debug representation of the WifiNetwork instance.

        Returns:
            String with id and ssid.
        """
        return f"<WifiNetwork id={self.id} ssid={self.ssid!r}>"


class SoftwareLicense(Storable):
    """
    Software license key.

    Attributes:
        id: Primary key (foreign key to Storable.id).
        product: Product/software name.
        license_key: Encrypted license key.
        licensed_to: Name of the licensee.
        version: Licensed product version.
    """
    __tablename__ = "SoftwareLicense"

    id = Column(Integer, ForeignKey("Storable.id"), primary_key=True)

    product = Column(String(512), nullable=False)
    license_key = Column(String(512), nullable=False)
    licensed_to = Column(String(512), nullable=False)
    version = Column(String(512), nullable=False)

    __mapper_args__ = {
        "polymorphic_identity": "license",
    }

    def __repr__(self) -> str:
        """
        Return a debug representation of the SoftwareLicense instance.

        Returns:
            String with id and product.
        """
        return f"<SoftwareLicense id={self.id} product={self.product!r}>"