"""
Alembic migration: crear tabla users con índices y restricciones

- Email PK (citext, único, case-insensitive), longitud <= 100
- Password hash (varchar(512))
- nombre (varchar(100))
- fecha_nac (date) con check de mayoría de edad >= 18 y en el pasado
- genero enum ('Hombre','Mujer')
- estado enum con todos los estados MX
- Soft-delete: deleted_at timestamptz y columna generada is_active
- Auditoría: created_at, updated_at; version con trigger de incremento
- Índices: estado, genero, is_active, updated_at
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql as psql

# Revisión
revision = "20241004120000"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Extensión citext (case-insensitive)
    op.execute("CREATE EXTENSION IF NOT EXISTS citext")

    # Enums
    genero_enum = sa.Enum("Hombre", "Mujer", name="genero_enum")
    genero_enum.create(op.get_bind(), checkfirst=True)

    estado_vals = [
        "Aguascalientes",
        "Baja California",
        "Baja California Sur",
        "Campeche",
        "Coahuila",
        "Colima",
        "Chiapas",
        "Chihuahua",
        "Ciudad de México",
        "Durango",
        "Guanajuato",
        "Guerrero",
        "Hidalgo",
        "Jalisco",
        "Estado de México",
        "Michoacán",
        "Morelos",
        "Nayarit",
        "Nuevo León",
        "Oaxaca",
        "Puebla",
        "Querétaro",
        "Quintana Roo",
        "San Luis Potosí",
        "Sinaloa",
        "Sonora",
        "Tabasco",
        "Tamaulipas",
        "Tlaxcala",
        "Veracruz",
        "Yucatán",
        "Zacatecas",
    ]
    estado_enum = sa.Enum(*estado_vals, name="estado_mx_enum")
    estado_enum.create(op.get_bind(), checkfirst=True)

    # Tabla users
    op.create_table(
        "users",
        sa.Column("email", psql.CITEXT(), primary_key=True, nullable=False),
        sa.Column("nombre", sa.String(length=100), nullable=True),
        sa.Column("password_hash", sa.String(length=512), nullable=False),
        sa.Column("fecha_nac", sa.Date(), nullable=False),
        sa.Column("genero", genero_enum, nullable=True),
        sa.Column("estado", estado_enum, nullable=False),
        sa.Column("deleted_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column(
            "is_active",
            sa.Boolean(),
            sa.Computed("(deleted_at IS NULL)", persisted=True),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        postgresql_partition_by=None,
    )

    # Checks de longitud y mayoría de edad
    op.create_check_constraint(
        "ck_users_email_len",
        "users",
        "char_length(email) BETWEEN 1 AND 100",
    )
    op.create_check_constraint(
        "ck_users_nombre_len",
        "users",
        "(nombre IS NULL) OR (char_length(nombre) <= 100)",
    )
    op.create_check_constraint(
        "ck_users_fecha_nac_adult",
        "users",
        "(fecha_nac < CURRENT_DATE) AND (DATE_PART('year', AGE(CURRENT_DATE, fecha_nac)) >= 18)",
    )

    # Índices auxiliares
    op.create_index("ix_users_estado", "users", ["estado"], unique=False)
    op.create_index("ix_users_genero", "users", ["genero"], unique=False)
    op.create_index("ix_users_is_active", "users", ["is_active"], unique=False)
    op.create_index("ix_users_updated_at", "users", ["updated_at"], unique=False)

    # Trigger para updated_at y version
    op.execute(
        """
        CREATE OR REPLACE FUNCTION users_set_updated_at_version()
        RETURNS trigger AS $$
        BEGIN
          NEW.updated_at = NOW();
          NEW.version = COALESCE(OLD.version, 1) + 1;
          RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_users_set_updated_at_version
        BEFORE UPDATE ON users
        FOR EACH ROW EXECUTE FUNCTION users_set_updated_at_version();
        """
    )


def downgrade() -> None:
    # Eliminar trigger y función
    op.execute("DROP TRIGGER IF EXISTS trg_users_set_updated_at_version ON users")
    op.execute("DROP FUNCTION IF EXISTS users_set_updated_at_version")

    # Drop índices y tabla
    op.drop_index("ix_users_updated_at", table_name="users")
    op.drop_index("ix_users_is_active", table_name="users")
    op.drop_index("ix_users_genero", table_name="users")
    op.drop_index("ix_users_estado", table_name="users")

    op.drop_table("users")

    # Drop enums (dejar citext extension intacta)
    op.execute("DROP TYPE IF EXISTS estado_mx_enum")
    op.execute("DROP TYPE IF EXISTS genero_enum")
