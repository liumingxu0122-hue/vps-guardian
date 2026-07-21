"""Initial controller schema."""

from alembic import op
import sqlalchemy as sa

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Models are the migration source of truth; create_all is deterministic for the first revision.
    from guardian.database import Base
    from guardian import models  # noqa: F401

    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)


def downgrade() -> None:
    from guardian.database import Base
    from guardian import models  # noqa: F401

    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)
