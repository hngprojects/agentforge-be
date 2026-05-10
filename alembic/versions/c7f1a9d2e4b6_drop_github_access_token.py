"""drop github access token

Revision ID: c7f1a9d2e4b6
Revises: 3f2d9d9d7b8a
Create Date: 2026-05-09 12:15:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'c7f1a9d2e4b6'
down_revision: Union[str, None] = '3f2d9d9d7b8a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column('users', 'github_access_token')


def downgrade() -> None:
    op.add_column(
        'users',
        sa.Column('github_access_token', sa.Text(), nullable=True),
    )
