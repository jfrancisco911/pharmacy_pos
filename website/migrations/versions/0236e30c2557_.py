"""empty message

Revision ID: 0236e30c2557
Revises: 56d767d44ed7
Create Date: 2024-04-12 10:28:11.088311

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0236e30c2557'
down_revision = '56d767d44ed7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('item', schema=None) as batch_op:
        batch_op.add_column(sa.Column('archived', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('item', schema=None) as batch_op:
        batch_op.drop_column('archived')

    # ### end Alembic commands ###
