"""Added price column to demand_post

Revision ID: b6c4a0b7d080
Revises: 13c511b7d3c0
Create Date: 2024-11-10 23:42:08.111461

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b6c4a0b7d080'
down_revision = '13c511b7d3c0'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('demand_post', schema=None) as batch_op:
        batch_op.add_column(sa.Column('price', sa.Float(), nullable=False))
        batch_op.alter_column('grade',
               existing_type=sa.VARCHAR(length=20),
               nullable=False)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('demand_post', schema=None) as batch_op:
        batch_op.alter_column('grade',
               existing_type=sa.VARCHAR(length=20),
               nullable=True)
        batch_op.drop_column('price')

    # ### end Alembic commands ###
