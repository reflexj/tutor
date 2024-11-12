"""Add additional_information column to service_post

Revision ID: 90b9bfa56d81
Revises: 6993f7e35317
Create Date: 2024-11-12 22:50:36.100430
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '90b9bfa56d81'
down_revision = '6993f7e35317'
branch_labels = None
depends_on = None

def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('service_post', schema=None) as batch_op:
        batch_op.add_column(sa.Column('additional_info', sa.String(length=200), nullable=True))

    # ### end Alembic commands ###

def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('service_post', schema=None) as batch_op:
        batch_op.drop_column('additional_info')

    # ### end Alembic commands ###
