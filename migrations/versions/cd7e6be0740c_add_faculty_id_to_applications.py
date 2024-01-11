"""Add faculty_id to applications

Revision ID: cd7e6be0740c
Revises: 38e111e81700
Create Date: 2023-12-07 14:13:29.181465

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cd7e6be0740c'
down_revision = '38e111e81700'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('application', schema=None) as batch_op:
        batch_op.add_column(sa.Column('faculty_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_application_faculty', 'faculty', ['faculty_id'], ['id'])

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('application', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_column('faculty_id')

    # ### end Alembic commands ###