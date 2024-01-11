from .extensions import db
from flask_login import UserMixin
from enum import Enum
class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(128), nullable=False)
    last_name = db.Column(db.String(128), nullable=False)
    # faculty = db.Column(db.String(128), nullable=False)
    department = db.Column(db.String(128), nullable=False)
    solisid = db.Column(db.String(128), unique=True, nullable=False)
    email = db.Column(db.String(128), unique=True, nullable=False)
    status = db.Column(db.String(20), nullable=False, default='pending')
    approved_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    approved_at = db.Column(db.DateTime)
    approved_by_user = db.relationship('User')  # Relationship to User
    faculty_id = db.Column(db.Integer, db.ForeignKey('faculty.id'))

    def __repr__(self):
        return f'<Application {self.first_name} {self.last_name}>'

class Role(Enum):
    ADMIN = 'admin'
    APPROVER = 'approver'
    USER = 'user'

class Faculty(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    role = db.Column(db.Enum(Role), default=Role.USER)
    faculty_id = db.Column(db.Integer, db.ForeignKey('faculty.id'), nullable=True)
    faculty = db.relationship('Faculty')




