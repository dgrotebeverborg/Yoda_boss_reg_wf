import pytest
from app.models import User, Application, Faculty
from sqlalchemy.exc import IntegrityError

# Setting up a fixture for the database
@pytest.fixture(scope='module')
def new_user():
    user = User(username='testuser', password='testpassword', role='APPROVER', faculty_id=1)
    return user

@pytest.fixture(scope='module')
def new_application():
    application = Application(first_name='John', last_name='Doe', faculty_id=1, department='TestDept', solisid='12345', email='john.doe@example.com')
    return application

@pytest.fixture(scope='module')
def new_faculty():
    faculty = Faculty(name='Test Faculty')
    return faculty

# Tests for User model
def test_new_user(new_user):
    assert new_user.username == 'testuser'
    assert new_user.password == 'testpassword'
    assert new_user.role == 'APPROVER'
    assert new_user.faculty_id == 1

# Tests for Application model
def test_new_application(new_application):
    assert new_application.first_name == 'John'
    assert new_application.last_name == 'Doe'
    assert new_application.faculty_id == 1
    assert new_application.department == 'TestDept'
    assert new_application.solisid == '12345'
    assert new_application.email == 'john.doe@example.com'

# Tests for Faculty model
def test_new_faculty(new_faculty):
    assert new_faculty.name == 'Test Faculty'
# from flask_testing import TestCase
#
# class MyTest(TestCase):
#     def create_app(self):
#         return create_app('testing')
#
#     def test_home_page(self):
#         response = self.client.get('/')
#         assert response.status_code == 200
#
#     def test_protected_page(self):
#         response = self.client.get('/protected', follow_redirects=True)
#         assert b"Please log in to access this page" in response.data
