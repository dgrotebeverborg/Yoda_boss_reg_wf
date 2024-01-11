import sqlalchemy
from flask import render_template, request, redirect, url_for

from . import db  # Relative import
from datetime import datetime
from .models import Application, Role, Faculty, User
from flask import request, redirect, url_for, render_template, flash
from flask import render_template, redirect, url_for, request, current_app, Blueprint
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash
from functools import wraps


# Your route definitions here
main = Blueprint('main', __name__)

from flask import flash

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                return redirect(url_for('main.index', next=request.url))
            return f(*args, **kwargs)
        return decorated_function
    return decorator



@main.route('/apply', methods=['GET', 'POST'])
def apply():
    faculties = Faculty.query.all()  # Query all faculties
    if request.method == 'POST':
        # Data processing
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        # faculty = request.form['faculty']
        department = request.form['department']
        solisid = request.form['solisid']
        email = request.form['email']
        faculty_id = request.form.get('faculty_id')

        # Data validation (basic example)
        if not first_name or not last_name:
            flash('Please fill out all required fields.', 'error')
            return render_template('application_form.html', faculties=faculties)  # Pass faculties here

        # Save to database (placeholder code)
        new_application = Application(
            first_name=first_name,
            last_name=last_name,
            # faculty=faculty,
            faculty_id=faculty_id,
            department=department,
            solisid=solisid,
            email=email
        )

        try:
            db.session.add(new_application)
            db.session.commit()
            flash('Application submitted successfully!', 'success')
        except sqlalchemy.exc.IntegrityError as e:
            db.session.rollback()
            app.logger.error(f'Integrity Error: {e}')  # Log the specific error
            flash('An error occurred. Please try again.', 'error')

        return redirect(url_for('main.apply'))


        # Send email notification (placeholder code)
        # send_confirmation_email(first_name, last_name, ...)

        # Redirect to a new page or display success message
        flash('Your application has been submitted successfully!', 'success')
        return redirect(url_for('application_submitted'))


    # GET request
    return render_template('application_form.html', faculties=faculties)

@main.route('/approver')
@login_required

def approver():
    if current_user.role == Role.APPROVER:
        if current_user.faculty_id:
            # Approver is assigned to a specific faculty
            print(current_user.faculty_id)
            pending_applications = Application.query.filter_by(
                faculty_id=current_user.faculty_id, status='pending').all()
        else:
            # Approver can approve applications from all faculties
            pending_applications = Application.query.filter_by(status='pending').all()
    else:
        # If not an approver, redirect to a different page or show an error
        flash('You do not have permission to access this page.')
        return redirect(url_for('main.index'))

    return render_template('approver_dashboard.html', applications=pending_applications)


@main.route('/application-submitted')
def application_submitted():
    return render_template('application_submitted.html')



@main.route('/approve/<int:application_id>')
@login_required
def approve_application(application_id):
    application = Application.query.get_or_404(application_id)
    application.status = 'approved'  # Set status as 'approved'
    application.approved_by = current_user.username
    # yoda apie call user aanmaken
    application.approved_by_username = current_user.username
    application.approved_at = datetime.utcnow()
    db.session.commit()
    flash('Application approved successfully.', 'success')
    return redirect(url_for('main.approver'))

@main.route('/reject/<int:application_id>')
@login_required
def reject_application(application_id):
    application = Application.query.get_or_404(application_id)
    application.status = 'rejected'  # Set status as 'rejected'
    db.session.commit()
    flash('Application rejected.', 'info')
 # Add to routes.py   return redirect(url_for('main.approver'))


@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == Role.ADMIN:
                return redirect(url_for('main.admin_dashboard'))
            elif user.role == Role.APPROVER:
                return redirect(url_for('main.approver'))
        else:
            flash('Invalid username or password')

        # If login is invalid, you might want to flash a message here

    return render_template('login.html')

@main.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.login'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.role == Role.ADMIN:
            return redirect(url_for('main.index', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@main.route('/admin')
@login_required
@admin_required
@role_required(Role.ADMIN)
def admin_dashboard():
    return render_template('admin_dashboard.html')

@main.route('/admin/applications')
@login_required
@admin_required
def view_applications():
    applications = Application.query.join(Faculty, Application.faculty_id == Faculty.id).add_columns(Application.id, Application.first_name, Application.last_name, Faculty.name, Application.status).all()
    return render_template('admin_view_applications.html', applications=applications)


@main.route('/admin/faculties')
@login_required
@admin_required
def admin_faculties():
    faculties = Faculty.query.all()
    return render_template('admin_faculties.html', faculties=faculties)

@main.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.all()
    return render_template('admin_users.html', users=users)

@main.route('/admin/faculties/add', methods=['POST'])
@login_required
@admin_required
def add_faculty():
    name = request.form.get('name')
    if name:
        new_faculty = Faculty(name=name)
        db.session.add(new_faculty)
        db.session.commit()
        flash('Faculty added successfully.')
    else:
        flash('Faculty name is required.')
    return redirect(url_for('main.admin_faculties'))

@main.route('/admin/faculties/edit/<int:faculty_id>', methods=['POST'])
@login_required
@admin_required
def edit_faculty(faculty_id):
    faculty = Faculty.query.get_or_404(faculty_id)
    faculty.name = request.form.get('name')
    db.session.commit()
    flash('Faculty updated successfully.')
    return redirect(url_for('main.admin_faculties'))

@main.route('/admin/faculties/delete/<int:faculty_id>', methods=['POST'])
@login_required
@admin_required
def delete_faculty(faculty_id):
    faculty = Faculty.query.get_or_404(faculty_id)
    db.session.delete(faculty)
    db.session.commit()
    flash('Faculty deleted successfully.')
    return redirect(url_for('main.admin_faculties'))

@main.route('/admin/users/add', methods=['GET', 'POST'])
@login_required
@admin_required
def add_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role = request.form.get('role')
        faculty_id = request.form.get('faculty_id')

        # Hash the password and create a new User object
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role, faculty_id=faculty_id)

        # Add to the database
        db.session.add(new_user)
        try:
            db.session.commit()
            flash('User added successfully!', 'success')
        except sqlalchemy.exc.IntegrityError:
            db.session.rollback()
            flash('Username already exists!', 'error')
        return redirect(url_for('main.admin_users'))

    # GET request - display the user form
    faculties = Faculty.query.all()
    return render_template('add_user.html', faculties=faculties)


@main.route('/admin/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        user.username = request.form.get('username')
        user.role = request.form.get('role')
        user.faculty_id = request.form.get('faculty_id')

        # Update in the database
        db.session.commit()
        flash('User updated successfully!', 'success')
        return redirect(url_for('main.admin_users'))

    # GET request - display the user form with current user data
    faculties = Faculty.query.all()
    return render_template('edit_user.html', user=user, faculties=faculties)


@main.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully!', 'success')
    return redirect(url_for('main.admin_users'))


@main.route('/approved')
@login_required
def approved_applications():
    applications = Application.query.filter_by(status='approved').all()
    return render_template('approved_applications.html', applications=applications)

@main.route('/all-applications')
@login_required
def all_applications():
    applications = Application.query.all()
    applications = Application.query.filter_by(faculty_id=current_user.faculty_id).join(Faculty, Application.faculty_id == Faculty.id).add_columns(Application.id,
                                                                                                     Application.first_name,
                                                                                                     Application.last_name,
                                                                                                     Faculty.name,
                                                                                                     Application.department,
                                                                                                     Application.email,
                                                                                                     Application.approved_by,
                                                                                                     Application.approved_at,
                                                                                                     Application.status).all()

    return render_template('all_applications.html', applications=applications)




