from werkzeug.security import generate_password_hash
from app import create_app, db
from app.models import User, Role

# Initialize the Flask application context
app = create_app()
def create_users():
    with app.app_context():
        # Create an admin user
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                password=generate_password_hash('test123'),
                role=Role.ADMIN
            )
            db.session.add(admin)

        # Create two approver users
        for i in range(1, 3):
            if not User.query.filter_by(username=f'approver{i}').first():
                approver = User(
                    username=f'approver{i}',
                    password=generate_password_hash('test123'),
                    role=Role.APPROVER
                )
                db.session.add(approver)

        db.session.commit()

if __name__ == "__main__":
    create_users()
