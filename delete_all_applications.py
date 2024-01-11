from app import create_app, db
from app.models import Application

app = create_app()

with app.app_context():
    # Retrieve all applications
    applications = Application.query.all()

    # Delete each application
    for application in applications:
        db.session.delete(application)

    # Commit the changes to the database
    db.session.commit()

    print("All applications have been deleted.")
