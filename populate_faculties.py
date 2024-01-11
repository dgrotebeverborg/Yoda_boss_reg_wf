from app import create_app, db
from app.models import Faculty

# Initialize the Flask application context
app = create_app()
with app.app_context():
    # Define the list of faculties
    faculties = [
        "Faculty of Humanities",
        "Faculty of Science",
        "Faculty of Law, Economics and Governance",
        "Faculty of Medicine",
        "Faculty of Geosciences",
        "Faculty of Social and Behavioural Sciences",
        "Faculty of Veterinary Medicine",
        "University College Utrecht",
        "University College Roosevelt"
    ]

    # Populate the database
    for name in faculties:
        if not Faculty.query.filter_by(name=name).first():
            new_faculty = Faculty(name=name)
            db.session.add(new_faculty)

    db.session.commit()
    print("Faculties have been populated in the database.")
