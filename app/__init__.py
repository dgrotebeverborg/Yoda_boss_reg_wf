from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from .extensions import db
# Initialize extensions
# db = SQLAlchemy()
from .extensions import db, login_manager, migrate  # Importing from extensions.py
from flask import Flask
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)

    # App configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
    app.config['SECRET_KEY'] = 'your_secret_key'

    # Initialize extensions with app context
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'
    migrate.init_app(app, db)  # Initialize Flask-Migrate with app and db

    # User loader for Flask-Login
    from .models import User  # Import here to avoid circular dependency

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Import routes
    from .routes import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app
