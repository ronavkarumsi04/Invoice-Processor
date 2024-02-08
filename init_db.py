from app import db

# Place db.create_all() within the application context
with db.app.app_context():
    db.create_all()
