
from app import app, db

with app.app_context():
	db.create_all()
	print("Database tables created (if not exist). You can now run add_history_column.py if needed.")
