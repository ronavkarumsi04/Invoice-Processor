from flask import Flask, render_template, request, jsonify, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from PIL import Image
import pytesseract
import requests
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    processed_data = db.Column(db.Text)
    user = db.relationship('User', backref=db.backref('invoices', lazy=True))

db.create_all()

# Function to extract text from image using Tesseract OCR
def extract_text_from_image(image):
    try:
        text = pytesseract.image_to_string(image)
        return text.strip()
    except Exception as e:
        print(f"Error extracting text from image: {e}")
        return None

# Dummy function to process invoice through ReQlogic
def process_invoice_through_reqlogic(invoice_data):
    try:
        response = requests.post('https://reqlogicapi.com/process_invoice', data=invoice_data)
        return response.text
    except Exception as e:
        print(f"Error processing invoice through ReQlogic: {e}")
        return None

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    user_invoices = Invoice.query.filter_by(user_id=current_user.id).all()
    return render_template('dashboard.html', user_invoices=user_invoices)

@app.route('/upload', methods=['POST'])
@login_required
def upload():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'})

        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'})

        if file:
            # Save the uploaded file with a unique name
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Open the uploaded image
            image = Image.open(file_path)

            # Extract text from the uploaded image
            extracted_text = extract_text_from_image(image)
            if not extracted_text:
                return jsonify({'error': 'Failed to extract text from image'})

            # Process extracted text
            processed_data = process_invoice_through_reqlogic({'text': extracted_text})

            # Save invoice details to the database
            new_invoice = Invoice(user_id=current_user.id, filename=filename, processed_data=processed_data)
            db.session.add(new_invoice)
            db.session.commit()

            return jsonify({'success': True, 'message': 'Invoice processed successfully', 'result': processed_data})
    except Exception as e:
        print(f"Error processing invoice: {e}")
        return jsonify({'error': 'An error occurred'})

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)

# Define your models here

# Place your db.create_all() statement within the application context
with app.app_context():
    db.create_all()
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'

db = SQLAlchemy(app)

# Define your models here
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)

class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(100), nullable=False)
    processed_data = db.Column(db.Text)
    user = db.relationship('User', backref=db.backref('invoices', lazy=True))

# Place your db.create_all() statement within the application context
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
