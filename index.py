from flask import Flask, render_template, request, redirect, url_for, flash
import mysql.connector
import bcrypt
import os
from werkzeug.utils import secure_filename
import pytesseract
from pdf2image import convert_from_path
import re

app = Flask(__name__)
app.secret_key = 'mZ13zdMZdz'

# Set the path for Tesseract OCR (update with the correct path to tesseract executable)
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"  # Windows path
# Or for macOS/Linux:
# pytesseract.pytesseract.tesseract_cmd = "/usr/local/bin/tesseract"  # macOS/Linux path

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # Replace with your database password
    'database': 'digitalrb'  # Replace with your database name
}

# File upload configuration
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to extract text from a PDF using Tesseract OCR
def extract_text_from_pdf(file_path):
    # Change the path to Poppler here if it's not already in your system's PATH
    poppler_path = r'C:\Users\Ralph\Downloads\Release-24.08.0-0\poppler-24.08.0\Library\bin'  # <-- Update this path to your Poppler installation path
    
    # Convert PDF to images using pdf2image with the specified Poppler path
    images = convert_from_path(file_path, poppler_path=poppler_path)
    
    text = ""
    for image in images:
        text += pytesseract.image_to_string(image)
    return text

# Helper function to extract keywords from text
def extract_keywords(text):
    words = re.findall(r'\w+', text.lower())
    stop_words = {'the', 'and', 'is', 'in', 'at', 'to', 'of', 'for', 'on', 'with', 'as', 'by', 'it', 'an', 'or', 'a'}  # You can expand this list
    keywords = [word for word in words if word not in stop_words]
    return list(set(keywords))  # Return unique keywords

# Helper function to calculate suitability score based on keyword matching
def calculate_suitability(keywords, job_title, job_description):
    job_keywords = extract_keywords(job_title + ' ' + job_description)
    matched_keywords = set(keywords) & set(job_keywords)
    if len(job_keywords) > 0:
        return (len(matched_keywords) / len(job_keywords)) * 100
    else:
        return 0  # Return 0 if no job keywords found

# Register route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first-name')
        last_name = request.form.get('last-name')
        email = request.form.get('email')
        password = request.form.get('password')

        if not first_name or not last_name or not email or not password:
            flash("All fields are required.", "error")
            return redirect(url_for('register'))

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()

            # Check if the email is already registered
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email is already registered.", "error")
                return redirect(url_for('register'))

            # Hash the password
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

            # Insert into database
            query = """
                INSERT INTO users (first_name, last_name, email, password)
                VALUES (%s, %s, %s, %s)
            """
            cursor.execute(query, (first_name, last_name, email, hashed_password))
            conn.commit()

            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "error")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('register.html')

# Login route
@app.route('/log', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)

            query = "SELECT * FROM users WHERE email = %s"
            cursor.execute(query, (email,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                flash("Login successful!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid email or password.", "error")
        except mysql.connector.Error as err:
            flash(f"Database error: {err}", "error")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('log.html')

# Home route
@app.route('/index')
def home():
    return render_template('index.html')

# Upload CV route
@app.route('/upload_cv', methods=['GET', 'POST'])
def upload_cv():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash("No file part", "error")
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash("No selected file", "error")
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            # Extract text and keywords
            extracted_text = extract_text_from_pdf(file_path)
            keywords = extract_keywords(extracted_text)

            # Match keywords with database and calculate suitability scores
            try:
                conn = mysql.connector.connect(**db_config)
                cursor = conn.cursor(dictionary=True)

                # Query jobs
                query = "SELECT * FROM jobs"
                cursor.execute(query)
                jobs = cursor.fetchall()

                recommended_jobs = []
                for job in jobs:
                    # Calculate suitability score for each job
                    suitability_score = calculate_suitability(keywords, job['job_title'], job['job_description'])
                    # Add the job and its suitability score to the recommended jobs list
                    job['suitability_score'] = round(suitability_score, 2)
                    recommended_jobs.append(job)

            except mysql.connector.Error as err:
                flash(f"Database error: {err}", "error")
                recommended_jobs = []
            finally:
                if conn.is_connected():
                    cursor.close()
                    conn.close()

            # Sort recommended jobs by suitability score in descending order (higher to lower)
            recommended_jobs.sort(key=lambda x: x['suitability_score'], reverse=True)

            # Render recommendations with suitability scores
            return render_template('recommendations.html', jobs=recommended_jobs)

    return render_template('upload_cv.html')

# Other routes (contact, about, etc.)
@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')


    # Job details route
@app.route('/job_details/<int:job_id>')
def job_details(job_id):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Query to fetch the job details based on the job_id
        query = "SELECT * FROM jobs WHERE job_id = %s"
        cursor.execute(query, (job_id,))
        job = cursor.fetchone()

        if job:
            return render_template('job_details.html', job=job)
        else:
            flash("Job not found.", "error")
            return redirect(url_for('home'))

    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "error")
        return redirect(url_for('home'))
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/job_listing')
def job_listings():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM jobs"
        cursor.execute(query)
        jobs_data = cursor.fetchall()
    except mysql.connector.Error as err:
        flash(f"Database error: {err}", "error")
        jobs_data = []
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

    return render_template('job_listing.html', jobs=jobs_data)

# Run the application
if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)
