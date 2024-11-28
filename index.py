from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
import mysql.connector
import bcrypt
import os
from werkzeug.utils import secure_filename
import pytesseract
from pdf2image import convert_from_path
import re
from flask_login import current_user, LoginManager, UserMixin, login_required

app = Flask(__name__)
app.secret_key = 'mZ13zdMZdz'

class User(UserMixin):
    def __init__(self, user_id, email, first_name, last_name, profile_picture=None):
        self.id = user_id  # This should match the user_id column in your database
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.profile_picture = profile_picture

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Assuming you have a User model or similar
@login_manager.user_loader
def load_user(user_id):
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE user_id = %s", (user_id,))
        user_data = cursor.fetchone()
        if user_data:
            user = User(**user_data)  # Assuming you have a User class
            return user
        return None
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Set the path for Tesseract OCR (update with the correct path to tesseract executable)
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

# Database configuration
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',  # Replace with your database password
    'database': 'digitalrb'  # Replace with your database name
}

#Profile Picture Configuration
@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# File upload configuration
UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Helper function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Helper function to extract text from a PDF using Tesseract OCR
def extract_text_from_pdf(file_path):
    poppler_path = r'C:\Users\Ralph\Downloads\Release-24.08.0-0\poppler-24.08.0\Library\bin'
    images = convert_from_path(file_path, poppler_path=poppler_path)
    text = ""
    for image in images:
        text += pytesseract.image_to_string(image)
    return text

# Helper function to extract keywords from text
def extract_keywords(text):
    words = re.findall(r'\w+', text.lower())
    stop_words = {'the', 'and', 'is', 'in', 'at', 'to', 'of', 'for', 'on', 'with', 'as', 'by', 'it', 'an', 'or', 'a'}
    keywords = [word for word in words if word not in stop_words]
    return list(set(keywords))

# Helper function to calculate suitability score
def calculate_suitability(keywords, job_title, job_description):
    job_keywords = extract_keywords(job_title + ' ' + job_description)
    matched_keywords = set(keywords) & set(job_keywords)
    return (len(matched_keywords) / len(job_keywords)) * 100 if job_keywords else 0

# Restrict access to authenticated users
def login_required(func):
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            flash("You must be logged in to access this page.", "error")
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

# Restrict access to authenticated user on login page
def already_login(func):
    def wrapper(*args, **kwargs):
        if 'user_id' in session:
            flash("You're already logged in", "error")
            return redirect(url_for('home'))
        return func(*args, **kwargs)
    wrapper.__name__ = func.__name__
    return wrapper

#Preventing to cache after request
@app.after_request
def add_header(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Register route
@app.route('/register', methods=['GET', 'POST'])
@already_login
def register():
    if request.method == 'POST':
        first_name = request.form.get('first-name')
        last_name = request.form.get('last-name')
        email = request.form.get('email')
        password = request.form.get('password')

        if not all([first_name, last_name, email, password]):
            flash("All fields are required.", "error")
            return redirect(url_for('register'))

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            if cursor.fetchone():
                flash("Email is already registered.", "error")
                return redirect(url_for('register'))

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            cursor.execute("""
                INSERT INTO users (first_name, last_name, email, password)
                VALUES (%s, %s, %s, %s)
            """, (first_name, last_name, email, hashed_password))
            conn.commit()
            flash("Registration successful! You can now log in.", "success")
            return redirect(url_for('login'))
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('register.html')

# Login route
@app.route('/log', methods=['GET', 'POST'])
@already_login
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
            user = cursor.fetchone()

            if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
                # Store the user ID and is_admin status in the session
                session['user_id'] = user['id']
                session['is_admin'] = user['is_admin']  # Store the admin status

                flash("Login successful!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid email or password.", "error")
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('log.html')

# Logout route
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))

# Home route
@app.route('/index')
@login_required
def home():
    # Get user info from the session
    user_id = session['user_id']
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        return render_template('index.html', user=user)
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Upload CV route
@app.route('/upload_cv', methods=['GET', 'POST'])
@login_required
def upload_cv():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not allowed_file(file.filename):
            flash("Invalid file.", "error")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        # Extract text and keywords from the uploaded PDF
        extracted_text = extract_text_from_pdf(file_path)
        keywords = extract_keywords(extracted_text)

        try:
            # Connect to the database
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)

            # Fetch only approved jobs
            cursor.execute("SELECT * FROM jobs WHERE pending = '0'")
            jobs = cursor.fetchall()

            # Calculate suitability score for each job
            for job in jobs:
                job['suitability_score'] = round(
                    calculate_suitability(keywords, job['job_title'], job['job_description']), 2
                )

            # Sort jobs by suitability score in descending order
            jobs.sort(key=lambda x: x['suitability_score'], reverse=True)

            # Render the recommendations template
            return render_template('recommendations.html', jobs=jobs)

        finally:
            # Close the database connection
            if conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('upload_cv.html')

# Job details route
@app.route('/job_details/<int:job_id>')
@login_required
def job_details(job_id):
    user_id = session['user_id']
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        
        # Get job details
        cursor.execute("SELECT * FROM jobs WHERE job_id = %s", (job_id,))
        job = cursor.fetchone()

        # Get comments for the job
        cursor.execute("""
            SELECT c.comment_text, c.created_at, u.first_name, u.last_name 
            FROM comments c 
            JOIN users u ON c.user_id = u.id 
            WHERE c.job_id = %s
            ORDER BY c.created_at DESC
        """, (job_id,))
        comments = cursor.fetchall()

        # Check if the user is an employee
        cursor.execute("SELECT is_employee FROM users WHERE id = %s", (user_id,))
        is_employee = cursor.fetchone()['is_employee']

        return render_template('job_details.html', job=job, comments=comments, is_employee=is_employee)
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/job_listing')
@login_required
def job_listing():
    try:
        conn = mysql.connector.connect(**db_config)  # Use your db_config to connect to the database
        cursor = conn.cursor(dictionary=True)  # Using dictionary=True will return results as dictionaries
        cursor.execute("SELECT * FROM jobs WHERE pending = '0'")  # Query only approved jobs
        jobs = cursor.fetchall()  # Fetch all the jobs

        return render_template('job_listing.html', jobs=jobs)

    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Other routes
@app.route('/contact')
@login_required
def contact():
    return render_template('contact.html')

@app.route('/about')
@login_required
def about():
    # Get user info from the session
    user_id = session['user_id']
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        return render_template('about.html', user=user)
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

@app.route('/post_job', methods=['GET', 'POST'])
@login_required
def post_job():
    if request.method == 'POST':
        job_title = request.form.get('job_title')
        job_description = request.form.get('job_description')
        job_type = request.form.get('job_type')
        location = request.form.get('location')
        salary_min = request.form.get('salary_min')
        salary_max = request.form.get('salary_max')
        posted_date = request.form.get('posted_date')
        closing_date = request.form.get('closing_date')
        company_name = request.form.get('company_name')
        status = request.form.get('status')

        if not all([job_title, job_description, job_type, location, salary_min, salary_max, posted_date, closing_date, company_name, status]):
            flash("All fields are required.", "error")
            return redirect(url_for('post_job'))

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO jobs (job_title, job_description, job_type, location, salary_min, salary_max, posted_date, closing_date, company_name, status)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (job_title, job_description, job_type, location, salary_min, salary_max, posted_date, closing_date, company_name, status))
            conn.commit()
            flash("Job posted successfully!", "success")
            return redirect(url_for('home'))
        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    return render_template('post_job.html')

# Admin dashboard
@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    # Ensure the user is an admin
    if 'is_admin' not in session or not session['is_admin']:
        flash("You are not authorized to access the admin dashboard.", "error")
        return redirect(url_for('home'))

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Get user count
        cursor.execute("SELECT COUNT(*) AS user_count FROM users")
        user_count = cursor.fetchone()['user_count']

        # Get job count
        cursor.execute("SELECT COUNT(*) AS job_count FROM jobs")
        job_count = cursor.fetchone()['job_count']

        # Get pending job posts
        cursor.execute("SELECT * FROM jobs WHERE pending = 1")
        pending_jobs = cursor.fetchall()

        return render_template('admin_dashboard.html', user_count=user_count, job_count=job_count, pending_jobs=pending_jobs)
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Approve job route
@app.route('/approve_job/<int:job_id>')
@login_required
def approve_job(job_id):
    if not session.get('is_admin'):
        return redirect(url_for('home'))  # Only admin should access this page

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("UPDATE jobs SET pending = 0 WHERE job_id = %s", (job_id,))
        conn.commit()
        flash("Job approved successfully.", "success")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

    return redirect(url_for('admin_dashboard'))

# Decline job route
@app.route('/decline_job/<int:job_id>')
@login_required
def decline_job(job_id):
    if not session.get('is_admin'):
        return redirect(url_for('home'))  # Only admin should access this page

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM jobs WHERE job_id = %s", (job_id,))
        conn.commit()
        flash("Job declined successfully.", "success")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

    return redirect(url_for('admin_dashboard'))

# Edit Profile route
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    user_id = session['user_id']
    
    if request.method == 'POST':
        first_name = request.form.get('first-name')
        last_name = request.form.get('last-name')
        email = request.form.get('email')
        password = request.form.get('password')
        profile_picture = request.files.get('profile_picture')

        if not first_name or not last_name or not email:
            flash("All fields are required.", "error")
            return redirect(url_for('edit_profile'))

        try:
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()

            # Update user details
            if password:
                hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
                cursor.execute("""
                    UPDATE users 
                    SET first_name = %s, last_name = %s, email = %s, password = %s 
                    WHERE id = %s
                """, (first_name, last_name, email, hashed_password, user_id))
            else:
                cursor.execute("""
                    UPDATE users 
                    SET first_name = %s, last_name = %s, email = %s 
                    WHERE id = %s
                """, (first_name, last_name, email, user_id))

            # Handle profile picture update
            if profile_picture:
                filename = secure_filename(profile_picture.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                profile_picture.save(file_path)
                cursor.execute("""
                    UPDATE users 
                    SET profile_picture = %s 
                    WHERE id = %s
                """, (filename, user_id))

            conn.commit()
            flash("Profile updated successfully!", "success")
            return redirect(url_for('edit_profile'))

        finally:
            if conn.is_connected():
                cursor.close()
                conn.close()

    # Fetch user details for the form
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        return render_template('edit_profile.html', user=user)
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        return render_template('edit_profile.html', user=user)
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

#Apply Job
@app.route('/apply_job/<int:job_id>', methods=['POST'])
@login_required
def apply_job(job_id):
    user_id = session['user_id']
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        # Save the application
        cursor.execute("""
            INSERT INTO applications (user_id, job_id)
            VALUES (%s, %s)
        """, (user_id, job_id))
        conn.commit()
        flash("You have successfully applied for this job!", "success")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    return redirect(url_for('job_details', job_id=job_id))

#Comments
@app.route('/add_comment/<int:job_id>', methods=['POST'])
@login_required
def add_comment(job_id):
    user_id = session['user_id']
    comment_text = request.form.get('comment')
    
    if not comment_text:
        flash("Comment cannot be empty.", "error")
        return redirect(url_for('job_details', job_id=job_id))

    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        # Insert comment into the database
        cursor.execute("""
            INSERT INTO comments (user_id, job_id, comment_text)
            VALUES (%s, %s, %s)
        """, (user_id, job_id, comment_text))
        conn.commit()
        flash("Comment added successfully!", "success")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
    return redirect(url_for('job_details', job_id=job_id))

#Comments Route
@app.route('/comment')
@login_required
def my_comments():
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Fetch all comments made by the logged-in user
        cursor.execute("""
            SELECT c.comment_text, c.created_at, j.job_title, j.job_id
            FROM comments c
            JOIN jobs j ON c.job_id = j.job_id
            WHERE c.user_id = %s
            ORDER BY c.created_at DESC
        """, (session['user_id'],))
        user_comments = cursor.fetchall()

        return render_template('comments.html', comments=user_comments)

    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

# Route to view user information
@app.route('/my_info')
@login_required
def my_info():
    if current_user.is_authenticated:
        user_id = current_user.id  # Assuming 'id' is set on login and corresponds to the primary key in the users table

        try:
            # Connect to the database and fetch user data
            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor(dictionary=True)
            
            # Fetch user data from the 'users' table based on the user_id
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchone()  # Get the first result

            if user:
                # Render the 'my_info.html' page and pass the user data
                return render_template('my_info.html', user=user)
            else:
                flash("User data not found.", "error")
                return redirect(url_for('index'))
        
        except mysql.connector.Error as err:
            flash(f"Error: {err}", "error")
            return redirect(url_for('index'))
        
        finally:
            # Close the database connection
            if conn.is_connected():
                cursor.close()
                conn.close()
                
# Run the application
if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    app.run(debug=True)

