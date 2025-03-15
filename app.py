import whisper
import os
from flask import Flask, render_template, request, jsonify, flash, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import speech_recognition as sr
from tempfile import NamedTemporaryFile
from deep_translator import GoogleTranslator
import difflib
import requests
from functools import wraps

# Initialize Flask app and set up the secret key
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'subesh')  # Use environment variable for production

# Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # SQLite database
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=True)
    password = db.Column(db.String(200), nullable=False)
    
class PronunciationHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sentence = db.Column(db.Text, nullable=False)
    transcript = db.Column(db.Text, nullable=False)
    similarity_score = db.Column(db.Float, nullable=False)
    incorrect_words = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())

    user = db.relationship('User', backref=db.backref('history', lazy=True))

    
    
def calculate_similarity(sentence, transcript):
    words1 = sentence.lower().split()
    words2 = transcript.lower().split()
    
    matcher = difflib.SequenceMatcher(None, words1, words2)
    similarity = matcher.ratio() * 100  # Convert to percentage

    incorrect_words = []
    for i, word in enumerate(words2):
        if i >= len(words1) or word != words1[i]:  # Check word mismatch
            incorrect_words.append((i + 1, word))  # Store position and word

    return similarity, incorrect_words

# Load Whisper model (you can use "base", "small", "medium", or "large" depending on your resources)
model = whisper.load_model("base", device="cpu")  # Removed fp16 argument

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.endpoint != 'login':  # Prevent infinite redirect
                flash('Please log in to access this page.', 'danger')
                return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
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
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'danger')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            flash('Error: Email or Username already exists!', 'danger')

    return render_template('signup.html')

@app.route('/home')
def home():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    return render_template('home.html')

@app.route('/logout')
@login_required
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/forgot', methods=['GET', 'POST'])
def forgot():
    if request.method == 'POST':
        email = request.form['email']
        # Logic for handling password reset (e.g., sending an email)
        flash('If this email is registered, a password reset link has been sent.', 'info')
        return redirect(url_for('login'))
    return render_template('forgot.html')

@app.route('/history')
@login_required
def history():
    if 'user_id' not in session:
        flash('Please log in to view your history.', 'danger')
        return redirect(url_for('login'))

    user_history = PronunciationHistory.query.filter_by(user_id=session['user_id']).order_by(PronunciationHistory.timestamp.desc()).all()
    return render_template('history.html', history=user_history)


@app.route('/pronunciation_detector')
@login_required
def pronunciation_detector():
    return render_template('pronunciation_detector.html')

@app.route('/process_pronunciation', methods=['POST'])
@login_required
def process_pronunciation():
    try:
        if 'user_id' not in session:
            return jsonify({'error': 'Please log in to save history'}), 401

        data = request.get_json()
        sentence = data['sentence']
        transcript = data['transcript']

        similarity_score, incorrect_words = calculate_similarity(sentence, transcript)
        feedback = f"Pronunciation Score: {similarity_score:.2f}%"

        incorrect_words_str = ", ".join(f"({pos}) {word}" for pos, word in incorrect_words)

        # Save to Database
        history_entry = PronunciationHistory(
            user_id=session['user_id'],
            sentence=sentence,
            transcript=transcript,
            similarity_score=similarity_score,
            incorrect_words=incorrect_words_str
        )
        db.session.add(history_entry)
        db.session.commit()

        if incorrect_words:
            feedback += f" | Incorrect words: {incorrect_words_str}"
        else:
            feedback += " | Perfect Pronunciation! ✅"

        return jsonify({'feedback': feedback})
    
    except Exception as e:
        return jsonify({'feedback': f'Error processing pronunciation: {str(e)}'}), 500

@app.route('/check_grammar', methods=['POST'])
@login_required
def check_grammar():
    data = request.get_json()
    sentence = data.get('sentence')

    if not sentence:
        return jsonify({"feedback": "No sentence provided!"}), 400
    
    try:
        response = requests.post(
            'https://api.languagetool.org/v2/check',
            headers={'Content-Type': 'application/x-www-form-urlencoded'},
            data={'text': sentence, 'language': 'en-US'}
        )
        
        result = response.json()
        
        if result.get("matches"):
            corrections = [
                f"{match['message']} (suggested: {', '.join(rep['value'] for rep in match['replacements'])})"
                for match in result["matches"]
            ]
            feedback = "\n".join(corrections)
        else:
            feedback = "No grammar or spelling errors found!"
    
    except Exception as e:
        feedback = f"Error checking grammar: {e}"
    
    return jsonify({"feedback": feedback})

@app.route('/grammar_checker')
@login_required
def grammar_checker():
    return render_template('grammar_checker.html')

@app.route('/translate', methods=['POST'])
@login_required
def translate():
    data = request.get_json()
    text = data.get('text', '').strip()
    target_lang = data.get('target_lang', '').strip()

    if not text or not target_lang:
        return jsonify({'error': 'Missing text or target language'}), 400

    try:
        translated_text = GoogleTranslator(source="auto", target=target_lang).translate(text)
        return jsonify({"translation": translated_text})

    except Exception as e:
        return jsonify({"error": f"Translation failed: {e}"})

@app.route('/translate_page')
@login_required
def translate_page():
    return render_template('translator.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)



