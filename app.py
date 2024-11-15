from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
import jwt
import os
from dotenv import load_dotenv
from functools import wraps
import re
import os


# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure CORS with specific origins
CORS(app, resources={
    r"/api/*": {
        "origins": ["http://localhost:5173"],
        "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": ["Content-Type", "Authorization"],
        "supports_credentials": True
    }
})

# Database Configuration
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_HOST = os.getenv('DB_HOST')
DB_PORT = os.getenv('DB_PORT')
DB_NAME = os.getenv('DB_NAME')

# PostgreSQL database URL
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
print(f"Trying to connect to: {DATABASE_URL}")

app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

if not os.getenv('SECRET_KEY'):
    raise ValueError("SECRET_KEY environment variable is not set!")
    
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

# Initialize database
db = SQLAlchemy(app)

# Models
class User(db.Model):
    __tablename__ = 'users'  # Added table name
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    full_name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    learning_cards = db.relationship('LearningCard', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class LearningCard(db.Model):
    __tablename__ = 'learning_cards'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Updated foreign key reference
    title = db.Column(db.String(200), nullable=False)
    progress = db.Column(db.Integer, default=0)
    target_days = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    word_pairs = db.relationship('WordPair', backref='card', lazy=True, cascade='all, delete-orphan')

class WordPair(db.Model):
    __tablename__ = 'word_pairs'
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, db.ForeignKey('learning_cards.id'), nullable=False)
    english = db.Column(db.String(100), nullable=False)
    indonesian = db.Column(db.String(100), nullable=False)
    is_learned = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# JWT Authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Invalid authorization header format'}), 401

        if not token:
            return jsonify({'error': 'Token is missing'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            # Updated: Using db.session.get() instead of Query.get()
            current_user = db.session.get(User, data['user_id'])
            
            if not current_user:
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            return jsonify({'error': 'Something went wrong'}), 500

        return f(current_user, *args, **kwargs)

    return decorated

def generate_token(user_id):
    try:
        payload = {
            'user_id': user_id,
            'exp': datetime.now(timezone.utc) + timedelta(days=1),
            'iat': datetime.now(timezone.utc)
        }
        
        token = jwt.encode(
            payload,
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        
        return token if isinstance(token, str) else token.decode('utf-8')
        
    except Exception as e:
        print(f"Token generation error: {str(e)}")
        return None

@app.route('/api/signup', methods=['POST'])
def signup():
    try:
        data = request.get_json()

        required_fields = ['email', 'fullName', 'password']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'{field} is required'}), 400

        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_regex, data['email']):
            return jsonify({'error': 'Invalid email format'}), 400

        if db.session.execute(db.select(User).filter_by(email=data['email'])).first():
            return jsonify({'error': 'Email already registered'}), 400

        new_user = User(
            email=data['email'],
            full_name=data['fullName']
        )
        new_user.set_password(data['password'])
        
        db.session.add(new_user)
        db.session.commit()

        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': new_user.id,
                'email': new_user.email,
                'fullName': new_user.full_name
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        
        if not data or not isinstance(data, dict):
            return jsonify({'error': 'Invalid request data'}), 400
            
        email = data.get('email', '').strip()
        password = data.get('password', '').strip()
        
        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        # Updated: Using db.session.execute() with select()
        result = db.session.execute(db.select(User).filter_by(email=email)).first()
        user = result[0] if result else None

        if user and user.check_password(password):
            token = generate_token(user.id)
            if not token:
                return jsonify({'error': 'Error generating token'}), 500

            return jsonify({
                'token': token,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'fullName': user.full_name
                }
            }), 200
        
        return jsonify({'error': 'Invalid credentials'}), 401

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/cards', methods=['GET'])
@token_required
def get_cards(current_user):
    try:
        # Updated: Using db.session.execute() with select()
        result = db.session.execute(
            db.select(LearningCard).filter_by(user_id=current_user.id)
        ).scalars()
        cards = list(result)
        
        return jsonify([{
            'id': card.id,
            'title': card.title,
            'progress': card.progress,
            'targetDays': card.target_days,
            'totalWords': len(card.word_pairs),
            'wordPairs': [{
                'english': pair.english,
                'indonesian': pair.indonesian
            } for pair in card.word_pairs]
        } for card in cards]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cards', methods=['POST'])
@token_required
def create_card(current_user):
    try:
        data = request.json
        
        if not data.get('title') or not data.get('targetDays') or not data.get('wordPairs'):
            return jsonify({'error': 'Missing required fields'}), 400

        new_card = LearningCard(
            title=data['title'],
            progress=0,  # Always start with 0 progress for new cards
            target_days=int(data['targetDays']),
            user_id=current_user.id
        )
        db.session.add(new_card)
        db.session.flush()
        
        for pair in data['wordPairs']:
            if not pair.get('english') or not pair.get('indonesian'):
                db.session.rollback()
                return jsonify({'error': 'Invalid word pair data'}), 400
                
            word_pair = WordPair(
                card_id=new_card.id,
                english=pair['english'],
                indonesian=pair['indonesian']
            )
            db.session.add(word_pair)
        
        db.session.commit()
        
        return jsonify({
            'id': new_card.id,
            'title': new_card.title,
            'progress': new_card.progress,
            'targetDays': new_card.target_days,
            'totalWords': len(data['wordPairs']),
            'wordPairs': data['wordPairs']
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/cards/<int:card_id>', methods=['PUT'])
@token_required
def update_card(current_user, card_id):
    try:
        result = db.session.execute(
            db.select(LearningCard).filter_by(id=card_id, user_id=current_user.id)
        ).first()
        card = result[0] if result else None
        
        if not card:
            return jsonify({'error': 'Card not found'}), 404
        
        data = request.json
        
        if not data.get('title') or not data.get('targetDays') or not data.get('wordPairs'):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Create a map of existing word pairs with their learned status
        existing_pairs = {
            f"{wp.english.lower()}:{wp.indonesian.lower()}": wp.is_learned 
            for wp in card.word_pairs
        }
        
        # Initialize learned words counter
        learned_words_count = 0
        
        # Prepare new word pairs while preserving learned status
        new_pairs = []
        for pair in data['wordPairs']:
            if not pair.get('english') or not pair.get('indonesian'):
                db.session.rollback()
                return jsonify({'error': 'Invalid word pair data'}), 400
            
            # Create a key for the current pair
            pair_key = f"{pair['english'].lower()}:{pair['indonesian'].lower()}"
            
            # Check if this pair existed before and was learned
            is_learned = existing_pairs.get(pair_key, False)
            
            # If the pair was learned, increment counter
            if is_learned:
                learned_words_count += 1
            
            new_pairs.append(WordPair(
                card_id=card_id,
                english=pair['english'],
                indonesian=pair['indonesian'],
                is_learned=is_learned
            ))
        
        # Update basic card info
        card.title = data['title']
        card.target_days = int(data['targetDays'])
        
        # Remove all existing word pairs
        db.session.execute(db.delete(WordPair).filter_by(card_id=card_id))
        
        # Add new word pairs
        for word_pair in new_pairs:
            db.session.add(word_pair)
        
        # Calculate new progress percentage
        total_words = len(new_pairs)
        if total_words > 0:
            new_progress = min(round((learned_words_count / total_words) * 100), 100)
        else:
            new_progress = 0
            
        # Update card progress
        card.progress = new_progress
        
        db.session.commit()
        
        return jsonify({
            'id': card.id,
            'title': card.title,
            'progress': card.progress,
            'targetDays': card.target_days,
            'totalWords': total_words,
            'wordPairs': [{
                'english': pair.english,
                'indonesian': pair.indonesian,
                'isLearned': pair.is_learned
            } for pair in new_pairs]
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
        
@app.route('/api/cards/<int:card_id>', methods=['DELETE'])
@token_required
def delete_card(current_user, card_id):
    try:
        # Updated: Using db.session.execute() with select()
        result = db.session.execute(
            db.select(LearningCard).filter_by(id=card_id, user_id=current_user.id)
        ).first()
        card = result[0] if result else None
        
        if not card:
            return jsonify({'error': 'Card not found'}), 404
        
        db.session.delete(card)
        db.session.commit()
        
        return jsonify({'message': 'Card deleted successfully'}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Pada Flask backend (app.py), perlu memodifikasi fungsi update_progress:

@app.route('/api/cards/<int:card_id>/progress', methods=['PUT'])
@token_required
def update_progress(current_user, card_id):
    try:
        result = db.session.execute(
            db.select(LearningCard).filter_by(id=card_id, user_id=current_user.id)
        ).first()
        card = result[0] if result else None
        
        if not card:
            return jsonify({'error': 'Card not found'}), 404
        
        data = request.json
        if 'wordPairs' not in data:
            return jsonify({'error': 'Word pairs data is required'}), 400
            
        # Get all existing word pairs for this card
        existing_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id)
        ).scalars().all()
        
        # Create a dictionary to map word pairs to their objects
        pair_map = {
            f"{pair.english}:{pair.indonesian}": pair 
            for pair in existing_pairs
        }
        
        # Update learned status for each word pair
        learned_count = 0
        total_count = len(existing_pairs)  # Use total number of existing pairs
        
        for pair_data in data['wordPairs']:
            pair_key = f"{pair_data['english']}:{pair_data['indonesian']}"
            word_pair = pair_map.get(pair_key)
            
            if word_pair:
                word_pair.is_learned = pair_data.get('isLearned', False)
                if word_pair.is_learned:
                    learned_count += 1
        
        # Calculate new progress
        if total_count > 0:
            new_progress = min(round((learned_count / total_count) * 100), 100)
            card.progress = new_progress
        else:
            card.progress = 0
            
        db.session.commit()
        
        return jsonify({
            'message': 'Progress updated successfully',
            'progress': card.progress,
            'learnedCount': learned_count,
            'totalCount': total_count
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    

@app.route('/api/cards/<int:card_id>/reset-progress', methods=['PUT'])
@token_required
def reset_progress(current_user, card_id):
    try:
        result = db.session.execute(
            db.select(LearningCard).filter_by(id=card_id, user_id=current_user.id)
        ).first()
        card = result[0] if result else None
        
        if not card:
            return jsonify({'error': 'Card not found'}), 404
            
        # Reset progress for all word pairs
        word_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id)
        ).scalars().all()
        
        for pair in word_pairs:
            pair.is_learned = False
            
        # Reset card progress
        card.progress = 0
            
        db.session.commit()
        
        return jsonify({
            'message': 'Progress reset successfully',
            'progress': 0
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/cards/<int:card_id>', methods=['GET'])
@token_required
def get_card_detail(current_user, card_id):
    try:
        result = db.session.execute(
            db.select(LearningCard).filter_by(id=card_id, user_id=current_user.id)
        ).first()
        
        if not result:
            return jsonify({'error': 'Card not found'}), 404
            
        card = result[0]
        
        # Fetch all word pairs for this card
        word_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id)
        ).scalars().all()
            
        response_data = {
            'id': card.id,
            'title': card.title,
            'progress': card.progress,
            'targetDays': card.target_days,
            'totalWords': len(word_pairs),  # Add totalWords to response
            'wordPairs': [{
                'english': pair.english,
                'indonesian': pair.indonesian
            } for pair in word_pairs]
        }
        
        return jsonify(response_data), 200
    except Exception as e:
        print(f"Error in get_card_detail: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500    

with app.app_context():
    db.create_all()


if __name__ == '__main__':
    app.run()