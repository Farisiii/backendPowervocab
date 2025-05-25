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


# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure CORS with specific origins
CORS(app, resources={
    r"/api/*": {
        "origins": ["*"],
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
    __tablename__ = 'users'
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
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    progress = db.Column(db.Integer, default=0)
    target_days = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    word_pairs = db.relationship('WordPair', backref='card', lazy=True, cascade='all, delete-orphan', order_by='WordPair.order_index')

class WordPair(db.Model):
    __tablename__ = 'word_pairs'
    id = db.Column(db.Integer, primary_key=True)
    card_id = db.Column(db.Integer, db.ForeignKey('learning_cards.id'), nullable=False)
    english = db.Column(db.String(100), nullable=False)
    indonesian = db.Column(db.String(100), nullable=False)
    is_learned = db.Column(db.Boolean, default=False)
    order_index = db.Column(db.Integer, nullable=False, default=0)  # New field for consistent ordering
    last_studied = db.Column(db.DateTime, nullable=True)  # Track when word was last studied
    study_count = db.Column(db.Integer, default=0)  # Track how many times studied
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
            'learnedWords': len([pair for pair in card.word_pairs if pair.is_learned]),
            'wordPairs': [{
                'id': pair.id,
                'english': pair.english,
                'indonesian': pair.indonesian,
                'isLearned': pair.is_learned,
                'orderIndex': pair.order_index,
                'studyCount': pair.study_count,
                'lastStudied': pair.last_studied.isoformat() if pair.last_studied else None
            } for pair in sorted(card.word_pairs, key=lambda x: x.order_index)]
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
            progress=0,
            target_days=int(data['targetDays']),
            user_id=current_user.id
        )
        db.session.add(new_card)
        db.session.flush()
        
        # Add word pairs with order index to maintain consistent ordering
        for index, pair in enumerate(data['wordPairs']):
            if not pair.get('english') or not pair.get('indonesian'):
                db.session.rollback()
                return jsonify({'error': 'Invalid word pair data'}), 400
                
            word_pair = WordPair(
                card_id=new_card.id,
                english=pair['english'],
                indonesian=pair['indonesian'],
                order_index=index  # Set order index
            )
            db.session.add(word_pair)
        
        db.session.commit()
        
        # Get the created word pairs with their IDs
        created_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=new_card.id).order_by(WordPair.order_index)
        ).scalars().all()
        
        return jsonify({
            'id': new_card.id,
            'title': new_card.title,
            'progress': new_card.progress,
            'targetDays': new_card.target_days,
            'totalWords': len(created_pairs),
            'learnedWords': 0,
            'wordPairs': [{
                'id': pair.id,
                'english': pair.english,
                'indonesian': pair.indonesian,
                'isLearned': pair.is_learned,
                'orderIndex': pair.order_index,
                'studyCount': pair.study_count,
                'lastStudied': None
            } for pair in created_pairs]
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
            
        # Create a map of existing word pairs with their learned status and study data
        existing_pairs_map = {}
        for wp in card.word_pairs:
            key = f"{wp.english.lower().strip()}:{wp.indonesian.lower().strip()}"
            existing_pairs_map[key] = {
                'is_learned': wp.is_learned,
                'study_count': wp.study_count,
                'last_studied': wp.last_studied
            }
        
        # Update basic card info
        card.title = data['title']
        card.target_days = int(data['targetDays'])
        
        # Remove all existing word pairs
        db.session.execute(db.delete(WordPair).filter_by(card_id=card_id))
        
        # Add new word pairs while preserving learned status and study data
        learned_words_count = 0
        new_pairs = []
        
        for index, pair in enumerate(data['wordPairs']):
            if not pair.get('english') or not pair.get('indonesian'):
                db.session.rollback()
                return jsonify({'error': 'Invalid word pair data'}), 400
            
            # Create key for matching with existing data
            pair_key = f"{pair['english'].lower().strip()}:{pair['indonesian'].lower().strip()}"
            existing_data = existing_pairs_map.get(pair_key, {})
            
            is_learned = existing_data.get('is_learned', False)
            study_count = existing_data.get('study_count', 0)
            last_studied = existing_data.get('last_studied', None)
            
            if is_learned:
                learned_words_count += 1
            
            word_pair = WordPair(
                card_id=card_id,
                english=pair['english'],
                indonesian=pair['indonesian'],
                is_learned=is_learned,
                study_count=study_count,
                last_studied=last_studied,
                order_index=index  # Maintain order
            )
            db.session.add(word_pair)
            new_pairs.append(word_pair)
        
        # Calculate new progress percentage
        total_words = len(new_pairs)
        if total_words > 0:
            new_progress = min(round((learned_words_count / total_words) * 100), 100)
        else:
            new_progress = 0
            
        card.progress = new_progress
        db.session.commit()
        
        # Get the updated word pairs with their new IDs
        updated_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id).order_by(WordPair.order_index)
        ).scalars().all()
        
        return jsonify({
            'id': card.id,
            'title': card.title,
            'progress': card.progress,
            'targetDays': card.target_days,
            'totalWords': total_words,
            'learnedWords': learned_words_count,
            'wordPairs': [{
                'id': pair.id,
                'english': pair.english,
                'indonesian': pair.indonesian,
                'isLearned': pair.is_learned,
                'orderIndex': pair.order_index,
                'studyCount': pair.study_count,
                'lastStudied': pair.last_studied.isoformat() if pair.last_studied else None
            } for pair in updated_pairs]
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
        
@app.route('/api/cards/<int:card_id>', methods=['DELETE'])
@token_required
def delete_card(current_user, card_id):
    try:
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
            
        # Get all existing word pairs for this card, ordered by order_index
        existing_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id).order_by(WordPair.order_index)
        ).scalars().all()
        
        # Create a dictionary to map word pairs by their ID
        pair_map = {pair.id: pair for pair in existing_pairs}
        
        # Update learned status for each word pair
        learned_count = 0
        total_count = len(existing_pairs)
        current_time = datetime.utcnow()
        
        for pair_data in data['wordPairs']:
            pair_id = pair_data.get('id')
            word_pair = pair_map.get(pair_id)
            
            if word_pair:
                old_status = word_pair.is_learned
                new_status = pair_data.get('isLearned', False)
                
                word_pair.is_learned = new_status
                
                # Update study tracking if status changed
                if old_status != new_status:
                    word_pair.study_count += 1
                    word_pair.last_studied = current_time
                
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
            
        # Reset progress for all word pairs but keep order
        word_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id).order_by(WordPair.order_index)
        ).scalars().all()
        
        for pair in word_pairs:
            pair.is_learned = False
            # Optional: Reset study tracking as well
            # pair.study_count = 0
            # pair.last_studied = None
            
        card.progress = 0
        db.session.commit()
        
        # Return complete card data with consistent ordering
        response_data = {
            'id': card.id,
            'title': card.title,
            'progress': 0,
            'targetDays': card.target_days,
            'totalWords': len(word_pairs),
            'learnedWords': 0,
            'wordPairs': [{
                'id': pair.id,
                'english': pair.english,
                'indonesian': pair.indonesian,
                'isLearned': False,
                'orderIndex': pair.order_index,
                'studyCount': pair.study_count,
                'lastStudied': pair.last_studied.isoformat() if pair.last_studied else None
            } for pair in word_pairs]
        }
        
        return jsonify(response_data), 200

    except Exception as e:
        db.session.rollback()
        print(f"Error in reset_progress: {str(e)}")
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
        
        # Fetch all word pairs for this card, ordered by order_index
        word_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id).order_by(WordPair.order_index)
        ).scalars().all()
        
        learned_count = len([pair for pair in word_pairs if pair.is_learned])
            
        response_data = {
            'id': card.id,
            'title': card.title,
            'progress': card.progress,
            'targetDays': card.target_days,
            'totalWords': len(word_pairs),
            'learnedWords': learned_count,
            'wordPairs': [{
                'id': pair.id,
                'english': pair.english,
                'indonesian': pair.indonesian,
                'isLearned': pair.is_learned,
                'orderIndex': pair.order_index,
                'studyCount': pair.study_count,
                'lastStudied': pair.last_studied.isoformat() if pair.last_studied else None
            } for pair in word_pairs]
        }
        
        return jsonify(response_data), 200
    except Exception as e:
        print(f"Error in get_card_detail: {str(e)}")
        return jsonify({'error': str(e)}), 500

# New endpoint to mark individual word as learned/unlearned
@app.route('/api/cards/<int:card_id>/words/<int:word_id>/toggle', methods=['PUT'])
@token_required
def toggle_word_learned(current_user, card_id, word_id):
    try:
        # Verify card belongs to user
        card_result = db.session.execute(
            db.select(LearningCard).filter_by(id=card_id, user_id=current_user.id)
        ).first()
        
        if not card_result:
            return jsonify({'error': 'Card not found'}), 404
            
        card = card_result[0]
        
        # Get the specific word pair
        word_result = db.session.execute(
            db.select(WordPair).filter_by(id=word_id, card_id=card_id)
        ).first()
        
        if not word_result:
            return jsonify({'error': 'Word pair not found'}), 404
            
        word_pair = word_result[0]
        
        # Toggle learned status
        word_pair.is_learned = not word_pair.is_learned
        word_pair.study_count += 1
        word_pair.last_studied = datetime.utcnow()
        
        # Recalculate card progress
        all_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id)
        ).scalars().all()
        
        learned_count = len([pair for pair in all_pairs if pair.is_learned])
        total_count = len(all_pairs)
        
        if total_count > 0:
            card.progress = min(round((learned_count / total_count) * 100), 100)
        
        db.session.commit()
        
        return jsonify({
            'wordId': word_pair.id,
            'isLearned': word_pair.is_learned,
            'studyCount': word_pair.study_count,
            'lastStudied': word_pair.last_studied.isoformat(),
            'cardProgress': card.progress,
            'learnedCount': learned_count,
            'totalCount': total_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
    
# Add this endpoint to your Flask backend after the existing toggle endpoint

@app.route('/api/cards/<int:card_id>/words/<int:word_id>/learned', methods=['PUT'])
@token_required
def set_word_learned_status(current_user, card_id, word_id):
    try:
        # Verify card belongs to user
        card_result = db.session.execute(
            db.select(LearningCard).filter_by(id=card_id, user_id=current_user.id)
        ).first()
        
        if not card_result:
            return jsonify({'error': 'Card not found'}), 404
            
        card = card_result[0]
        
        # Get the specific word pair
        word_result = db.session.execute(
            db.select(WordPair).filter_by(id=word_id, card_id=card_id)
        ).first()
        
        if not word_result:
            return jsonify({'error': 'Word pair not found'}), 404
            
        word_pair = word_result[0]
        
        # Get the desired learned status from request body
        data = request.json
        if 'isLearned' not in data:
            return jsonify({'error': 'isLearned field is required'}), 400
            
        new_learned_status = bool(data['isLearned'])
        
        # Only update if status actually changed
        if word_pair.is_learned != new_learned_status:
            word_pair.is_learned = new_learned_status
            word_pair.study_count += 1
            word_pair.last_studied = datetime.utcnow()
        
        # Recalculate card progress
        all_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id)
        ).scalars().all()
        
        learned_count = len([pair for pair in all_pairs if pair.is_learned])
        total_count = len(all_pairs)
        
        if total_count > 0:
            card.progress = min(round((learned_count / total_count) * 100), 100)
        
        db.session.commit()
        
        return jsonify({
            'wordId': word_pair.id,
            'isLearned': word_pair.is_learned,
            'studyCount': word_pair.study_count,
            'lastStudied': word_pair.last_studied.isoformat(),
            'cardProgress': card.progress,
            'learnedCount': learned_count,
            'totalCount': total_count
        }), 200
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

# Get learning statistics for a card
@app.route('/api/cards/<int:card_id>/stats', methods=['GET'])
@token_required
def get_card_stats(current_user, card_id):
    try:
        # Verify card belongs to user
        card_result = db.session.execute(
            db.select(LearningCard).filter_by(id=card_id, user_id=current_user.id)
        ).first()
        
        if not card_result:
            return jsonify({'error': 'Card not found'}), 404
            
        card = card_result[0]
        
        # Get all word pairs
        word_pairs = db.session.execute(
            db.select(WordPair).filter_by(card_id=card_id).order_by(WordPair.order_index)
        ).scalars().all()
        
        learned_words = [pair for pair in word_pairs if pair.is_learned]
        unlearned_words = [pair for pair in word_pairs if not pair.is_learned]
        
        # Calculate statistics
        total_study_sessions = sum(pair.study_count for pair in word_pairs)
        most_studied = max(word_pairs, key=lambda x: x.study_count) if word_pairs else None
        least_studied = min(word_pairs, key=lambda x: x.study_count) if word_pairs else None
        
        # Recent study activity (last 7 days)
        week_ago = datetime.utcnow() - timedelta(days=7)
        recently_studied = [
            pair for pair in word_pairs 
            if pair.last_studied and pair.last_studied > week_ago
        ]
        
        stats = {
            'cardId': card.id,
            'title': card.title,
            'totalWords': len(word_pairs),
            'learnedWords': len(learned_words),
            'unlearnedWords': len(unlearned_words),
            'progressPercentage': card.progress,
            'totalStudySessions': total_study_sessions,
            'recentlyStudiedCount': len(recently_studied),
            'mostStudiedWord': {
                'english': most_studied.english,
                'indonesian': most_studied.indonesian,
                'studyCount': most_studied.study_count
            } if most_studied and most_studied.study_count > 0 else None,
            'leastStudiedWord': {
                'english': least_studied.english,
                'indonesian': least_studied.indonesian,
                'studyCount': least_studied.study_count
            } if least_studied else None,
            'averageStudyCount': round(total_study_sessions / len(word_pairs), 2) if word_pairs else 0
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run()
