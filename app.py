from flask import Flask, render_template, redirect, url_for, request, jsonify, flash, g
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, set_access_cookies
from flask_bcrypt import Bcrypt
from flask_dance.contrib.google import make_google_blueprint, google
from models import db, User, Post, UserCarbonTracking, Leaderboard, Comment, PostLike, Notification, CommentLike
from config import Config
import requests
from datetime import datetime, timedelta
from flask_admin import Admin, AdminIndexView, expose
from flask_admin.contrib.sqla import ModelView
from flask_mail import Mail, Message
from flask_login import LoginManager, current_user, login_user, logout_user, login_required
from functools import wraps
from sqlalchemy import or_
import click
from flask_moment import Moment
from flask_cli import with_appcontext

app = Flask(__name__)
app.config.from_object(Config)
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
moment = Moment(app)
app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token_cookie"

API_KEY = "5f6c9d7e7f16f04d6b55942614817b69"
YOUTUBE_API_KEY = 'AIzaSyAmXWhLn-6rBUjQzgpxo79onTS11iOZMDM'

# Initialize Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sreelekhaoff@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'ztgj hwes qmes juxf'     # Replace with your app password
mail = Mail(app)

def get_weather_videos(city):
    youtube_url = f"https://www.googleapis.com/youtube/v3/search?part=snippet&q={city}+weather&key={YOUTUBE_API_KEY}&maxResults=3&type=video"
    response = requests.get(youtube_url)
    video_data = response.json()

    videos = []
    if "items" in video_data:
        for item in video_data["items"]:
            video = {
                "title": item["snippet"]["title"],
                "video_id": item["id"]["videoId"],
                "thumbnail": item["snippet"]["thumbnails"]["high"]["url"],
                "description": item["snippet"]["description"]
            }
            videos.append(video)
    
    return videos

# Function to fetch weather data from OpenWeatherMap API
def get_weather(city):
    weather_url = "https://api.openweathermap.org/data/2.5/weather"
    params = {
        "q": city,
        "appid": API_KEY,
        "units": "metric"
    }
    response = requests.get(weather_url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print("Error fetching weather data:", response.json())  # Debugging output
        return {"error": response.json().get("message", f"HTTP {response.status_code} error")}
    


def get_aqi(lat, lon):
    """Fetch AQI data from OpenWeatherMap API."""
    aqi_url = "https://api.openweathermap.org/data/2.5/air_pollution"
    params = {
        "lat": lat,
        "lon": lon,
        "appid": API_KEY
    }
    response = requests.get(aqi_url, params=params)
    if response.status_code == 200:
        return response.json()
    else:
        print("Error fetching AQI data:", response.json())  # Debugging output
        return None

def get_aqi_description(aqi_level):
    """Map AQI level to a description."""
    if aqi_level == 1:
        return "Good", "green"
    elif aqi_level == 2:
        return "Satisfactory", "lightgreen"
    elif aqi_level == 3:
        return "Moderate", "yellow"
    elif aqi_level == 4:
        return "Poor", "orange"
    elif aqi_level == 5:
        return "Very Poor", "red"
    elif aqi_level == 6:
        return "Severe", "darkred"
    else:
        return "Unknown", "gray"
    
db.init_app(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Admin Views
class SecureModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated and current_user.role == 'admin'

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('login'))

class CustomAdminIndexView(AdminIndexView):
    @expose('/')
    def index(self):
        if not (current_user.is_authenticated and current_user.role == 'admin'):
            return redirect(url_for('login'))
        return super(CustomAdminIndexView, self).index()

admin = Admin(app, index_view=CustomAdminIndexView())
admin.add_view(SecureModelView(User, db.session))
admin.add_view(SecureModelView(Post, db.session))
admin.add_view(SecureModelView(Comment, db.session))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You need to be an admin to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def send_notification_email(user_email, subject, body):
    try:
        msg = Message(subject,
                     sender=app.config['MAIL_USERNAME'],
                     recipients=[user_email])
        msg.body = body
        mail.send(msg)
    except Exception as e:
        print(f"Error sending email: {e}")

@app.before_request
def before_request():
    access_token = request.cookies.get('access_token_cookie')
    if access_token:
        g.headers = {'Authorization': f'Bearer {access_token}'}
    else:
        g.headers = {}

# Function to retrieve headers in routes
def get_headers():
    return getattr(g, 'headers', {})

# Google OAuth Setup
google_bp = make_google_blueprint(
    client_id=app.config['GOOGLE_OAUTH_CLIENT_ID'],
    client_secret=app.config['GOOGLE_OAUTH_CLIENT_SECRET'],
    redirect_to='google_login',
    scope=["profile", "email"]
)
app.register_blueprint(google_bp, url_prefix='/google')

# Home Route
@app.route('/', methods=["GET", "POST"])
def home():
    # Check if a city is passed in the form, otherwise set a default city
    city = None
    if request.method == 'POST':
        city = request.form['city']
    else:
        city = "New York"  # Set a default city if no city is provided

    # Get weather data for the city
    weather_data = get_weather(city)
    
    if "error" in weather_data:
        return render_template('weather_dashboard.html', weather_info={})

    # Extract latitude and longitude from weather data
    lat = weather_data["coord"]["lat"]
    lon = weather_data["coord"]["lon"]
    
    # Fetch AQI data
    aqi_data = get_aqi(lat, lon)
    if aqi_data and "list" in aqi_data:
        aqi_level = aqi_data["list"][0]["main"]["aqi"]
        aqi_description, aqi_color = get_aqi_description(aqi_level)
    else:
        aqi_level = None
        aqi_description, aqi_color = "Unavailable", "gray"
        
    # Extract all weather details
    weather_info = {
        "temperature": weather_data["main"]["temp"],
        "humidity": weather_data["main"]["humidity"],
        "wind_speed": weather_data["wind"]["speed"],
        "feels_like": weather_data["main"]["feels_like"],
        "visibility": weather_data.get("visibility", 0) / 1000 if "visibility" in weather_data else "N/A",
        "pressure": weather_data["main"]["pressure"],
        "sunrise": datetime.utcfromtimestamp(weather_data["sys"]["sunrise"]).strftime('%I:%M:%S %p'),
        "sunset": datetime.utcfromtimestamp(weather_data["sys"]["sunset"]).strftime('%I:%M:%S %p'),
        "aqi_level": aqi_level,  # AQI value fetched from the Air Pollution API
        "aqi_description": aqi_description,  # AQI category description
        "aqi_color": aqi_color
    }

    NEWS_API_KEY = "pub_605655cd986cb585931ba91afa9ded253026a"
    url = f"https://newsdata.io/api/1/news?apikey={NEWS_API_KEY}&country=in&language=en&q={city}"
    response = requests.get(url)
    news_data = response.json()
    articles = news_data.get("results", [])
    weather_articles = [
        article for article in articles
        if (
            (article.get('title') and 'weather' in article['title'].lower()) or
            (article.get('description') and 'weather' in article['description'].lower())
        )
    ]   
    weather_articles = weather_articles[:3]
    
    weather_videos = get_weather_videos(city)

    return render_template('weather_dashboard.html', weather_info=weather_info, city=city, articles=weather_articles, videos=weather_videos)

# User Registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Extract form data
        name = request.form['name']  # Store full name in the 'name' field
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        city = request.form['city']

        # Check if passwords match
        if password != confirm_password:
            return jsonify(message="Passwords do not match"), 400

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        # Store the name in the 'username' column of the 'users' table
        new_user = User(username=name, email=email, password=hashed_password, city=city)
        
        # Add the new user to the session and commit
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    
    return render_template('register.html')

# Community route with optional authentication
@app.route('/community')
@jwt_required(optional=True)
def community():
    current_user_id = get_jwt_identity()
    if not current_user_id:
        return redirect(url_for('login'))
        
    user = User.query.get(current_user_id)
    
    # Get all posts based on user role and ownership
    if user.role == 'admin':
        # Admin sees all posts
        posts = Post.query.order_by(Post.created_at.desc()).all()
    else:
        # Regular users see their own posts and approved posts from others
        posts = Post.query.filter(
            or_(
                Post.user_id == current_user_id,  # User's own posts
                Post.is_approved == True  # Approved posts
            )
        ).order_by(Post.created_at.desc()).all()
    
    user_likes = [like.post_id for like in PostLike.query.filter_by(user_id=current_user_id).all()]
    user_comment_likes = [like.comment_id for like in CommentLike.query.filter_by(user_id=current_user_id).all()]
    
    # Convert all timestamps to IST
    for post in posts:
        post.created_at = post.created_at + timedelta(hours=5, minutes=30)
        for comment in post.comments:
            comment.created_at = comment.created_at + timedelta(hours=5, minutes=30)

    return render_template('community.html', 
                         posts=posts, 
                         user=user, 
                         user_likes=user_likes,
                         user_comment_likes=user_comment_likes)

@app.route('/create_post', methods=['POST'])
@jwt_required()
def create_post():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        current_user = User.query.get(current_user_id)
        # Validate input
        if not data.get('title') or not data.get('description'):
            return jsonify({'error': 'Title and description are required'}), 400
        
        new_post = Post(
            title=data['title'],
            description=data['description'],
            user_id=current_user_id,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            is_approved=False  # Posts start as unapproved
        )
        
        db.session.add(new_post)
        db.session.commit()
        
        # Create notification for admins about new post
        admins = User.query.filter_by(role='admin').all()
        for admin in admins:
            notification = Notification(
                user_id=admin.id,
                message=f"New post created: {data['title']}",
                type='new_post',
                created_at=datetime.utcnow(),
                related_post_id=new_post.id
            )
            db.session.add(notification)
        db.session.commit()
        user_email = 'weather.aqm@gmail.com'
        subject = 'Someone Created a post'
        body = (
            f"Dear Admin,\n\n"
            f"A new post titled '{new_post.title}' has been created by {current_user.username}.\n\n"
            f"Please review the post to ensure it aligns with our community guidelines and standards. Based on your review, you can either approve the post for publication or delete it if it violates our policies.\n\n"
            f"Thank you for your time and attention to this matter.\n\n"
            f"Best regards,\n"
            f"[Your Team Name]"
        )

        send_notification_email(user_email, subject, body)


        return jsonify({
            'message': 'Post created successfully',
            'post': {
                'id': new_post.id,
                'title': new_post.title,
                'description': new_post.description
            }
        }), 201
    except Exception as e:
        print(f"Error creating post: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/post/<int:post_id>/comment', methods=['POST'])
@jwt_required()
def add_comment(post_id):
    try:
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        if not current_user:
            return jsonify({'error': 'User not found'}), 401

        if not request.is_json:
            return jsonify({'error': 'Invalid request format'}), 400

        data = request.get_json()
        content = data.get('content')
        
        if not content or not content.strip():
            return jsonify({'error': 'Comment content is required'}), 400

        post = Post.query.get_or_404(post_id)
        
        # Create new comment
        new_comment = Comment(
            content=content,
            user_id=current_user_id,
            post_id=post_id,
            created_at=datetime.utcnow()
        )
        db.session.add(new_comment)
        
        # Create notification for post author
        if post.user_id != current_user_id:  # Don't notify if user comments on their own post
            notification = Notification(
                user_id=post.user_id,
                message=f"{current_user.username} commented on your post: '{post.title}'",
                type='comment',
                created_at=datetime.utcnow(),
                related_post_id=post_id
            )
            db.session.add(notification)
        
        db.session.commit()
        u_name = post.author.username
        user_email = post.author.email
        subject = 'Someone commented on your post'
        body = (
                f"Dear {u_name},\n\n"
                f"{current_user.username} has commented on your post, '{post.title}'! 🎉\n\n"
                f"This is a great indication that your content is sparking meaningful conversations within the community. Keep sharing your thoughts and ideas to inspire even more engagement!\n\n"
                f"Thank you for being an integral part of our community. Should you have any questions or need assistance, feel free to reach out.\n\n"
                f"Warm regards,\n"
                f"[Your Team Name]"
            )
        send_notification_email(user_email, subject, body)
        # Convert UTC to IST for display
        ist_time = new_comment.created_at + timedelta(hours=5, minutes=30)
        
        return jsonify({
            'message': 'Comment added successfully',
            'comment': {
                'id': new_comment.id,
                'content': new_comment.content,
                'author': current_user.username,
                'created_at': ist_time.strftime('%Y-%m-%dT%H:%M:%S')
            }
        }), 201
        
    except Exception as e:
        print(f"Error in add_comment: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/post/<int:post_id>/like', methods=['POST'])
@jwt_required()
def like_post(post_id):
    try:
        current_user_id = get_jwt_identity()
        c_user = User.query.get(current_user_id)
        if not c_user:
            return jsonify({'error': 'User not found'}), 404
        # Check if user already liked the post
        existing_like = PostLike.query.filter_by(
            user_id=current_user_id,
            post_id=post_id
        ).first()
        
        post = Post.query.get_or_404(post_id)
        
        if existing_like:
            # Unlike the post
            db.session.delete(existing_like)
            message = "Post unliked"
            liked = False
        else:
            # Like the post
            new_like = PostLike(
                user_id=current_user_id,
                post_id=post_id,
                created_at=datetime.utcnow()
            )
            db.session.add(new_like)
            
            # Create notification for post author
            if post.user_id != current_user_id:  # Don't notify if user likes their own post
                notification = Notification(
                    user_id=post.user_id,
                    message=f"'{c_user.username}' liked your post: '{post.title}'",
                    type='post_like',
                    created_at=datetime.utcnow(),
                    related_post_id=post_id
                )
                db.session.add(notification)
            
                      
            message = "Post liked"
            liked = True
            u_name = post.author.username
            user_email = post.author.email
            subject = 'Post Liked'
            body = (
                f"Dear {u_name},\n\n"
                f"We’re excited to share that {c_user.username} has liked your post, '{post.title}'! 🎉\n\n"
                f"This shows how your contributions are resonating with the community and sparking engagement. Keep up the great work by sharing more inspiring content!\n\n"
                f"Thank you for being an integral part of our community. Should you have any questions or need assistance, feel free to reach out.\n\n"
                f"Warm regards,\n"
                f"[Your Team Name]"
            )
            send_notification_email(user_email, subject, body)
        db.session.commit()
        
        # Get updated like count
        like_count = PostLike.query.filter_by(post_id=post_id).count()
        
        return jsonify({
            'message': message,
            'liked': liked,
            'likeCount': like_count
        }), 200
        
    except Exception as e:
        print(f"Error in like_post: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/approve_post/<int:post_id>', methods=['POST'])
@jwt_required()
def approve_post(post_id):
    try:
        current_user_id = get_jwt_identity()
        admin_user = User.query.get(current_user_id)
        
        # Check if user is admin
        if not admin_user or admin_user.role != 'admin':
            return jsonify({'error': 'Unauthorized - Admin access required'}), 403
        
        post = Post.query.get(post_id)
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        
        post.is_approved = True
        db.session.commit()
        
        # Notify post author
        notification = Notification(
            user_id=post.user_id,
            message=f"Your post '{post.title}' has been approved!",
            type='post_approved',  # Added notification type
            created_at=datetime.utcnow(),
            related_post_id=post_id
        )
        
        u_name = post.author.username
        user_email = post.author.email
        subject = 'Post Approved'
        body = (
                f"Dear {u_name},\n\n"
                f"We’re thrilled to inform you that your post, '{post.title}', has been reviewed and successfully approved! 🎉\n\n"
                f"Your contribution plays a vital role in enriching our community, sparking meaningful discussions, and inspiring others. "
                f"Feel free to share your post with your network to maximize its impact.\n\n"
                f"Thank you for your valuable input, and we look forward to more of your exceptional contributions. "
                f"Should you have any questions or need assistance, don’t hesitate to reach out.\n\n"
                f"Warm regards,\n"
                f"[Your Team Name]"
            )
        
        send_notification_email(user_email, subject, body)
        db.session.add(notification)
        db.session.commit()
        
        return jsonify({'message': 'Post approved successfully'}), 200
    except Exception as e:
        print(f"Error in approve_post: {str(e)}")  # Add debugging
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/admin/delete_post/<int:post_id>', methods=['POST'])
@jwt_required()
def delete_post(post_id):
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        # Check if user is admin
        if user.role != 'admin':
            return jsonify({'error': 'Unauthorized'}), 403
            
        # Explicitly load the post with its author in the same session
        post = Post.query.options(db.joinedload(Post.author)).get(post_id)
        
        if not post:
            return jsonify({'error': 'Post not found'}), 404
        
        # Delete all likes for the post
        PostLike.query.filter_by(post_id=post_id).delete()
        
        # Delete all comments for the post
        Comment.query.filter_by(post_id=post_id).delete()
        
        # Delete all notifications related to this post
        Notification.query.filter_by(related_post_id=post_id).delete()
        
        # Store author information before deleting the post
        u_name = post.author.username
        user_email = post.author.email
        post_title = post.title
        
        # Delete the post
        db.session.delete(post)
        db.session.commit()
        
        # Notify post author
        notification = Notification(
            user_id=post.author.id,  # Use author's ID directly
            message=f"Your post '{post_title}' has been deleted!",
            type='post_deleted',  # Corrected notification type
            created_at=datetime.utcnow(),
            related_post_id=None
        )

        db.session.add(notification)
        db.session.commit()
        
        subject = 'Post Deleted'
        body = (
        f"Dear {u_name},\n\n"
        f"We regret to inform you that your post, '{post_title}', has been removed following a review by our moderation team. We strive to maintain a community that fosters meaningful and respectful discussions, and unfortunately, your post did not align with our community guidelines.\n\n"
        f"We understand that this may be disappointing, and we sincerely apologize for any inconvenience this decision may have caused. If you believe this action was taken in error or would like further clarification, please feel free to reach out to us.\n\n"
        f"We greatly value your contributions and encourage you to continue sharing content that inspires and enriches our community. Thank you for your understanding and cooperation.\n\n"
        f"Warm regards,\n"
        f"[Your Team Name]"
        )

        send_notification_email(user_email, subject, body)
        
        
        return jsonify({'message': 'Post deleted successfully'}), 200
        
    except Exception as e:
        print(f"Error deleting post: {str(e)}")
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/create_admin', methods=['POST'])
def create_admin():
    try:
        # Check if admin already exists
        existing_admin = User.query.filter_by(role='admin').first()
        if existing_admin:
            return jsonify({'message': 'Admin user already exists'}), 400
        
        # Create admin user
        admin_password = bcrypt.generate_password_hash('admin123').decode('utf-8')
        admin_user = User(
            username='admin',
            email='admin@example.com',
            password=admin_password,
            role='admin',
            city='Admin City'
        )
        
        db.session.add(admin_user)
        db.session.commit()
        
        return jsonify({'message': 'Admin user created successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/notifications')
@jwt_required()
def get_notifications():
    current_user_id = get_jwt_identity()
    notifications = Notification.query.filter_by(
        user_id=current_user_id,
        read=False
    ).order_by(Notification.created_at.desc()).all()
    
    return jsonify([{
        'id': n.id,
        'message': n.message,
        'type': n.type,
        'created_at': n.created_at.isoformat(),
        'related_post_id': n.related_post_id
    } for n in notifications])

@app.route('/notifications/mark_read/<int:notification_id>', methods=['POST'])
@jwt_required()
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    notification.read = True
    db.session.commit()
    return jsonify({'message': 'Notification marked as read'})

# User Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Authenticate user
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=str(user.id))
            response = redirect(url_for('home'))
            set_access_cookies(response, access_token)
            return response

        return render_template('login.html')

    return render_template('login.html')

@app.route('/ctlogin', methods=['GET', 'POST'])
def ctlogin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Authenticate user
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=str(user.id))
            response = redirect(url_for('carbon_tracking'))
            set_access_cookies(response, access_token)
            return response

        return render_template('ctlogin.html')

    return render_template('ctlogin.html')

@app.route('/clogin', methods=['GET', 'POST'])
def clogin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        # Authenticate user
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            access_token = create_access_token(identity=str(user.id))
            response = redirect(url_for('community'))
            set_access_cookies(response, access_token)
            return response
        return render_template('clogin.html')

    return render_template('clogin.html')

# Google Login Callback
@app.route('/google/authorized')
def google_login():
    if not google.authorized:
        return redirect(url_for('google.login'))

    # Fetch user info from Google
    google_info = google.get('/plus/v1/people/me')
    user_info = google_info.json()

    # Handle user authentication or registration here...
    return jsonify(message="Google login successful", user_info=user_info)

@app.route('/track_carbon', methods=['POST'])
@jwt_required()

def track_carbon():
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)  # Fetch user details
    transportation_km = request.form['transportation_km']
    transportation_mode = request.form['transportation_mode']
    electricity_prev_month = request.form['electricity_prev_month']
    electricity_today = request.form['electricity_today']
    dry_waste = request.form['dry_waste']
    wet_waste = request.form['wet_waste']

    # Calculate carbon footprint for transportation
    transport_modes = {
        'car': 0.120,  # kg CO2 per km
        'bus': 0.060,
        'bike': 0.020
    }
    
    carbon_transport = float(transportation_km) * transport_modes.get(transportation_mode.lower(), 0.120)

    # Calculate carbon footprint for electricity usage
    carbon_electricity = (float(electricity_today) + float(electricity_prev_month)) * 0.8  # Example conversion factor

    # Calculate carbon footprint for waste
    carbon_waste = (float(dry_waste) + float(wet_waste)) * 0.1  # Example conversion factor

    # Total carbon footprint
    total_carbon_footprint = carbon_transport + carbon_electricity + carbon_waste

    # Store the data in the UserCarbonTracking model
    today_date = datetime.utcnow().date()
    user_carbon_tracking = UserCarbonTracking(
        user_id=current_user_id,
        today_date=today_date,
        transportation=carbon_transport,
        electricity=carbon_electricity,
        water=0.0,  # Adjust this if needed
        totalCarbonFootprint=total_carbon_footprint
    )

    db.session.add(user_carbon_tracking)

    # Update the Leaderboard model
    leaderboard_entry = Leaderboard.query.filter_by(user_id=current_user_id , today_date=today_date).first()
    if not leaderboard_entry:
        leaderboard_entry = Leaderboard(
            user_id=current_user_id,
            today_date=today_date,
            totalCarbonFootprint=total_carbon_footprint,
            city=user.city,
            username=user.username
        )
        db.session.add(leaderboard_entry)
    else:
        leaderboard_entry.totalCarbonFootprint = total_carbon_footprint

    db.session.commit()

    return redirect(url_for('carbon_tracking'))

# Ensure this route is added in your app initialization
@app.route('/carbon_tracking')
@jwt_required()

def carbon_tracking():
    current_user_id = int(get_jwt_identity())
    user = User.query.get(current_user_id)

    # Retrieve historical data for the user
    carbon_data = UserCarbonTracking.query.filter_by(user_id=current_user_id).all()
    dates = [data.today_date.strftime('%Y-%m-%d') for data in carbon_data]
    transportation = [data.transportation for data in carbon_data]
    electricity = [data.electricity for data in carbon_data]
    water = [data.water for data in carbon_data]

    carbon_data_dict = {
        "dates": dates,
        "transportation": transportation,
        "electricity": electricity,
        "water": water
    }

    # Assuming a utility function exists to calculate totals
    carbon_footprint = calculate_total_carbon_footprint(current_user_id)

    # Retrieve leaderboard data
    leaderboard_data = Leaderboard.query.order_by(Leaderboard.totalCarbonFootprint.asc()).all()

    return render_template('carbon_tracking.html', carbon_data=carbon_data_dict, carbon_footprint=carbon_footprint, leaderboard_data=leaderboard_data)

def calculate_total_carbon_footprint(user_id):
    # Aggregate carbon footprint data for the user
    total_transport = db.session.query(db.func.sum(UserCarbonTracking.transportation)).filter_by(user_id=user_id).scalar() or 0.0
    total_electricity = db.session.query(db.func.sum(UserCarbonTracking.electricity)).filter_by(user_id=user_id).scalar() or 0.0
    total_water = db.session.query(db.func.sum(UserCarbonTracking.water)).filter_by(user_id=user_id).scalar() or 0.0

    total_carbon_footprint = total_transport + total_electricity + total_water
    return {
        "transportation": total_transport,
        "electricity": total_electricity,
        "water": total_water,
        "total": total_carbon_footprint
    }



@app.cli.command('create-admin')
@with_appcontext
def create_admin():
    username = 'admin'
    email = 'admin@example.com'
    password = 'adminpassword'
    
    # Check if the admin user already exists
    existing_admin = User.query.filter_by(email=email).first()
    if existing_admin:
        print('Admin user already exists.')
        return
    
    # Create new admin user
    admin_user = User(username=username, email=email, password=Bcrypt().generate_password_hash(password).decode('utf-8'), role='admin')
    db.session.add(admin_user)
    db.session.commit()
    print('Admin user created successfully!')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables are created
    app.run(debug=True)
