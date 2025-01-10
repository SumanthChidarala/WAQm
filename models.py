from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import UserMixin

# Initialize SQLAlchemy
db = SQLAlchemy()

# Users Table
class User(db.Model, UserMixin):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    logged_in = db.Column(db.Boolean, default=False)
    city = db.Column(db.String(100), nullable=True)
    carbonemitted = db.Column(db.Float, default=0.0)
    username = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    carbon_tracking = db.relationship('UserCarbonTracking', backref='user', lazy=True)
    posts = db.relationship('Post', backref='author', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    notifications = db.relationship('Notification', backref='user', lazy=True)
    leaderboard = db.relationship('Leaderboard', backref='user', lazy=True)
    comment_likes = db.relationship('CommentLike', backref='user', lazy=True)

    def is_admin(self):
        return self.role == 'admin'

# User Carbon Tracking Table
class UserCarbonTracking(db.Model):
    __tablename__ = 'user_carbon_tracking'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    today_date = db.Column(db.Date, nullable=False)
    transportation = db.Column(db.Float, default=0.0)
    water = db.Column(db.Float, default=0.0)
    electricity = db.Column(db.Float, default=0.0)
    totalCarbonFootprint = db.Column(db.Float, default=0.0)

# Leaderboard Table
class Leaderboard(db.Model):
    __tablename__ = 'LeaderBoard'
    
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), primary_key=True, nullable=False)
    today_date = db.Column(db.Date, primary_key=True, nullable=False)
    totalCarbonFootprint = db.Column(db.Float, default=0.0)
    city = db.Column(db.String(100), nullable=True)
    username = db.Column(db.String(50), nullable=True)

# Posts Table
class Post(db.Model):
    __tablename__ = 'posts'
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_approved = db.Column(db.Boolean, default=False)
    
    # Relationships
    comments = db.relationship('Comment', backref='post', lazy=True, cascade='all, delete-orphan')
    likes = db.relationship('PostLike', backref='post', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    __tablename__ = 'comments'
    
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    is_approved = db.Column(db.Boolean, default=True)
    
    # Remove duplicate relationships and use the ones from User and Post
    likes = db.relationship('CommentLike', backref='comment', lazy=True, cascade='all, delete-orphan')

class CommentLike(db.Model):
    __tablename__ = 'comment_likes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class PostLike(db.Model):
    __tablename__ = 'post_likes'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    type = db.Column(db.String(50), nullable=False, default='system')  
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    related_post_id = db.Column(db.Integer, db.ForeignKey('posts.id'), nullable=True)
