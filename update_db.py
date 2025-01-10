from app import app, db
from models import User, Post, Comment, PostLike, Notification
from sqlalchemy import text

def update_database():
    with app.app_context():
        try:
            # Add new columns to users table
            db.session.execute(text("ALTER TABLE users ADD COLUMN role VARCHAR(20) DEFAULT 'user'"))
            print("Added role column")
        except Exception as e:
            print(f"Role column might already exist: {e}")

        try:
            db.session.execute(text("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE"))
            print("Added is_active column")
        except Exception as e:
            print(f"is_active column might already exist: {e}")

        try:
            db.session.execute(text("ALTER TABLE users ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
            print("Added created_at column")
        except Exception as e:
            print(f"created_at column might already exist: {e}")

        # Update posts table
        try:
            db.session.execute(text("ALTER TABLE Posts MODIFY COLUMN description TEXT"))
            print("Modified description column")
        except Exception as e:
            print(f"Error modifying description column: {e}")

        try:
            db.session.execute(text("ALTER TABLE Posts ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP"))
            print("Added created_at column to Posts")
        except Exception as e:
            print(f"created_at column might already exist in Posts: {e}")

        try:
            db.session.execute(text("ALTER TABLE Posts ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP"))
            print("Added updated_at column to Posts")
        except Exception as e:
            print(f"updated_at column might already exist in Posts: {e}")

        try:
            db.session.execute(text("ALTER TABLE Posts ADD COLUMN is_approved BOOLEAN DEFAULT FALSE"))
            print("Added is_approved column to Posts")
        except Exception as e:
            print(f"is_approved column might already exist in Posts: {e}")

        # Create comments table
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS comments (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INT NOT NULL,
                    post_id INT NOT NULL,
                    is_approved BOOLEAN DEFAULT FALSE,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (post_id) REFERENCES Posts(post_id)
                )
            """))
            print("Created comments table")
        except Exception as e:
            print(f"Comments table might already exist: {e}")

        # Create post_likes table
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS post_likes (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    post_id INT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (post_id) REFERENCES Posts(post_id),
                    UNIQUE KEY unique_like (user_id, post_id)
                )
            """))
            print("Created post_likes table")
        except Exception as e:
            print(f"Post_likes table might already exist: {e}")

        # Create notifications table
        try:
            db.session.execute(text("""
                CREATE TABLE IF NOT EXISTS notifications (
                    id INT PRIMARY KEY AUTO_INCREMENT,
                    user_id INT NOT NULL,
                    message TEXT NOT NULL,
                    type VARCHAR(50) NOT NULL,
                    `read` BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    related_post_id INT,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (related_post_id) REFERENCES Posts(post_id)
                )
            """))
            print("Created notifications table")
        except Exception as e:
            print(f"Notifications table might already exist: {e}")

        db.session.commit()
        print("Database schema update completed!")

if __name__ == "__main__":
    update_database()
