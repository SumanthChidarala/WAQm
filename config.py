from dotenv import load_dotenv
import os

load_dotenv()

class Config:
    SECRET_KEY = 'your_secret_key'
    SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:Mani%402004@localhost/infosys'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    GOOGLE_OAUTH_CLIENT_ID = '541441980761-tmhlqs9pt59a43vicec0lc9o7j09rtsl.apps.googleusercontent.com'
    GOOGLE_OAUTH_CLIENT_SECRET = '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'
    GOOGLE_OAUTH_REDIRECT_URI = 'http://127.0.0.1:5000/google/login'