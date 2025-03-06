from flask import Flask, request, jsonify, Response
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pymongo import MongoClient
from telethon import TelegramClient
from celery import Celery
from datetime import datetime
import bcrypt
import pyotp
import csv
from io import StringIO
import os
from dotenv import load_dotenv

load_dotenv()  # Load environment variables

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

# MongoDB setup
client_mongo = MongoClient(os.getenv('MONGO_URI'))
db = client_mongo["telegram_tool"]
users_collection = db["users"]
contacts_collection = db["contacts"]
messages_collection = db["messages"]
templates_collection = db["templates"]

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data["_id"]
        self.username = user_data["username"]

@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({"_id": user_id})
    if user_data:
        return User(user_data)
    return None

# Rate limiting
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])

# Celery setup
celery = Celery(app.name, broker=os.getenv('REDIS_URL'))
celery.conf.update(app.config)

# Telegram API setup
api_id = os.getenv('TELEGRAM_API_ID')
api_hash = os.getenv('TELEGRAM_API_HASH')
client_telegram = TelegramClient('session_name', api_id, api_hash)

# Register user
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if users_collection.find_one({"username": username}):
        return jsonify({"status": "error", "message": "User already exists"})

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    user_id = users_collection.insert_one({"username": username, "password": hashed_password}).inserted_id
    return jsonify({"status": "success", "message": "User registered", "user_id": str(user_id)})

# Login user
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    user_data = users_collection.find_one({"username": username})
    if user_data and bcrypt.checkpw(password.encode('utf-8'), user_data["password"]):
        user = User(user_data)
        login_user(user)
        return jsonify({"status": "success", "message": "Logged in"})
    return jsonify({"status": "error", "message": "Invalid credentials"})

# Upload contacts
@app.route('/upload-contacts', methods=['POST'])
@login_required
def upload_contacts():
    file = request.files['file']
    contacts = file.read().decode('utf-8').splitlines()
    contacts_data = [{"phone_number": num, "user_id": current_user.id} for num in contacts]
    contacts_collection.insert_many(contacts_data)
    return jsonify({"status": "success", "message": "Contacts uploaded"})

# Send message
@celery.task
def send_telegram_message(phone_numbers, message):
    async def send():
        await client_telegram.start()
        for number in phone_numbers:
            await client_telegram.send_message(number, message)
        await client_telegram.disconnect()
    client_telegram.loop.run_until_complete(send())

@app.route('/send-message', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def send_message():
    data = request.json
    message = data.get('message')
    schedule_time = data.get('schedule_time')

    contacts = list(contacts_collection.find({"user_id": current_user.id}, {"_id": 0, "phone_number": 1}))
    phone_numbers = [contact["phone_number"] for contact in contacts]

    if schedule_time:
        # Schedule message
        send_telegram_message.apply_async(args=[phone_numbers, message], eta=datetime.fromisoformat(schedule_time))
        return jsonify({"status": "success", "message": "Message scheduled"})
    else:
        # Send immediately
        send_telegram_message.delay(phone_numbers, message)
        return jsonify({"status": "success", "message": "Message sent"})

# Analytics
@app.route('/analytics', methods=['GET'])
@login_required
def analytics():
    sent_messages = messages_collection.find({"user_id": current_user.id})
    return jsonify({"status": "success", "data": list(sent_messages)})

# Export analytics
@app.route('/export-analytics', methods=['GET'])
@login_required
def export_analytics():
    sent_messages = list(messages_collection.find({"user_id": current_user.id}, {"_id": 0, "phone_number": 1, "message": 1, "timestamp": 1}))

    csv_data = StringIO()
    writer = csv.DictWriter(csv_data, fieldnames=["phone_number", "message", "timestamp"])
    writer.writeheader()
    writer.writerows(sent_messages)

    return Response(
        csv_data.getvalue(),
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=analytics.csv"}
    )

# Enable 2FA
@app.route('/enable-2fa', methods=['POST'])
@login_required
def enable_2fa():
    secret = pyotp.random_base32()
    users_collection.update_one({"_id": current_user.id}, {"$set": {"2fa_secret": secret}})
    return jsonify({"status": "success", "secret": secret})

# Verify 2FA
@app.route('/verify-2fa', methods=['POST'])
@login_required
def verify_2fa():
    data = request.json
    token = data.get('token')
    user_data = users_collection.find_one({"_id": current_user.id})
    totp = pyotp.TOTP(user_data["2fa_secret"])
    if totp.verify(token):
        return jsonify({"status": "success", "message": "2FA verified"})
    return jsonify({"status": "error", "message": "Invalid token"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
