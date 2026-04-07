from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class TrafficLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    packet_size = db.Column(db.Float)
    connection_duration = db.Column(db.Float)
    src_bytes = db.Column(db.Float)
    protocol_type = db.Column(db.String(20))
    classification = db.Column(db.String(50))
    confidence = db.Column(db.Float)

class AnomalyDetection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    traffic_volume = db.Column(db.Float)
    packet_rate = db.Column(db.Float)
    connection_frequency = db.Column(db.Float)
    packets_sent = db.Column(db.Float)
    anomaly_status = db.Column(db.Integer)
    anomaly_score = db.Column(db.Float)
