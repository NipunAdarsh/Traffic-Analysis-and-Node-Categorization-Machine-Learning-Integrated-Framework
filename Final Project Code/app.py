from flask import Flask, render_template, request, jsonify
from routes.main import main, init_model_manager, init_limiter
from models.model_manager import ModelManager
from models.database import db, User
from flask_socketio import SocketIO
import logging
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

socketio = SocketIO()

def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get('SECRET_KEY', 'default-secret-key')
    
    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///traffic.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    # Model paths (used by background loader if .pkl files exist)
    app.config['TRAFFIC_MODEL_PATH'] = 'traffic_analysis_model.pkl'
    app.config['NODE_MODEL_PATH'] = 'node_cat_model.pkl'
    app.config['ANOMALY_MODEL_PATH'] = 'anomaly_detection_model.pkl'
    
    # Initialize database
    db.init_app(app)
    
    with app.app_context():
        db.create_all()
        
        # Seed default users if none exist
        if not User.query.first():
            default_users = {
                'admin': {'password': 'admin123', 'role': 'admin'},
                'Chirag': {'password': 'Chirag123', 'role': 'admin'},
                'Nipun': {'password': 'Nipun123', 'role': 'admin'},
                'Sethu': {'password': 'Sethu123', 'role': 'admin'}
            }
            for username, data in default_users.items():
                user = User(username=username, role=data['role'])
                user.set_password(data['password'])
                db.session.add(user)
            db.session.commit()
            logger.info("Default users seeded to database.")

    
    # Configure app
    app.config.update(
        RATELIMIT_DEFAULT="50 per minute",
        PROTOCOL_MAPPING={
            "tcp": 1,
            "udp": 2,
            "icmp": 3,
            "mqtt": 4,
            "": 0
        },
        DEVICE_MAPPING={
            "router": 1,
            "switch": 2,
            "server": 3,
            "workstation": 4,
            "iot": 5,
            "": 0
        }
    )
    
    # Initialize SocketIO with threading mode (compatible with debug/reloader)
    # NOTE: eventlet async_mode was removed because monkey_patch() at module level
    # breaks werkzeug's reloader in debug mode, causing the server to hang.
    # Threading mode works perfectly for the REST-polling dashboard architecture.
    socketio.init_app(app, cors_allowed_origins="*", async_mode='threading')
    
    # Create and register model manager
    app.model_manager = ModelManager()
    
    # Start background model loading (non-blocking, fails gracefully if no .pkl files)
    app.model_manager.load_models_async(app)
    logger.info("Model Manager initialized (background loading started)")
    
    # NOTE: Real-time dashboard uses /api/simulate_packet REST polling
    # instead of background WebSocket threads.
    
    # Register blueprints
    app.register_blueprint(main)
    
    # Initialize rate limiter
    init_limiter(app)
    
    return app

if __name__ == '__main__':
    app = create_app()
    socketio.run(app, debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))

