import sys
import os
import logging
from flask import Flask
from flask_cors import CORS
from q_commsec_api.logging_config import setup_logging
from q_commsec_api.session_store import SessionStore
from q_commsec_api.key_manager import KeyManager
from q_commsec_api.secure_cipher import SecureCipher
from q_commsec_api.routes.commsec_routes import create_commsec_blueprint
from q_commsec_api.routes.ui_routes import create_ui_blueprint

# Add the root directory to the PYTHONPATH for proper module resolution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# Initialize global instances (singleton pattern) for core components
session_store_instance = None
key_manager_instance = None
secure_cipher_instance = None

def create_app(test_config=None):
    """
    Creates and configures the Flask application instance.

    Args:
        test_config (dict, optional): A dictionary of configuration values to override default settings.

    Returns:
        Flask: The configured Flask application object.
    """
    app = Flask(__name__, template_folder='templates')

    # Set up default configuration for the app
    configure_app(app, test_config)

    # Set up logging
    setup_logging(log_file_path=app.config['LOG_FILE_PATH'], level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("Flask app initialization started.")

    # Initialize core components (SessionStore, KeyManager, SecureCipher)
    initialize_core_components(app, logger)

    # Enable CORS for all origins (development only; restrict in production)
    CORS(app)

    # Register blueprints with the app
    register_blueprints(app)

    # Health check route
    app.route('/health')(lambda: "API is healthy", 200)

    logger.info("Flask app initialization completed.")
    return app

def configure_app(app, test_config=None):
    """Configure the Flask app with default settings and optional test config."""
    app.config.from_mapping(
        SECRET_KEY=os.getenv('SECRET_KEY', 'a_very_secret_key_default'),
        SESSION_DB_FILE=os.path.join(app.root_path, 'data', 'sessions.db'),
        LOG_FILE_PATH=os.path.join(app.root_path, 'logs', 'api.log')
    )
    
    if test_config:
        app.config.from_mapping(test_config)

def initialize_core_components(app, logger):
    """Initialize SessionStore, KeyManager, and SecureCipher as singletons."""
    global session_store_instance, key_manager_instance, secure_cipher_instance
    try:
        session_store_instance = SessionStore(db_file=app.config['SESSION_DB_FILE'])
        key_manager_instance = KeyManager(session_store_instance)
        secure_cipher_instance = SecureCipher()
    except Exception as e:
        logger.critical(f"CRITICAL ERROR: Failed to initialize core components: {e}", exc_info=True)
        sys.exit(1)

def register_blueprints(app):
    """Register blueprints for the app."""
    app.register_blueprint(create_commsec_blueprint(key_manager_instance, secure_cipher_instance), url_prefix='/api')
    app.register_blueprint(create_ui_blueprint(key_manager_instance, secure_cipher_instance), url_prefix='/')

if __name__ == '__main__':
    app = create_app()

    # Only this block will run if the script is executed directly
    logger = logging.getLogger(__name__)
    logger.info(f"✅ Q-COMMSEC API is running in {app.config['ENV']} mode on http://localhost:5000")
    app.run(debug=app.config['ENV'] == 'development', host='0.0.0.0', port=5000)  # Listen on all interfaces for Docker
