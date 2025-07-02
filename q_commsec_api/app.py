from flask import Flask
import subprocess
import sys
import os
import time
import logging
from flask_cors import CORS

# Import logging configuration and set it up immediately
from q_commsec_api.logging_config import setup_logging

# Initialize global instances of KeyManager, SecureCipher, and SessionStore.
# These instances will be passed to the blueprint factories to ensure they are
# singletons and shared across all requests within the application.
session_store_instance = None
key_manager_instance = None
secure_cipher_instance = None # Will be initialized in create_app

def create_app(test_config=None):
    """
    Creates and configures the Flask application instance.

    Args:
        test_config (dict, optional): A dictionary of configuration values
                                      to override default settings, typically used for testing.

    Returns:
        Flask: The configured Flask application object.
    """
    app = Flask(__name__, template_folder='templates')

    # Configure app
    app.config.from_mapping(
        SECRET_KEY=os.getenv('SECRET_KEY', 'a_very_secret_key_default'),  # IMPORTANT: Use a strong, random key in production
        # Default session database file path relative to the app's root
        SESSION_DB_FILE=os.path.join(app.root_path, 'data', 'sessions.db'),
        # Default log file path relative to the app's root
        LOG_FILE_PATH=os.path.join(app.root_path, 'logs', 'api.log')
    )

    if test_config:
        # Load the test configuration if provided (e.g., for pytest)
        app.config.from_mapping(test_config)
    
    # Setup logging using the configured path
    setup_logging(log_file_path=app.config['LOG_FILE_PATH'], level=logging.INFO)
    logger = logging.getLogger(__name__)
    logger.info("Flask app initialization started.")

    # Initialize SessionStore and KeyManager using the app's config
    # Use global variables to ensure singletons
    global session_store_instance, key_manager_instance, secure_cipher_instance
    try:
        session_store_instance = SessionStore(db_file=app.config['SESSION_DB_FILE'])
        key_manager_instance = KeyManager(session_store_instance)
        secure_cipher_instance = SecureCipher() # SecureCipher is stateless
    except Exception as e:
        logger.critical(f"CRITICAL ERROR: Failed to initialize core components: {e}", exc_info=True)
        sys.exit(1)  # Exit if master key is not set or invalid

    # Enable CORS for all origins (for development, restrict in production)
    CORS(app)

    # Import blueprints here to avoid circular imports, as they depend on initialized managers
    from q_commsec_api.routes.commsec_routes import create_commsec_blueprint
    from q_commsec_api.routes.ui_routes import create_ui_blueprint

    # Register the blueprints, passing the shared instances.
    app.register_blueprint(create_commsec_blueprint(key_manager_instance, secure_cipher_instance), url_prefix='/api')
    app.register_blueprint(create_ui_blueprint(key_manager_instance, secure_cipher_instance), url_prefix='/')

    @app.route('/health')
    def health_check():
        """Simple health check endpoint."""
        logger.debug("Health check requested.")
        return "API is healthy", 200

    logger.info("Flask app initialization completed.")
    return app

if __name__ == '__main__':
    # When run directly (e.g., by Docker CMD), create the app.
    # The Dockerfile's CMD handles running pytest first.
    app = create_app()
    logger = logging.getLogger(__name__) # Get logger after setup_logging is called

    # This block will only execute if the script is run directly,
    # and after pytest has completed successfully (due to '&&' in CMD).
    logger.info(f"✅ Q-COMMSEC API is running in {app.config['ENV']} mode on http://localhost:5000")
    # Run the Flask development server.
    # debug=False is recommended for production-like environments.
    app.run(debug=app.config['ENV'] == 'development', host='0.0.0.0', port=5000) # Listen on 0.0.0.0 for Docker
