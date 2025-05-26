import os
from app import create_app

# Determine the configuration name from FLASK_CONFIG environment variable,
# defaulting to 'development' if not set.
config_name = os.getenv('FLASK_CONFIG') or 'development'
app = create_app(config_name)

if __name__ == '__main__':
    # Use a default port if not specified in environment, e.g., 5000
    port = int(os.environ.get("PORT", 5000)) 
    app.run(host='0.0.0.0', port=port)
