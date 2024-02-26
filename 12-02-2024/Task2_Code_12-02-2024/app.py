from flask import Flask
from datetime import timedelta

# Setup the flask app and configure
app = Flask(__name__)
app.secret_key = 'oiajfoiwajrfjaoifjawf235012530925'
app.permanent_session_lifetime = timedelta(days=1)
import routes

# If the app is being run from this file
if __name__ == '__main__':
    app.run(debug=True)