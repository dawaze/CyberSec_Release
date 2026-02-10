import os
import datetime

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE = os.path.join(BASE_DIR, 'users.db')
SECRET_KEY = '5bed50057df99f9bcf86cf191b8bbf5a52567db6'
SESSION_PERMANENT = True
PERMANENT_SESSION_LIFETIME = datetime.timedelta(days=10)
DEBUG = True