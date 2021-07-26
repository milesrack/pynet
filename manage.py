#!/usr/bin/python3
import sys
import sqlite3
import hashlib
import getpass
from prettytable import PrettyTable
from settings import *

db = sqlite3.connect(DB_URI, uri=True, isolation_level=None)
cur = db.cursor()
cur.execute('CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT, max_time INTEGER DEFAULT 0, expiration TEXT DEFAULT "1970-01-01")')

usage = f'''Usage: python3 {sys.argv[0]} ACTION
ACTIONS include:
list			List users in the database.
create			Creates a new user.
update			Update a user's information.
delete			Delete a user.'''

if len(sys.argv) != 2:
	print(usage)
	sys.exit()
else:
	operation = sys.argv[1]

if operation == 'list':
	try:
		users = PrettyTable(['ID', 'Username', 'Max time', 'Expiration']) 
		query = cur.execute('SELECT id, username, max_time, expiration FROM users')
		for user in query:
			_id, username, max_time, expiration = user
			users.add_row([_id, username, max_time, expiration])
		print(users)
	except Exception as e:
		print(f'\033[0;31m{e}\033[0m')

elif operation == 'create':
	try:
		username = input('Username: ')
		password = hashlib.sha256(getpass.getpass('Password: ').encode('utf-8')).hexdigest()
		max_time = int(input('Max time (seconds): '))
		days = int(input('Days until expiration: '))
		expiration = cur.execute(f'SELECT DATE("now", "+{days} day")').fetchone()[0]
		cur.execute(f'INSERT INTO users (username, password, max_time, expiration) VALUES (?, ?, ?, ?)', (username, password, max_time, expiration))
		print(f'\033[0;32mSuccessfully created user {username}.\033[0m')
	except Exception as e:
		print(f'\033[0;31m{e}\033[0m')

elif operation == 'update':
	try:
		username = input('Username: ')
		print('Enter nothing to keep values the same')
		password = getpass.getpass('Password: ')
		if password == '':
			password = cur.execute('SELECT password FROM users WHERE username=?', (username,)).fetchone()[0]
		else:
			password = hashlib.sha256(password.encode('utf-8')).hexdigest()
		try:
			max_time = int(input('Max time (seconds): '))
		except:
			max_time = cur.execute('SELECT max_time FROM users WHERE username=?', (username,)).fetchone()[0]
		try:
			days = int(input('Days until expiration: '))
			expiration = cur.execute(f'SELECT DATE("now","+{days} day")').fetchone()[0]
		except:
			expiration = cur.execute('SELECT expiration FROM users WHERE username=?', (username,))
		cur.execute('UPDATE users SET password=?, max_time=?, expiration=? WHERE username=?', (password, max_time, expiration, username))
		print(f'\033[0;32mSuccessfully update user {username}.\033[0m')
	except Exception as e:
		print(f'\033[0;31m{e}\033[0m')
			
		

elif operation == 'delete':
	try:
		username = input('Username: ')
		cur.execute('DELETE FROM users WHERE username=?', (username,))
		print(f'\033[0;32mSuccessfully deleted user {username}.\033[0m')
	except Exception as e:
		print(f'\033[0;31m{e}\033[0m')

else:
	print(usage)
