# pynet :snake:
A proof-of-concept botnet written in Python.

## :pushpin: Installation
```
git clone https://github.com/milesrack/pynet.git
cd pynet
pip3 install -r requirements.txt
```

## :pushpin: Usage
### Changing Settings
Before running the script edit `settings.py`. You will need to change `BIND_IP` and `DB_URI`, everything else can stay as it is.

### Starting the Server
To start the server:
```
python3 server.py
```
This will begin listening for connections from infected machines, listen for user connections, and start a web server which serves the payload. A `public` directory will be created which contains the following files:
- `infect.sh`: Installs Python, downloads `client.py`, and sets up persistence for Linux machines (requires root access because of raw sockets).
- `infect.bat`: Streams the data from `infect.ps1` into powershell without writing to the disk (bypasses execution policy).
- `infect.ps1`: Installs Python, downloads `client.py`, and sets up persistence for Windows machines.
- `client.py`: Recieves commands from server and executes them.

### Infecting Machines
**Linux payload:** `http://<BIND_IP>:<WEB_PORT>/infect.sh`

**Windows payload:** `http://<BIND_IP>:<WEB_PORT>/infect.bat`

### Creating a User
Before you log into the server, you must create a user:
```
python3 manage.py create
```
You can use the `manage.py` script to list, create, update, and delete users. Run `python3 manage.py` (without arguments) for help.

### Logging In
To log into the server, make a raw TCP connection to `<BIND_IP>:<COMMAND_PORT>`. You can use netcat (Linux), PuTTY (Windows), or anything that allows raw TCP connections. From there you will be prompted for your username and password.

### Executing Commands
Once you are logged in, run `help` to see the available commands and their usage.

## :pushpin: Improvements
This project was just done for learning purposes. It could be improved by encrypting the commands sent over raw TCP sockets (by default this is plaintext). This would prevent unauthorized people from sending commands to the bots and make analysis slightly harder. Another improvement would be to rewrite the client end in a compiled language.

## :warning: Disclaimer
Do not use this code for anything malicous. Only infect machines that you own or have permission to infect.