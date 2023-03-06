---
tags: BOOKS
---

# Black Hat Python 2E

## 1 Setting Up Your Python Env ... 1

### Installing Kali Linux

### Setting Up Python3
Use Python3 with a [**Virtual Environment**](https://hackmd.io/4f6vHQGCQDWTCl1xBhl3_w)
```shell=
$ cd bhp

bhp$ python -m venv venv3
# create a new virtual environment
# call our env. *venv3*

# To exit the env, use 'deactivate'
```

### Installing an IDE

### Code Hygiene

## 2 Basic Networking Tools ... 9

[Python 3 "Black Hat Python" Source Code](https://github.com/EONRaider/blackhat-python3)

### Python Networking in a Paragraph

### TCP Client

```python=
import socket

target_host = "www.google.com"
target_port = 80

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# AF_INET := IPv4
# SOCK_STREAM := TCP client

# connect the client to server
client.connect((target_host, target_port))

# send some data as bytes
client.send(b"GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")

# receive data
response = client.recv(4096)

client.close()

print(response)
```

### UDP Client

```python=
import socket

target_host = "127.0.0.1"
target_port = 80

# create a socket object
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Because UDP is connectionless, there is no connect() here

# send some data
client.sendto(b"AAABBBCCC", (target_host, target_port))

# receive(return) some data and remote host and port
data, addr = client.recvfrom(4096)

client.close()

print(data)
```

### TCP Server

```python=
import socket
import threading

IP = '0.0.0.0'
PORT = 9998

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # bind server on IP and PORT
    server.bind((IP, PORT))
    
    # server starts listening
    '''
    tells the socket library that we want it to queue 
    up as many as 5 connect requests (the normal max)
    before refusing outside connections
    '''
    server.listen(5)
    
    print(f'[*] Listening on {IP}:{PORT}')

    while True:
        # receive client socket and connection details
        client, address = server.accept()
        
        print(f'[*] Accepted connection from {address[0]}:{address[1]}')
        client_handler = threading.Thread(target=handle_client, args=(client,))
        client_handler.start()
        
def handle_client(client_socket):
    with client_socket as sock:
        request = sock.recv(1024)
        print(f'[*] Received: {request.decode("utf-8")}')
        sock.send(b'ACK')

if __name__ == '__main__':
    main()
```

### Replacing Netcat
> Smart sys-admins would remove netcat as it can be quite an asset for attackers that found a way in.

```python=
import argparse
import socket
import shlex
import subprocess
import sys
import textwrap
import threading


def execute(cmd):
    cmd = cmd.strip()
    if not cmd:
        return
    
    '''
    create a new process to run a command and
    output the output from the terminal
    '''
    output = subprocess.check_output(shlex.split(cmd),
                                     stderr=subprocess.STDOUT)
    return output.decode()

class NetCat:
    
    # NetCat object initializtion with args from CLI and buffer
    def __init__(self, args, buffer=None):
        self.args = args
        self.buffer = buffer
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        # Create socket object
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Entry point
    def run(self):
        # Execution delegation
        if self.args.listen:
            self.listen()
        else:
            self.send()

    def send(self):
        self.socket.connect((self.args.target, self.args.port))
        if self.buffer:
            self.socket.send(self.buffer)

        try:
            while True:
                recv_len = 1
                response = ''
                while recv_len:
                    data = self.socket.recv(4096)
                    recv_len = len(data)
                    response += data.decode()
                    if recv_len < 4096:
                        break
                if response:
                    print(response)
                    buffer = input('> ')
                    buffer += '\n'
                    self.socket.send(buffer.encode())
        except KeyboardInterrupt:
            print('User terminated.')
            self.socket.close()
            sys.exit()

    def listen(self):
        print('listening')
        self.socket.bind((self.args.target, self.args.port))
        self.socket.listen(5)
        while True:
            client_socket, _ = self.socket.accept()
            client_thread = threading.Thread(target=self.handle, args=(client_socket,))
            client_thread.start()

    def handle(self, client_socket):
        if self.args.execute:
            output = execute(self.args.execute)
            client_socket.send(output.encode())

        elif self.args.upload:
            file_buffer = b''
            while True:
                data = client_socket.recv(4096)
                if data:
                    file_buffer += data
                    print(len(file_buffer))
                else:
                    break

            with open(self.args.upload, 'wb') as f:
                f.write(file_buffer)
            message = f'Saved file {self.args.upload}'
            client_socket.send(message.encode())

        elif self.args.command:
            cmd_buffer = b''
            while True:
                try:
                    client_socket.send(b' #> ')
                    while '\n' not in cmd_buffer.decode():
                        cmd_buffer += client_socket.recv(64)
                    response = execute(cmd_buffer.decode())
                    if response:
                        client_socket.send(response.encode())
                    cmd_buffer = b''
                except Exception as e:
                    print(f'server killed {e}')
                    self.socket.close()
                    sys.exit()

if __name__ == '__main__':
    
    # create a CLI
    parser = argparse.ArgumentParser(
        description='BHP Net Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        
        # provide example usage when invoked with --help
        epilog=textwrap.dedent('''Example:
          netcat.py -t 192.168.1.108 -p 5555 -l -c # command shell
          netcat.py -t 192.168.1.108 -p 5555 -l -u=mytest.whatisup # upload to file
          netcat.py -t 192.168.1.108 -p 5555 -l -e=\"cat /etc/passwd\" # execute command
          echo 'ABCDEFGHI' | ./netcat.py -t 192.168.1.108 -p 135 # echo local text to server port 135
          netcat.py -t 192.168.1.108 -p 5555 # connect to server
          '''))
    # six args specifying program behavior
    # Listener: -c, -e, , -u, -l
    # Sender: -t, -p
    parser.add_argument('-c', '--command', action='store_true', help='initialize command shell')
    parser.add_argument('-e', '--execute', help='execute specified command')
    parser.add_argument('-l', '--listen', action='store_true', help='listen')
    parser.add_argument('-p', '--port', type=int, default=5555, help='specified port')
    parser.add_argument('-t', '--target', default='192.168.1.203', help='specified IP')
    parser.add_argument('-u', '--upload', help='upload file')
    args = parser.parse_args()
    
    # If set up as a listener...
    if args.listen:
        buffer = ''                # Empty buffer string
    else:
        buffer = sys.stdin.read()  # Send buffer content from stdin

    nc = NetCat(args, buffer.encode('utf-8'))
    nc.run()

```

### Building a TCP Proxy

### SSH with Paramiko

### SSH Tunneling
 
## 3 Writing a Sniffer ... 35

## 4 Owning the Network  with SCAPY ... 53

## 5 Web Hackery ... 71

## 6 Extending BURP Proxy ... 93

## 7 Github Command and Control ... 117

## 8 Common Trojaning Tasks on Windows ... 127
 
## 9 Fun with Exfiltration ... 139

## 10 Windows Privilege Escalation ... 153

## 11 Offensive Forensics ... 169