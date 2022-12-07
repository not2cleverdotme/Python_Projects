#!/bin/python3
#Inspired by Black Hat Python
#ssh with Paramiko, chapter 2.
#Installed Paramiko using "pip install paramiko"

import getpass
import paramiko

#The below function makes an ssh connection.
def ssh_command(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()

    #Accept ssh key.
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)

    #Run the command that was passed to the call ssh_command function.
    _, stdout, stderr = client.exec_command(cmd)
    output = stdout.readlines() + stderr.readlines()
    if output:
        print("--- Output ---")
        for line in output:
            print(line.strip())

#Request credentials using the getpass module.
if __name__ == '__main__':
    user = input("Username: ")
    password = getpass.getpass()
    ip = input("Enter server IP: ") or "192.168.1.203"
    port = input("Enter port or <CR>: ") or 2222
    cmd = input("Enter command or <CR>: ") or "id"
        
    #Get the IP, Port, User, Password, and command.
    ssh_command(ip, port, user, password, cmd)






