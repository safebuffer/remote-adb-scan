#! /usr/bin/python3
#Check remote adb on android devices @wazehell

import socket,sys,re

if len(sys.argv) < 2:
    print(" Usage: %s ip" % sys.argv[0])
    sys.exit(1)

def send(ip):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((str(ip),5555))
        s.send("\x43\x4e\x58\x4e\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1\x68\x6f\x73\x74\x3a\x3a\x00") 
        return s.recv(2048)
    except Exception as e:
        print("[-] Connection Error {}".format(e))
        sys.exit(1)


data = send(sys.argv[1])
if 'product' in data:
    try:
        print("[+] Product Name : {}".format(re.search("product.name=(.*);ro.product.model",data).group(1)))
        print("[+] Product Model : {}".format(re.search("ro.product.model=(.*);ro.product.device=",data).group(1)))
        print("[+] Product Device : {}".format(re.search(";ro.product.device=(.*);",data).group(1)))
    except:
        print("[-] Error while getting info !")
else:
    print("[-] port 5555 doesn't mean it's adb !")
