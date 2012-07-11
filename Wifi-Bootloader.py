# -*- coding: utf-8 -*-
import socket
import crc16
import sys
#import time
from time import *

flashsize = 8192
read_step = 64

bootadr = int()
bootbytes = int()


#++++++++++++++ detect Bootloader+++++++++++++++++
def detect_bootloader():
    send_data = bytearray()
    send_data.append(0x0f)
    
    loopcondition = bool()
    loopcondition = 1
    
    #print "Try to detect Bootloader"
    
    while loopcondition:
        s.send(send_data)
        print "."
        try:
            recv_data = s.recv(1024)
        except socket.timeout:
            print "x"
            recv_data = ""
        
        
        if recv_data: 
            recv_data.find(chr(0x0f))
            print "--> Bootloader detected"
            loopcondition = 0
#++++++++++++++ clean Receive DATA++++++++++++++++++
#Saubert die Antwort des Mikrocontrollers, damit nurnoch die Rohdaten
#vorhanden sind. Steuerzeichen und CRC werden entfernt
def clean_data(string):

    str1 = bytearray()
    str2 = bytearray()
    dle = bool()

    for i in range(1,string.__len__()-3):
        str1.append(string[i])

    for c in str1:
        if c == 0x05:
            if dle == 0:
                dle = 1
            else:
                str2.append(c)
                dle = 0
        else:
            dle = 0
            str2.append(c)
    return str(str2)
#++++++++++++++ get Bootloader info+++++++++++++++++
def get_bootloader_info():
    
    send_data = bytearray()
    send_data.append(0x0f)
    send_data.append(0x00)
    send_data.append(0x00)
    send_data.append(0x00)
    send_data.append(0x04)
    
    loopcondition = bool()
    loopcondition = 1
    
    print "Get Bootloader Information"
    
    while loopcondition:
        s.send(send_data)
        try:
            recv_data = s.recv(1024)
        except socket.timeout:
            print "x"
            recv_data = ""
        
        
        if recv_data:
            if recv_data.__len__() > 12:
                print "--> successfull"
                #for c in recv_data:
                    #print "%#x" % ord(c)
                loopcondition = 0
                return recv_data
            
            else:
                print "--> failed"
                print "Received datalength:", recv_data.__len__()
                loopcondition = 0
                return 0
            
#++++++++++++++ get Bootloader info+++++++++++++++++
def print_bootloader_info(string):
    
    global bootbytes
    global bootadr
    bootbytes = ord(string[1])
    bootbytes = bootbytes<<8
    bootbytes += ord(string[0])
    print ""
    print "-----------------------------------------------"
    print "BOOTLOADER INFORMATIONS"
    print "-----------------------------------------------"
    print "Bootblock Size:", bootbytes

    print "Bootloader Version:", ord(string[2]), ".",ord(string[3])

    print "Commandmask:", "%#x" % ord(string[4]) 

    print "Family-ID:", ord(string[5])
    
    bootadr = ord(string[8])
    bootadr = bootadr<<8
    bootadr += ord(string[7])
    bootadr = bootadr<<8
    bootadr += ord(string[6])
    
    print "Bootloader Address:", "%#x" %  bootadr

    deviceid = ord(string[10])
    deviceid = deviceid << 8
    deviceid += ord(string[11])
    deviceid = deviceid >> 6
    
    print "Device-ID:" ,"%#x" % deviceid

#++++++++++++++++ read Device Flash++++++++++++++++++++
def read_flash():
    
    print "-----------------------------------------------"
    print "READ DEVICE FLASH"
    print "-----------------------------------------------"
    
    flash_mem = bytearray()
    
    for i in range(0x0,flashsize,read_step):
        #print "Reading from address", i
        send_data = bytearray()
        send_data.append(0x01)
        send_data.append(i >> 0 & 0xff)
        send_data.append(i >> 8 & 0xff)
        send_data.append(i >> 16 & 0xff)
        send_data.append(0x00)
        send_data.append(read_step >> 0 & 0xff)
        send_data.append(read_step >> 8 & 0xff)
    
        s.send(build_send_str(send_data))
        try:
            recv_data = s.recv(1024)
        except socket.timeout:
            print "x"
            recv_data = ""
        
        if recv_data:
            if check_crc(recv_data):
                for c in clean_data(recv_data):
                    flash_mem.append(c)
            else:
                print "CRC FAILURE"
                break
            
    return flash_mem

#++++++++++++++++ print Device Flash++++++++++++++++++++
def print_flash(flash_arr):
    
    flash_arr_words = list()
    for j in range(0,flash_arr.__len__(),2):
       flash_arr_words.append((flash_arr[j+1] << 8) + flash_arr[j])
        
    
    for i in range(0,flash_arr_words.__len__(),8):
        print "%04X | %04X %04X %04X %04X %04X %04X %04X %04X" % (i, flash_arr_words[i], flash_arr_words[i+1],  flash_arr_words[i+2], flash_arr_words[i+3],flash_arr_words[i+4], flash_arr_words[i+5], flash_arr_words[i+6], flash_arr_words[i+7])

    
#++++++++++++++++ check crc ++++++++++++++++++++
#Funktion prüft die Checksumme. Wichtig! Übergebener string muss noch alle Steuerzeichen 
#sowie die Checksumme enthalten. Unbearbeitete Mikrocontrollerantwort.
#(Funktion clean_data darf auf diesem String noch nicht ausgeführt worden sein)
def check_crc(string):
    
    crc = crc16.crc16xmodem(clean_data(string), 0x0000)    
    crc_arr = bytearray()
    crc_arr.append(crc >> 0 & 0xff)
    crc_arr.append(crc >> 8 & 0xff)
    
    recv_crcH = string[string.__len__()-2]
    recv_crcL = string[string.__len__()-3]
    
    #print "%#x" % ord(recv_crcH)
    #print "%#x" % ord(recv_crcL)
    
    #print "%#x" % crc_arr[0]
    #print "%#x" % crc_arr[1]

    if (crc_arr[0] == ord(recv_crcL)) & (crc_arr[1] == ord(recv_crcH)):
        return 1
    else:
        return 0

#++++++++++++++++ build send string ++++++++++++++++++++
#Funktion fügt Steuerzeichen und CRC zu dem String hinzu. 
#Notwendig, damit der Bootloader den String richtig interpretiert.
def build_send_str(string):
    
    str_arr = bytearray()
    dle = bool()
    
    crc = crc16.crc16xmodem(str(string), 0x0000)
    
    str_arr.append(0x0f)
    
    for c in string:
        if (c == 0x05)|(c == 0x0f)|(c == 0x04):
            str_arr.append(0x05)
        str_arr.append(c)
    
    crcH = (crc >> 0 & 0xff)
    crcL = (crc >> 8 & 0xff) 

    if (crcH == 0x05)|(crcH == 0x0f)|(crcH == 0x04):
            str_arr.append(0x05)
    str_arr.append(crcH)

    if (crcL == 0x05)|(crcL == 0x0f)|(crcL == 0x04):
        str_arr.append(0x05)
    str_arr.append(crcL)



    str_arr.append(0x04)

        #for c in str_arr:
            #print hex(c)

    return str_arr

#++++++++++++++++ write Programmcode to Device Flash ++++++++++++++++++++
def write_flash(address):
    
    detect_bootloader()
    print_bootloader_info(clean_data(get_bootloader_info()))
    detect_bootloader()
    flash_current_mem = read_flash()
    
    print "-----------------------------------------------"
    print "WRITE DEVICE FLASH"
    print "-----------------------------------------------"

    temp = address.split(":")
    path = temp[1]
    print "Pfad der .hex-Datei:",path
    
    try:
        answer = ""
        answer = raw_input("Dateinpfad korrekt? y/n")
        if (answer.find("y")== -1):
            return
    except:
        print "EINGABEFEHLER"
        return

    file = open(path, "r")

    flash_wr_mem = bytearray()
    for e in range(0,flashsize):
        flash_wr_mem.append(0xff)
        flash_wr_mem.append(0x3F)

    for line in file:
        
        Offset = line.find(":")
        
        #Check ob : in der Line vorhanden ist
        if Offset > -1:
            Datalength = int(line[Offset+1],16) << 4
            Datalength += int(line[Offset+2],16)
            
            Address = int(line[Offset+3],16) << 12
            Address += int(line[Offset+4],16) << 8
            Address += int(line[Offset+5],16) << 4
            Address += int(line[Offset+6],16) << 0
            
            Recordtyp = int(line[Offset+7],16) << 4
            Recordtyp += int(line[Offset+8],16) << 0
            
            #print  "  ", line, "Datenworte", Datalength, "Adresse", hex(Address), "Recordtyp", Recordtyp
            
            #break wenn Recordtyp = 1
            if Recordtyp == 1:
                break
            
            #Prüfe Recordtyp ob es sich um Daten handelt
            if Recordtyp == 0:
                for i in range(0, Datalength):
                    
                    byte = int(line[Offset+9+(i*2)],16) << 4
                    byte += int(line[Offset+(i*2)+10],16) << 0
                    flash_wr_mem[Address+i] = byte  
    file.close()

    print ""
    print "Remapping App-Vektor to adress:", "%#x" %  bootadr
                        
    #Put App Vektor to flash_wr_mem
    flash_wr_mem[(bootadr)*2-10] = (0x018A >> 0) & 0xff
    flash_wr_mem[(bootadr)*2-9] = (0x018A >> 8) & 0xff  
    flash_wr_mem[(bootadr)*2-8] = flash_wr_mem[0]
    flash_wr_mem[(bootadr)*2-7] = flash_wr_mem[1]
    flash_wr_mem[(bootadr)*2-6] = flash_wr_mem[2]
    flash_wr_mem[(bootadr)*2-5] = flash_wr_mem[3]
    flash_wr_mem[(bootadr)*2-4] = flash_wr_mem[4]
    flash_wr_mem[(bootadr)*2-3] = flash_wr_mem[5]
    flash_wr_mem[(bootadr)*2-2] = flash_wr_mem[6]
    flash_wr_mem[(bootadr)*2-1] = flash_wr_mem[7]
    

    #Put Resetvektor to flash_wr_mem
    word1 = 0x3000 | (((bootadr+3) >>8) & 0xff)         #movlw high(BootloaderBreakCheck)
    word2 = 0x008A                                      #movwf PCLATH
    word3 = 0x2800 | ((bootadr+3) & 0x7ff)             #goto  BootloaderBreakCheck
                  
    flash_wr_mem[0] = (word1 >> 0) & 0xff
    flash_wr_mem[1] = (word1 >> 8) & 0xff
    flash_wr_mem[2] = (word2 >> 0) & 0xff
    flash_wr_mem[3] = (word2 >> 8) & 0xff
    flash_wr_mem[4] = (word3 >> 0) & 0xff
    flash_wr_mem[5] = (word3 >> 8) & 0xff


    #print_flash(flash_wr_mem)
    
    detect_bootloader()
    
    for i in range(0, flashsize * 2, 16):
        
        if (i < bootadr) | (i > bootadr+bootbytes*2): 
            write_data = bytearray()
            write_data.append(0x04)
            write_data.append(i/2 >> 0 & 0xff)
            write_data.append(i/2 >> 8 & 0xff)
            write_data.append(i/2 >> 16 & 0xff)
            write_data.append(0x00)
            write_data.append(0x01)
            for j in range(0, 16):
                write_data.append(flash_wr_mem[i+j])
      
            write_string = build_send_str(write_data)
            s.send(write_string)
      
            try:
                recv_data = s.recv(1024)
            except socket.timeout:
                print "x"
                recv_data = ""
      
            if recv_data:
                if check_crc(recv_data) == 0:
                    print "CRC FAILURE"
                    break
                    
   
#************ MAIN *************************************

TCP_IP = '192.168.2.44'
TCP_PORT = 2000
BUFFER_SIZE = 1024

print ""
print "-----------------------------------------------"
print "                 PIC BOOTLOADER   "
print "-----------------------------------------------"

for arg in sys.argv:
    #------help ARG------
    if (arg.find("help")> -1)|(arg.find("?")> -1):
        print "Parameter: ?                      --> Bedienungsanleitung"
        print "Parameter: help                   --> Bedienungsanleitung"
        print "Parameter: bl_info                --> Bootloader des Mikrocontrollers auslesen"
        print "Parameter: read_flash             --> Flash-Inhalt des Mikrocontrollers auslesen"
        print "Parameter: write_flash:code.hex   --> Programmiert den Inhalt der angegebenen Datei"
        break
    #------bl_info ARG---
    if (arg.find("bl_info")> -1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TCP_IP, TCP_PORT))    
        s.settimeout(1)

        detect_bootloader()
        recv_data = get_bootloader_info()
        print_bootloader_info(clean_data(recv_data))

        if check_crc(recv_data) == 0:
            print "CRC_FAIL"

        s.close()

    #-----read_flash ARG---
    if (arg.find("read_flash")> -1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TCP_IP, TCP_PORT)) 
        s.settimeout(1)

        detect_bootloader()
        print_flash(read_flash())
        s.close()
    #-----write_flash ARG---
    if (arg.find("write_flash")> -1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TCP_IP, TCP_PORT)) 
        s.settimeout(2)
        write_flash(arg)
        s.close()
    