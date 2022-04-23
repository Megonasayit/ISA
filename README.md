# ISA

Client/server application for transporting encrypted file by ICMP echo messages.

## Application lauch:
secret -r <file> -s <ip|hostname> [-l]
-r <file> : specified file for transport
-s <ip|hostname> : ip address/hostname where the file will be sent
-l : if program is launched with this parametre, it will be launch as server, which will listen for incoming ICMP messages and will save file in the same
  directory program was launched in
