# ISA

Project of subject Network Applications and Network Administration of BUT FIT Bachelors course. <br />
Client/server application for transporting encrypted file by ICMP echo messages.

## Application lauch:
secret -r \<file> -s <ip|hostname> [-l] <br />
-r \<file> : specified file for transport <br />
-s <ip|hostname> : ip address/hostname where the file will be sent <br />
-l : if program is launched with this parametre, it will be launch as server, which will listen for incoming ICMP messages and will save file in the same
  directory program was launched in <br />
