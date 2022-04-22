CC= g++

secret: secret.cpp
		$(CC) $(CFLAGS) secret.cpp -o secret -lcrypto -lpcap