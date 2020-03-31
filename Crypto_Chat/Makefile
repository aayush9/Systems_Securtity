all:
	gcc -std=c11 -pthread -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib client_16002.c -o client_16002 -lcrypto
	gcc -std=c11 -pthread -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib server_16002.c -o server_16002 -lcrypto

clean:
	rm -f server_16002 client_16002
