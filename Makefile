c:
	g++ client.cpp ./RSA/bigInt.cpp -l ws2_32 -I ./AES/ -I ./RSA/ -o client.exe
all:
	g++ client.cpp -l ws2_32 -I . -o client_A.exe
	g++ server.cpp -l ws2_32 -I . -o server_B.exe
clean:
	del *.exe