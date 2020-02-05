all:
	g++ -g -std=c++11 server.cpp -o server -lpthread -lcrypto
	g++ -g -std=c++11 client.cpp -o client -lpthread -lcrypto
	sudo chown root:root server
	sudo chown root:root client
	sudo cp server /usr/bin
	sudo cp client /usr/bin
	sudo chmod u+s /usr/bin/server
	sudo chmod u+s /usr/bin/client

.PHONY: clean
	
clean:	
	-rm server client /usr/bin/server /usr/bin/client