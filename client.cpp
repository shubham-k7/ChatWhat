#include <vector>
#include <algorithm>
#include <errno.h>  
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <iostream>
#include <pthread.h>
#include <fstream>
#include <string>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <limits>
#include <sstream>
#include <thread>
#include <cstring>
#include <cstdlib>
#include <pwd.h>
#include <netdb.h>
#include<tuple>
#include <openssl/evp.h>
using namespace std;

#define BUFFER_SIZE 5000
#define MAXLINES 15
#define MAX_ATTEMPTS 5
#define MAXUSERS 5
#define KDC_PORT 6565
#define CHAT_PORT 8080

#define KEY_LEN 32 // 256 bit
#define IV_LEN 16 // 128 bit
#define BLOCK_SIZE 16 // same as IV for AES-256-cbc
#define DELIM ",,,"

struct enc_util
{
	string salt;
	string password;
	unsigned char key[KEY_LEN];
	unsigned char iv[BLOCK_SIZE];

};
typedef struct enc_util enc_uti;

vector<string> split(const string& s,string del)
{
	vector<string> tokens;
	string token;
	string ss = s;
	size_t pos = 0;

	while ((pos = ss.find(del)) != string::npos)
	{
		token = ss.substr(0, pos);
		tokens.push_back(token);
		ss = ss.substr(pos + del.length());
	}
	tokens.push_back(ss);
	return tokens;
}

void exit_with_failure(string msg)
{
	cout<<msg<<endl;
	exit(-1);
}

string get_user(uid_t uid)
{
	struct passwd *pw = getpwuid(uid);
	return string(pw->pw_name);
}

string encrypt(enc_util* params, unsigned char* in_buf, int in_len)
{
	
	unsigned char *out_buf = new unsigned char[in_len + BLOCK_SIZE];
	
	int last_len = 0, out_len, out_size;

	EVP_CIPHER_CTX* ctx;
 	
 	ctx = EVP_CIPHER_CTX_new();
	
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, params->key, params->iv);
	
	EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, in_len);
	
	EVP_EncryptFinal_ex(ctx, out_buf+out_len, &last_len);
	
	EVP_CIPHER_CTX_reset(ctx);

	out_size = out_len + last_len;

	string enc_line(out_buf, out_buf + out_size);
	return enc_line;

}

string decrypt(enc_util* params, unsigned char* in_buf, int in_len)
{
	
	unsigned char* out_buf = new unsigned char[in_len];
	
	int last_len = 0, out_len, out_size;

	EVP_CIPHER_CTX* ctx;
 	
 	ctx = EVP_CIPHER_CTX_new();
	
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, params->key, params->iv);
	
	EVP_DecryptUpdate(ctx, out_buf, &out_len, in_buf, in_len);
	
	EVP_DecryptFinal_ex(ctx, out_buf+out_len, &last_len);
	
	EVP_CIPHER_CTX_reset(ctx);

	out_size = out_len + last_len;

	string dec_line(out_buf, out_buf + out_size);
	return dec_line;
}

int set_key_iv(string user, enc_util* params)
{

	if(!params) exit_with_failure("Couldn't create on heap");
	ifstream ifs;
	string line;
	ifs.open("/etc/shadow", istream::in);
	if(!ifs) exit_with_failure("Couldn't open Shadow file. Check suid bit of binary!");
	
	int flag = 0;
	while(getline(ifs, line))
	{
		if(line.substr(0,2) == user)
		{
			flag = 1;
			break;
		}
	}
	if(!flag) exit_with_failure("User not found!");

	vector<string> v = split(line, ":");
	string salt = line.substr(6,8);
	string pass = line.substr(15,86);

	params->salt = salt;
	params->password = pass;
	
	// Generate keys from input data
	int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), (unsigned char *) salt.c_str(), (unsigned char *) pass.c_str(), pass.length(), 3, params->key, params->iv);
	if(i != 32) //32 bytes = 64 hex-digits = 256 bits
	{
		exit_with_failure("Incorrect key size generated!\n");
	}

	return 0;
}

int send_enc(int cskt, enc_util* params, string payload)
{
	string enc_payload = encrypt(params,(unsigned char*)payload.c_str(), payload.length());
	return send(cskt, enc_payload.c_str(), enc_payload.size(), 0);
}

pair<int, string> recv_dec(int cskt, enc_util* params)
{
	char client_message[BUFFER_SIZE];
	memset(client_message,0, sizeof client_message);
	int rb = recv(cskt, client_message, BUFFER_SIZE-5, 0);
	string response(client_message, client_message + rb);
	string dec_res = decrypt(params, (unsigned char*)response.c_str(), response.length());
	return make_pair(rb, dec_res);
}

int main(int argc,char ** argv)
{
	int kdcSkt, chatSkt;
	srand(time(0));
	string current_user = get_user(getuid());
	cout<<"Welcome "<<current_user<<"! Initiating authentication with KDC\n";

	struct hostent *he;
	struct sockaddr_in kdcServer;
	he = gethostbyname("localhost");
	if(he == NULL)
		exit_with_failure("gethostbyname error");

	kdcSkt = socket(AF_INET, SOCK_STREAM, 0);
	
	if(kdcSkt == -1)
		exit_with_failure("Couldn't create KDC socket!");

	bzero(&kdcServer,sizeof(kdcServer));
	kdcServer.sin_family = AF_INET;
	kdcServer.sin_port = htons(KDC_PORT);
	kdcServer.sin_addr = *((struct in_addr*)he->h_addr);

	// Connecting to KDC server
	if(connect(kdcSkt,(struct sockaddr *)&kdcServer,sizeof(kdcServer))== -1)
		exit_with_failure("Couldn't connect to KDC Server!");

	string client_message;
	char server_reply[BUFFER_SIZE];
	char client_to_send[BUFFER_SIZE];
	int sb, rb;

	// Starting NS Authentication
	// Generate a nonce between 1 to 100
	int nonce1 = (rand() % 100) + 1;
	cout<<"n1: "<<nonce1<<endl;
	// STEP 1 n1, Alice
	string payload = to_string(nonce1) + "," + current_user;
	string client_m;
	// string client_m(payload.substr(0,BUFFER_SIZE-15)); // Threat
	
	sb = send(kdcSkt, payload.c_str(), payload.length(), 0);
	if(sb <= 0)
		exit_with_failure("Couldn't send... Possibly, Connection closed!");

	// STEP 2
	memset(server_reply,0, sizeof server_reply);
	rb = recv(kdcSkt, server_reply, BUFFER_SIZE-10, 0);
	if(rb == 0)
		exit_with_failure("Server disconnected");
	string response(server_reply, server_reply + rb);

	enc_util *params = new enc_util();
	set_key_iv(current_user, params);

	// Nonce1, "Server", kab, ticket
	string dec_response = decrypt(params, (unsigned char*) response.c_str(), response.length());

	vector<string> v = split(dec_response, DELIM);

	if(v.size() != 4)
		exit_with_failure("Payload has been tamperred with! Possible attack. Disconnecting!");

	int nonce1_reply = stoi(v.at(0));
	if(nonce1 != nonce1_reply)
		exit_with_failure("Incorrect Nonce replied! Could be Man in the Middle(MITM)!");

	string kab = v.at(2);
	string ticket = v.at(3);

	enc_util *temp = new enc_util();
	vector<string> v2 = split(kab,"===");
	memcpy(temp->key, (unsigned char*)v2.at(0).c_str(), KEY_LEN);
	memcpy(temp->iv, (unsigned char*)v2.at(1).c_str(), IV_LEN);

	// STEP 3
	int nonce2 = (rand() % 100) + 1;
	string strnonce2 = to_string(nonce2);
	string kabnonce2 = encrypt(temp, (unsigned char*)strnonce2.c_str(), strnonce2.length());
	
	payload = ticket + DELIM + kabnonce2; // Ticket,kab(nonce2)

	client_m = payload.substr(0,BUFFER_SIZE-15); // Threat
	
	struct sockaddr_in chatServer;

	chatSkt = socket(AF_INET, SOCK_STREAM, 0);
	
	if(chatSkt == -1)
		exit_with_failure("Couldn't create Chat socket!");

	bzero(&chatServer,sizeof(chatServer));
	chatServer.sin_family = AF_INET;
	chatServer.sin_port = htons(CHAT_PORT);
	chatServer.sin_addr = *((struct in_addr*)he->h_addr);

	// Connecting to Chat server
	if(connect(chatSkt,(struct sockaddr *)&chatServer,sizeof(chatServer))== -1)
		exit_with_failure("Couldn't connect to Chat Server!");

	sb = send(chatSkt, client_m.c_str(), client_m.length(), 0);
	if(sb <= 0)
		exit_with_failure("Couldn't send... Possibly, Connection closed!");

	memset(server_reply,0, sizeof server_reply);
	rb = recv(chatSkt, server_reply, BUFFER_SIZE-10, 0);
	if(rb == 0)
		exit_with_failure("Server disconnected");
	response = string(server_reply, server_reply + rb); // kab(n2-1,n3)

	dec_response = decrypt(temp, (unsigned char*)response.c_str(), response.length());
	v = split(dec_response,DELIM);
	cout<<"n2-1: "<<v.at(0)<<endl;
	cout<<"n3: "<<v.at(1)<<endl;
	int nonce2m1 = stoi(v.at(0));
	int nonce3 = stoi(v.at(1));

	payload = to_string(nonce3-1);
	string enc_payload = encrypt(temp, (unsigned char*)payload.c_str(), payload.length());
	client_m = enc_payload.substr(0,BUFFER_SIZE-15); // Threat

	sb = send(chatSkt, client_m.c_str(), client_m.length(), 0);
	if(sb <= 0)
		exit_with_failure("Couldn't send... Possibly, Connection closed!");

	pair<int, string> res;
	while(1)
	{
		res = recv_dec(chatSkt, temp);
		if(res.first == 0)
			exit_with_failure("Server disconnected");
		cout<<res.second;

		getline(cin, client_m);
		sb = send_enc(chatSkt, temp, client_m);
		if(sb <= 0)
			exit_with_failure("Couldn't send... Possibly, Connection closed!");
	}
	
	close(kdcSkt);
	// thread read_t(readHandler, ref(chatSkt));
	// thread write_t(writeHandler, ref(chatSkt));

	close(chatSkt);
	return 0;
}