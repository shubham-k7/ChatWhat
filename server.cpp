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
#include<tuple>
#include <netdb.h>
#include <list>
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
string PWD;
struct enc_util
{
	string salt;
	string password;
	unsigned char key[KEY_LEN];
	unsigned char iv[BLOCK_SIZE];

};
typedef struct enc_util enc_uti;

struct group_info
{
	string admin;
	int gid;
	string gname;
	vector<string> users;
	string shared_secret;
};
typedef struct group_info group_info;

std::list< tuple<string, int, pair<string, string>> > logged_in_users;

string get_user(uid_t uid)
{
	struct passwd *pw = getpwuid(uid);
	return string(pw->pw_name);
}

string get_ticket(string current_user)
{
	return string("kapa");
}

bool exists (const string& path)
{	
	struct stat buffer;
	return (stat (path.c_str(), &buffer) == 0);
}

bool isfile(const string& path)
{
	struct stat buffer;
	return (stat (path.c_str(), &buffer) == 0 && S_ISREG(buffer.st_mode));
}

bool isdir(const string &path)
{
	struct stat sb;
	return stat(path.c_str(), &sb) == 0 && S_ISDIR(sb.st_mode);
}

int generate_sending_error(int cskt)
{
	cout<<"Couldn't send... Possibly, Connection closed!\n";
	close(cskt);
	return 0;
}
int generate_client_error(int cskt)
{
	cout<<"Client disconnected!\n";
	close(cskt);
	return 0;
}

bool pathResolver(const string path, string *result)
{
	char* absol = realpath(path.c_str(), NULL);
	if(absol)
	{
		cout<<"Path resolved: "<<*absol<<endl;
		*result = string(absol);
		return true;
	}
	cout<<"path: "<<path<<" Not found!"<<endl;
	return false;
}

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

bool authenticate_read_perm(string result_path, string current_user, int cskt, string cwd) 
{
	int sb;
	// string server_reply = "Read denied [Authentication failed]\n";
	if(result_path.find(PWD) != 0)
	{
		// sb = send(cskt, server_reply.c_str(), server_reply.length(),0);
		// if(sb<0)
		// 	generate_sending_error(cskt);
		cout<<"THIS 1\n";
		return false;
	}
	int n = result_path.length();
	if(result_path.substr(n-2) == ".m")
	{
		// sb = send(cskt, server_reply.c_str(), server_reply.length(),0);
		// if(sb<0)
		// 	generate_sending_error(cskt);
		cout<<"THIS 2\n";
		return false;
	}
	string temp(result_path);
	temp += ".m";
	string user, group; 
	ifstream ifs, ifs_groups;
	
	ifs.open(temp, ifstream::in);
	if(!ifs)
	{
		cout<<"THIS 3\n";
		return false;
	}
	getline(ifs, user);
	getline(ifs, group);
	ifs.close();
	string server_reply;
	ifs.open("groups.txt",ifstream::in);
	if(!ifs)
	{
		server_reply = "Group files have been tampered with. Aborting...\n";
		sb = send(cskt, server_reply.c_str(), server_reply.length(),0);
		if(sb<0)
			generate_sending_error(cskt);
		close(cskt);
		pthread_exit(NULL);
		cout<<"THIS 4\n";
		return false;
	}
	if(user == current_user)
	{
		cout<<"THIS 5\n";
		return true;
	}
	else
	{
		string line, g;
		while (getline(ifs, line))
		{
			vector<std::string> v = split(line,",");
			if(group == v.at(0))
			{
				if(find(v.begin(), v.end(),user) != v.end()) // allow
				{
					ifs.close();
					cout<<"THIS 6\n";
					return true;
				}
			}
		}
		ifs.close();
		cout<<"THIS 7\n";
		return false;
	}
	ifs.close();
	return false;
}
bool authenticate_write_perm(string result_path, string current_user, int cskt, string cwd)
{

	int sb;
	string server_reply = "Path NOT Allowed";
	if(result_path.find(PWD) != 0)
	{
		sb = send(cskt, server_reply.c_str(), server_reply.length(),0);
		if(sb<0)
			generate_sending_error(cskt);
		return false;
	}
	string temp(result_path);
	temp += ".m";
	string user, group;
	ifstream ifs, ifs_groups;
	
	ifs.open(temp, ifstream::in);
	getline(ifs, user);
	ifs.close();

	bool allow = false;
	if(user == current_user)
	{
		return true;
	}
	else
		return false;
}

vector<string> split_path_file(const string& str)
{
	size_t found = str.find_last_of("/\\");
	vector<string> v;
	string path = str.substr(0,found);
	string file = str.substr(found+1);
	if(found == string::npos)
	{
		return v;
	}
	return v;
}

// FPUT WRITE AUTHENTICATE

string file_get(string path)
{
	ifstream ifs;
	string line, response;
	ifs.open(path.c_str(), istream::in);
	if(!ifs)
	{
		return "Cannot read directory[fgets]\n";
	}
	while(getline(ifs, line))
	{
		response += (line + "\n");
	}
	return response;
}

void exit_with_failure(string msg)
{
	cout<<msg<<endl;
	exit(-1);
}

int set_key_iv(string user, enc_util* params)
{

	if(!params) exit_with_failure("Couldn't create on heap");

	ifstream ifs;
	string line;
	ifs.open("/etc/shadow", istream::in);
	if(!ifs) exit_with_failure("Couldn't open Shadow file. Check suid bit of binary!");
	
	int n = user.length();
	int flag = 0;
	while(getline(ifs, line))
	{
		if(line.substr(0,n) == user)
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

pair<string, string> generate_eph_key_iv()
{
	// Generate keys from random number
	unsigned char key[KEY_LEN];
	unsigned char iv[BLOCK_SIZE];

	string salt = to_string(rand());
	string pass = to_string(rand());
	int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha256(), (unsigned char *) salt.c_str(), (unsigned char *) pass.c_str(), pass.length(), 3, key, iv);
	if(i != 32) //32 bytes = 64 hex-digits = 256 bits
	{
		exit_with_failure("Incorrect key size generated!\n");
	}
	return make_pair(string(key,key + KEY_LEN), string(iv, iv + IV_LEN));
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


void kdcClientHandler(int cskt)
{
	char client_message[BUFFER_SIZE+10];
	int sb, rb;
	
	memset(client_message,0, sizeof client_message);
	rb = recv(cskt, client_message, BUFFER_SIZE-5, 0);
	string response(client_message, client_message + rb); // Response: N1, Alice

	vector<string> v = split(response, ","); 
	int nonce1 = stoi(v.at(0));
	string user = v.at(1);

	if(user != "u1" && user != "u2" && user != "u3")
	{
		cout<<"Wrong user attempting connection! Closing socket!"<<endl;
		close(cskt);
	}
	cout<<"KDC: Authenticating Client: "<<user<<endl;
	cout<<"n1: "<<nonce1<<endl;
	
	enc_util *params = new enc_util();
	set_key_iv(user, params);

	pair<string, string> p = generate_eph_key_iv();

	enc_util *param_for_ticket = new enc_util();
	string chat_server_name = get_user(getuid());
	set_key_iv(chat_server_name, param_for_ticket);

	string kab = p.first + "===" + p.second;

	string ticket_content = kab + DELIM + user;
	string ticket = encrypt(param_for_ticket, (unsigned char*) ticket_content.c_str(), ticket_content.length());

	string payload = v.at(0) + DELIM + chat_server_name + DELIM + kab + DELIM + ticket; // Ka(n1, server, kab, ticket)

	string enc_payload = encrypt(params, (unsigned char*) payload.c_str(), payload.length());

	sb = send(cskt, enc_payload.c_str(), enc_payload.size(), 0);
	if(sb < 0)
		generate_sending_error(cskt);

	close(cskt);
}

void kdcHandler()
{
	int kdcSkt;
	if((kdcSkt = socket(AF_INET , SOCK_STREAM , 0)) < 0)
	{
		perror("Socket not created");
		return;
	}
	struct sockaddr_in server_address, client_address;
	memset(&server_address,0,sizeof(server_address));
	server_address.sin_family=AF_INET;
	server_address.sin_port=htons(KDC_PORT);
	server_address.sin_addr.s_addr=htonl(INADDR_ANY);

	int b = ::bind(kdcSkt, (struct sockaddr*)&server_address, sizeof(server_address));
	if(b == -1)
	{
		perror("Binding failed");
		exit(EXIT_FAILURE);
	}
	
	int l = listen(kdcSkt, MAXUSERS);
	if(l == -1)
	{
		perror("listening failed");
	   	exit(EXIT_FAILURE);
	}

	cout<<"KDC Server is listening at PORT: "<<KDC_PORT<<endl;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size;
	
	thread tid[MAXUSERS];
	int i = 0, clientSkt;
	while(1)
	{
		addr_size = sizeof(serverStorage);
		clientSkt = accept(kdcSkt, (struct sockaddr*)&client_address, &addr_size);
		if(clientSkt == -1)
		{
			perror("Connection error!");
			exit(-1);
		}
		tid[i++] = std::thread(kdcClientHandler, ref(clientSkt));
		if(i >= MAXUSERS)
		{
			i = 0;
			while(i<MAXUSERS)
			{
				tid[i++].join();
			}
			i=0;
		}
	}
}

void chatClientHandler(int cskt)
{	
	char client_message[BUFFER_SIZE+10];
	bool logged_in = false, flag = false;
	int sb, rb;
	
	memset(client_message,0, sizeof client_message);
	rb = recv(cskt, client_message, BUFFER_SIZE-5, 0);
	if(rb == 0)
		generate_client_error(cskt);

	string response(client_message, client_message + rb); // Response contains: Ticket, kab(Nonce2)
	// cout<<"response: "<<response<<endl;
	vector<string> v = split(response, DELIM);
	// cout<<v.size()<<endl;
	string ticket = v.at(0);
	// cout<<ticket<<endl;
	string kabn2 = v.at(1);

	enc_util *param_for_ticket = new enc_util();
	string chat_server_name = get_user(getuid());
	set_key_iv(chat_server_name, param_for_ticket);

	string dec_ticket = decrypt(param_for_ticket, (unsigned char*)ticket.c_str(), ticket.length());

	// Verify ticket
	v = split(dec_ticket,DELIM);
	// cout<<"dec_tick sizE: "<<v.size()<<endl;
	string kab = v.at(0);
	string user = v.at(1);

	enc_util *temp = new enc_util();
	v = split(kab,"===");
	// cout<<"kab: "<<kab<<endl;
	// cout<<"kab split: "<<v.size()<<endl;
	memcpy(temp->key, (unsigned char*)v.at(0).c_str(), KEY_LEN);
	memcpy(temp->iv, (unsigned char*)v.at(1).c_str(), IV_LEN);

	string strnonce2 = decrypt(temp, (unsigned char*)kabn2.c_str(), kabn2.length());
	// cout<<"YOLO: "<<strnonce2<<endl;
	int nonce2 = stoi(strnonce2);
	cout<<"n2: "<<nonce2<<endl; 
	int nonce3 = (rand() % 100) + 1;
	string payload = to_string(nonce2-1) + DELIM + to_string(nonce3);
	string enc_payload = encrypt(temp, (unsigned char*)payload.c_str(), payload.length());

	sb = send(cskt, enc_payload.c_str(), enc_payload.size(), 0);
	if(sb < 0)
	{
		generate_sending_error(cskt);
		close(cskt);
		return;
	}

	memset(client_message,0, sizeof client_message);
	rb = recv(cskt, client_message, BUFFER_SIZE-5, 0);
	if(rb == 0)
		generate_client_error(cskt);

	response = string(client_message, client_message + rb); // Response contains: kab(Nonce3)
	// cout<<"response: "<<response<<endl;
	string strnonce3m1 = decrypt(temp, (unsigned char*)response.c_str(), response.length());
	// cout<<"str n3: "<<strnonce3m1<<endl;
	int recv_nonce3m1 = stoi(strnonce3m1);
	cout<<"n3-1: "<<recv_nonce3m1<<endl;
	// Verify N3
	if(recv_nonce3m1 != nonce3 - 1)
	{
		close(cskt);
		exit_with_failure("Incorrect Nonce replied! Could be Man in the Middle(MITM)! Disconnecting...");
	}

	logged_in_users.push_front(make_tuple(user, cskt, make_pair(string(reinterpret_cast<char*>(temp->key)), string(reinterpret_cast<char*>(temp->iv)))));

	cout<<"Authenticated "<<user<<endl;
	payload = "Authenticated!\nEnter Command: ";

	sb = send_enc(cskt, temp, payload);
	
	if(sb < 0)
	{
		generate_sending_error(cskt);
		close(cskt);
		return;
	}

	pair<int, string> content;

	string client_m, command;
	string userid;
	int skt;
	pair<string, string> ktemp;
	while(1)
	{
		
		content = recv_dec(cskt, temp);
		if(content.first == 0)
			generate_client_error(cskt);
		client_m = content.second;
		v = split(client_m, DELIM);
		command = v.at(0);
		cout<<"com: "<<command<<endl;
		if(command == "exit")
			generate_client_error(cskt);
		else if(command == "who")
		{
			response = "Logged in users\n";
			// cout<<"Users: "<<logged_in_users.size()<<endl;
			auto it = logged_in_users.begin();	
			while (it!=logged_in_users.end())
			{
				tie(userid, skt, ktemp) = (*it);
				// unsigned char buf;
				// cout<<"Trying: "<<userid<<endl;
				// rb = recv(skt, &buf,1,MSG_PEEK);
				// if(rb <= 0)
				// {
				// 	it = logged_in_users.erase(it);
				// }
				// else
				// {
					// cout<<"active: "<<userid<<endl;
					response += (userid + "\n");
					it++;
				// }
			}
		}

		response += "Enter Command: ";
		sb = send_enc(cskt, temp, response);
		if(sb < 0)
			generate_sending_error(cskt);
	}
	close(cskt);
}

void chatHandler()
{
	int chatSkt;
	if((chatSkt = socket(AF_INET , SOCK_STREAM , 0)) < 0)
	{
		perror("Socket not created");
		return;
	}
	struct sockaddr_in server_address, client_address;
	memset(&server_address,0,sizeof(server_address));
	server_address.sin_family=AF_INET;
	server_address.sin_port=htons(CHAT_PORT);
	server_address.sin_addr.s_addr=htonl(INADDR_ANY);

	int b = ::bind(chatSkt, (struct sockaddr*)&server_address, sizeof(server_address));
	if(b == -1)
	{
		perror("Binding failed");
		exit(EXIT_FAILURE);
	}
	
	int l = listen(chatSkt, MAXUSERS);
	if(l == -1)
	{
		perror("listening failed");
	   	exit(EXIT_FAILURE);
	}

	cout<<"Chat Server is listening at PORT: "<<CHAT_PORT<<endl;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size;
	
	thread tid[MAXUSERS];
	int i = 0, clientSkt;
	while(1)
	{
		addr_size = sizeof(serverStorage);
		clientSkt = accept(chatSkt, (struct sockaddr*)&client_address, &addr_size);
		if(clientSkt == -1)
		{
			perror("Connection error!");
			exit(-1);
		}
		tid[i++] = std::thread(chatClientHandler, ref(clientSkt));
		if(i >= MAXUSERS)
		{
			i = 0;
			while(i<MAXUSERS)
			{
				tid[i++].join();
			}
			i=0;
		}
	}
}

int main(int argc, char const *argv[])
{

	char pwd_buffer[PATH_MAX];
	getcwd(pwd_buffer, sizeof pwd_buffer);
	PWD = string(strtok(pwd_buffer," \n\r"));

	thread kdc(kdcHandler);
	thread chat(chatHandler);
	// initialise();
	kdc.join();
	chat.join();

	return 0;
}