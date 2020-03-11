#ifndef TCPSERVER_H
#define TCPSERVER_H

#include "Server.h"
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <cstdlib> 
#include <unistd.h> 
#include <string>
#include <vector>
#include <thread>
#include "Logger.h"
#include <mutex>
#include "PasswdMgr.h"

/* Structure to hold attributes of a client object */
struct Client {
	std::string name;
	int conn;
	std::string ipAddress;
};

class TCPServer : public Server 
{
public:
   TCPServer();
   ~TCPServer();

   void clientThread(int conn, std::string ipAddrStr);
   std::string getClientMenu();
   std::string handleUserString(std::string userString, Client client);
   std::string sanitizeUserInput(const std::string& s);
   std::string handlePasswordChange(Client client);
   void bindSvr(const char *ip_addr, unsigned short port);
   void listenSvr();
   void shutdown();
   void heartbeatThread(int conn);
   bool checkIfIPWhiteListed(std::string ipAddr);
   void sendMessage(int conn, std::string msg);
   std::string receiveMessage(int conn);

private:
 int sockfd = -1;
 std::vector<int> clientConns;

 sockaddr_in sockaddr;
 std::string serverName = "Brian's server";
 std::string serverOwner = "Brian D. Curran Jr.";
 Logger logger;
 std::mutex m; // lock for PasswdMgr
 PasswdMgr pwm =  PasswdMgr("passwd"); // single instance of password manager
 bool authenticateClient(Client &client);

 std::mutex m1; // lock for logger
 void log(const char *msg);
 void log(std::string msg);
};


#endif
