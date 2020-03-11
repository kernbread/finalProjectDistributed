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
#include <map>

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
   std::string sanitizeUserInput(const std::string& s);
   void bindSvr(const char *ip_addr, unsigned short port);
   void listenSvr();
   void shutdown();
   void heartbeatThread(int conn);
   bool checkIfIPWhiteListed(std::string ipAddr);
   void sendMessage(int conn, std::string msg);
   std::string receiveMessage(int conn);

private:
 int sockfd = -1;
 std::vector<int> slaveConns; // vector to hold slave connection id's
 std::vector<int> deadSlaveConns; // vector to hold slave conn's that die; when death detected, conn id added here.
 // once all outbound jobs to this conn are reset, conn id removed from this vector.

 // (clientId, N) -> vector of prime factors found for N so far
 // initially, vectors<int> = N for a given entry
 std::map<std::tuple<int, int>, std::vector<int>> clientPrimes; 

 // (slaveNodeId, clientId, N, n)) : N = original number to factorize and n = number to pollards rho
 std::vector<std::tuple<int, int, int, int>> jobs; // current jobs assigned to slave nodes

 sockaddr_in sockaddr;
 Logger logger;
 std::mutex m; // lock for PasswdMgr

 std::mutex m1; // lock for logger
 void log(const char *msg);
 void log(std::string msg);


 // daemon services
 void crmd(); // client request management daemon
 void jmd(); // job management daemon

 // utility functions
 std::vector<int> getAvailableSlaveNodeIds(); // returns slave node id's not currently assigned a job
 void insertEntryIntoClientPrimes(int clientId, int N); // used to initially insert an entry into clientPrimes
 void markSlaveConnAsDead(int connId); // when we lose connection with a slave node, call this method
};


#endif
