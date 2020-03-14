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
#include <queue>

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
   void mainServerThread(int conn, std::string ipAddrStr);

   std::string sanitizeUserInput(const std::string& s);
   void bindSvr(const char *ip_addr, unsigned short port);
   void listenSvr();
   void shutdown();
   void heartbeatThread(int conn);
   bool checkIfIPWhiteListed(std::string ipAddr);
   void sendMessage(int conn, std::string msg);
   std::string receiveMessage(int conn);
   void handleMessage(std::string msg, int conn);

private:
 int sockfd = -1;
 std::vector<int> slaveConns; // vector to hold slave connection id's
 std::vector<int> deadSlaveConns; // vector to hold slave conn's that die; when death detected, conn id added here.
 // once all outbound jobs to this conn are reset, conn id removed from this vector.

 // (slaveNodeId, clientId, numberToFactorize, done, cancelled)) 
 std::vector<std::tuple<int, int, int, bool, bool>> jobs; // current jobs assigned to slave nodes
 std::mutex jobsMutex; 

 // (clientId, numberToFactorize, prime factors of numberToFactorize)
 std::queue<std::tuple<std::string, std::string, std::string>> completedJobs; // queue of all jobs that completed and need to be sent to main server

 sockaddr_in sockaddr;
 Logger logger;
 std::mutex m; // lock for PasswdMgr

 std::string mainServerIpAddress = "127.0.0.2"; // IP address of main server
 int mainServerConnId = -1; // connection ID to main server
 bool mainServerAlive = true;

 int numberOfJobsPerClientReq = 2; // number of jobs for each client request (TODO: need to change this to be based on the number of slave nodes!!!)

 std::mutex m1; // lock for logger
 void log(const char *msg);
 void log(std::string msg);

 // daemon services
 void jmd(); // job management daemon
 void cjd(); // completed jobs daemon

 // utility functions
 std::vector<int> getAvailableSlaveNodeIds(); // returns slave node id's not currently assigned a job
 void markSlaveConnAsDead(int connId); // when we lose connection with a slave node, call this method
 bool checkIfJobCancelled(int inSlaveNodeId); // checks whether a job assigned to a slave node is cannceled 
 void setJobToDone(int inSlaveNodeId); // sets a job with slaveNodeId to done
 std::vector<int> setJobsToCancelled(int inSlaveNodeId, int inClientId, int inNumberToFactorize); // for any job that is not inSlaveNodeId, if it has the same (clientId, numberToFactorize) as inSlaveNodeId, set job to cancelled
};


#endif
