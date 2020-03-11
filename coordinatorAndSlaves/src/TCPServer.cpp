#include "TCPServer.h"
#include <sstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <regex>
#include "exceptions.h"
#include <iostream>
#include <iterator>
#include <fstream>
#include <vector>
#include <algorithm>

TCPServer::TCPServer() {
}


TCPServer::~TCPServer() {
}

/*
 * Wrapper functions for logging. They use a lock to ensure threads do not attempt to write/read from
 * the log file at the same time.
 */
void TCPServer::log(const char *msg) {
	m1.lock();
	logger.log(msg);
	m1.unlock();
}

void TCPServer::log(std::string msg) {
	m1.lock();
	logger.log(msg);
	m1.unlock();
}

/**********************************************************************************************
 * bindSvr - Creates a network socket and sets it nonblocking so we can loop through looking for
 *           data. Then binds it to the ip address and port
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/
void TCPServer::bindSvr(const char *ip_addr, short unsigned int port) {
	log("Server starting up");

	// create socket
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	// ensure created successfully
	if (sockfd == 0) 
			throw socket_error("Failed to make socket!");
	

	// bind
	sockaddr_in sockaddr;
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = inet_addr(ip_addr);
	sockaddr.sin_port = htons(port);

	int bound = bind(sockfd, (struct sockaddr*)&sockaddr, sizeof(sockaddr));

	// ensure binding succeeds
	if (bound < 0) 
		throw socket_error("Failed to bind to port!");


	this->sockfd = sockfd;
	this->sockaddr = sockaddr;

	// start daemon threads
	std::thread jmdThread(&TCPServer::jmd, this);
	jmdThread.detach();

	// for testing: add job
	insertEntryIntoClientPrimes(1, 15);
	//insertEntryIntoClientPrimes(2, 30); 
}

/**********************************************************************************************
 * listenSvr - Performs a loop to look for connections and create TCPConn objects to handle
 *             them. Also loops through the list of connections and handles data received and
 *             sending of data. 
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/
void TCPServer::listenSvr() {
	int listening;

	while (true) {
		if (this->sockfd != -1) 
			listening = listen(this->sockfd, 10);
		else 
			throw socket_error("Failed to listen on socket!");
		

		// ensure listening successful
		if (listening < 0) 
			throw socket_error("Failed to listen on socket!");

		struct sockaddr_in peerAddr;

		// grab a connection
		auto addrlen = sizeof(this->sockaddr);
		int connection = accept(this->sockfd, (struct sockaddr*)&peerAddr, (socklen_t*)&addrlen);
		char *ipAddress = inet_ntoa(peerAddr.sin_addr);
		std::string ipAddrStr(ipAddress);
		auto port = peerAddr.sin_port;
		
		if (connection < 0) {
			throw socket_error("Failed to get connection!");
		} else {
			// ensure ip address is white listed
			if (!checkIfIPWhiteListed(ipAddrStr)) {
				log("IP address isn't white listed! Refusing connection. IP address is: " + ipAddrStr);
				close(connection); // close the connection
				continue; // skip adding connection
			}

			// start client thread
			log("IP address is on white list. Accepting connection. IP address is: " + ipAddrStr);
			std::thread clientThread(&TCPServer::clientThread, this, connection, ipAddrStr);
			clientThread.detach(); // make thread a daemon
			this->slaveConns.push_back(connection);
		}
	}
}

/*
 * checkIfIPWhiteListed - Checks whitelist file to see if provided ip address is white listed. 
 *
 *   Params: ipAddr - ip address to check
 */
bool TCPServer::checkIfIPWhiteListed(std::string ipAddr) {

	std::ifstream is("whitelist");
	std::vector<std::string> ipAddresses;

	std::copy(std::istream_iterator<std::string>(is), std::istream_iterator<std::string>(),
			std::back_inserter(ipAddresses));
	is.close();
	
	for (auto whitelistedAddr : ipAddresses) {
		if (whitelistedAddr.compare(ipAddr) == 0)
			return true;
	}

	return false;
}

/*
 * heartbeatThread - sends a heartbeat to the client every 3 seconds to ensure stable connection.
 *
 *   Params: conn - the fd of the connection.
 *
 *   Throws: runtime_error if unable to send heart beat.
 */
void TCPServer::heartbeatThread(int conn) {
	std::string hbStr = "HEARTBEAT\n";

	while (true) {
		std::this_thread::sleep_for(std::chrono::seconds(3));

		try {
			send(conn, hbStr.c_str(), hbStr.length(), 0);
		} catch (std::exception& e) {
			throw std::runtime_error("Failed to send heartbeat to client!");
		}
	}
}

/*
 * sendMessage: interface to send messages to a client.
 *
 *   Params: conn - connection fd
 *           msg - message to send to client
 *
 *   Throws: runtime_error if unable to send message to client.
 */
void TCPServer::sendMessage(int conn, std::string msg) {
	try {
		send(conn, msg.c_str(), msg.length(), 0);
	} catch (std::exception& e) {
		throw std::runtime_error("Failed to send message to client!");
	}
}

/*
 * receiveMessage: interface to receive messages from client.
 *
 *   Params: conn - connection fd
 *
 *   Returns "FAILED" if client disconnected
 */
std::string TCPServer::receiveMessage(int conn) {
	char buffer[2048] = "";
	try {
		auto bytesToRead = read(conn, buffer, sizeof(buffer));

		if (bytesToRead < 1) {
			return "FAILED";
		}
	} catch (std::exception& e) {
		return "FAILED";
	}

	std::string userString(buffer);
	
	return userString;
}

/*
 * clientThread: main thread for a client. Starts heartbeat thread with client, authenticates, then, if 
 * authentication successful, allows client to interact with modules.
 *
 *   Params: conn - connection fd
 *           ipAddrStr - string representation of clients ip address
 *
 *   Throws: runtime_error if unable to communicate (upstream and downstream) with client.
 */
void TCPServer::clientThread(int conn, std::string ipAddrStr) {
	Client client;
	client.conn = conn;
	client.ipAddress = ipAddrStr;

	// TODO: start heartbeat thread with client
	//std::thread hbThread(&TCPServer::heartbeatThread, this, conn);
	//hbThread.detach();

	// wait for messages from client
	while (true) {
		auto userString = receiveMessage(conn);

		// check if client still connected
		if (userString.compare("FAILED") == 0)
		{
			markSlaveConnAsDead(conn);
			break; 
		}

		auto sanitizedInput = sanitizeUserInput(userString); // sanitize user input

		std::cout << "received: " << sanitizedInput << " from client " << conn << std::endl;
	}

	log("Closing/lost connection with client " + client.name + ". IP address is :" + ipAddrStr);
}

/*
 * sanitizeUserInput - converts user input into lowercase, removes spaces from beginning/end.
 *
 *   Params: s - string to sanitize
 *
 *   Returns - string, which is parameter s sanitized.
 */
std::string TCPServer::sanitizeUserInput(const std::string& s) {
	// remove leading/trailing white spaces from user input
	// influence from https://www.techiedelight.com/trim-string-cpp-remove-leading-trailing-spaces/
	std::string leftTrimmed = std::regex_replace(s, std::regex("^\\s+"), std::string(""));
	std::string leftAndRightTrimmed = std::regex_replace(leftTrimmed, std::regex("\\s+$"), std::string(""));
	
	// convert string to lowercase
	// influence from https://stackoverflow.com/questions/313970/how-to-convert-stdstring-to-lower-case
	std::transform(leftAndRightTrimmed.begin(), leftAndRightTrimmed.end(), leftAndRightTrimmed.begin(),
    [](unsigned char c){ return std::tolower(c); });

	return leftAndRightTrimmed;
}


// utility functions below...
std::vector<int> TCPServer::getAvailableSlaveNodeIds() {
	std::vector<int> occupiedSlaveNodeIds;
	for (auto const& job : jobs) {
		auto slaveNodeId = std::get<0>(job);

		if (slaveNodeId != -1)
			occupiedSlaveNodeIds.push_back(slaveNodeId);
	}

	// calculate difference between all slave node id's and occupied ones
	std::vector<int> diff;

	auto slaveNodeIds = slaveConns;

	std::sort(slaveNodeIds.begin(), slaveNodeIds.end());
	std::sort(occupiedSlaveNodeIds.begin(), occupiedSlaveNodeIds.end());

	std::set_difference(slaveNodeIds.begin(), slaveNodeIds.end(), occupiedSlaveNodeIds.begin(), occupiedSlaveNodeIds.end(),
        std::inserter(diff, diff.begin()));

	return diff;
}

void TCPServer::insertEntryIntoClientPrimes(int clientId, int N) {
	auto tup = std::make_pair(clientId, N);
	std::vector<int> vec;
	vec.push_back(N); // upon inital placement into client primes, add only N as a divisor

	clientPrimes.insert({tup, vec});

	// then, add a job for this
	auto n = N;
	jobs.push_back(std::make_tuple(-1, clientId, N, n)); // adding -1 for slave node id to signal one needs to be assigned
}

void TCPServer::markSlaveConnAsDead(int connId) {
	deadSlaveConns.push_back(connId); // show that this conn is so outbound jobs assigned to this conn can be re-assigned
	slaveConns.erase(std::remove(slaveConns.begin(), slaveConns.end(), connId)); // remove conn from our list of active slave nodes
}

// Daemon services below...
/**********************************************************************************************
* client request management daemon
* - daemon checking through clientPrimes, checking if prod(vector<int> = N^2). (cpd)
* 	- when this happens, sends msg to main server with prime factorization and remove elem 
*	  from clientPrimes once main server acks receipt
***********************************************************************************************/
void TCPServer::crmd() {
}

/**********************************************************************************************
* job management daemon
* - goes through jobs checks for jobs with slaveId=-1 (means no slave node yet assigned)
*		- assigns an available slave node to entry
*		- sends job to assigned slave
* - if a slave node dies, updates entry with slaveId=failedSlaveId and sets it back to -1
***********************************************************************************************/
void TCPServer::jmd() {
	while (true) {
		for (auto& job : jobs) {
			auto slaveNodeId = std::get<0>(job);
			auto clientId = std::get<1>(job);
			auto N = std::get<2>(job);
			auto n = std::get<3>(job);

			if (slaveNodeId == -1) { // check if no slave node working on this job
				auto availableSlaveNodes = getAvailableSlaveNodeIds();

				// if there are available slave nodes, assign one to this node
				if (availableSlaveNodes.size() > 0) {
					auto newSlaveNodeId = availableSlaveNodes[0];
					auto logStr = "JMD:: Assigned (clientId=" + std::to_string(clientId) + ",N=" + std::to_string(N) + ",n=" +std::to_string(n) + ") to slave node " + std::to_string(newSlaveNodeId);
					log(logStr);
					std::get<0>(job) = newSlaveNodeId;

					// send job to slave node!
					auto messageToSend = std::to_string(clientId) + "|" + std::to_string(N) + "|" + std::to_string(n);
					log("JMD:: Sending message: " + messageToSend + " to slave node " + std::to_string(newSlaveNodeId));
					sendMessage(newSlaveNodeId, messageToSend);
				}
			} else if (std::count(deadSlaveConns.begin(), deadSlaveConns.end(), slaveNodeId)) { // check if this job is assigned to a dead slave node
				auto logStr = "JMD:: Warning! slave node " + std::to_string(slaveNodeId) + " disconnected before we received a response. Resetting job (clientId=" + std::to_string(clientId) + ",N=" + std::to_string(N) + ",n=" + std::to_string(n) + ") back to slave node -1 (for reassignment)";
				log(logStr);
				std::get<0>(job) = -1; // reset back to -1 so it will be reassigned to a slave node that is alive
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep thread
	}
}


/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/
void TCPServer::shutdown() {
	log("Shutting down server");

	// close all client sockets
	for(int slaveConn : this->slaveConns)
		close(slaveConn);

	// close socket
	close(this->sockfd);
}
