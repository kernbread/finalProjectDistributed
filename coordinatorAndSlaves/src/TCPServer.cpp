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
#include <boost/algorithm/string.hpp>
#include <sstream>

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
	std::thread cjdThread(&TCPServer::cjd, this);
	cjdThread.detach();
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
				log("WARN: IP address isn't white listed! Refusing connection. IP address is: " + ipAddrStr);
				close(connection); // close the connection
				continue; // skip adding connection
			}

			log("INFO: IP address is on white list. Accepting connection. IP address is: " + ipAddrStr);

			// determine whether this is a slave node, or the main server connecting...
			if (ipAddrStr.compare(mainServerIpAddress) == 0) { // this is the main server
				mainServerConnId = connection; // remember connection ID of main server
				std::thread mainServerThread(&TCPServer::mainServerThread, this, connection, ipAddrStr);
				mainServerThread.detach(); // make thread a daemon
				log("INFO: connected with main server at " + ipAddrStr);
				mainServerAlive = true;
			} else { // assume this is a slave node...
				// start slave node thread
				std::thread clientThread(&TCPServer::clientThread, this, connection, ipAddrStr);
				clientThread.detach(); // make thread a daemon
				this->slaveConns.push_back(connection);
				log("INFO: connected with slave node at " + ipAddrStr + ":" + std::to_string(port));
			}
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

		log("INFO: received message from slave node " + std::to_string(conn) + ": " + sanitizedInput);

		handleMessage(sanitizedInput, conn);
	}

	log("INFO: closing/lost connection with client " + client.name + ". IP address is :" + ipAddrStr);
}

void TCPServer::mainServerThread(int conn, std::string ipAddrStr) {
	// wait for messages from main server
	while (true) {
		auto message = receiveMessage(mainServerConnId);

		if (message.compare("FAILED") == 0) {  // check if still connected to main server
			log("WARN: lost connection with main server!");
			mainServerAlive = false;
			break;
		}

		auto sanitizedInput = sanitizeUserInput(message);

		log("INFO: received message from main server: " + sanitizedInput);
		
		handleMessage(sanitizedInput, conn);
	}

	log("INFO: closing/lost connection with main server.");
}

/*
	convertDelimitedStringToVector - takes a string and splits it into a vector based on the passed in delimiter.

	Params:
		in - string you want to parse through.
		delimiter - delimiter to break string by.

	Returns:
		A vector of strings.
*/
std::vector<std::string> convertDelimitedStringToVector(std::string in, char delimiter) {
	std::string temp;
	std::stringstream ss(in);
	std::vector<std::string> elems;

	while (std::getline(ss, temp, delimiter)) {
		elems.push_back(temp);
	}

	return elems;
}

void TCPServer::handleMessage(std::string msg, int conn) {
	// split string by message delimiter (|) and load into split message
	std::vector<std::string> splitMessage;
	boost::algorithm::split(splitMessage, msg, boost::is_any_of("|"));

	auto messageType = splitMessage.at(0);

	if (messageType.compare("FACTOR_REQ") == 0) {
		std::string clientId;
		std::string numberToFactorize;
		try {
			clientId = splitMessage.at(1);
			numberToFactorize = splitMessage.at(2);
		} catch (std::exception& e) {
			log("WARN: Failed to receive FACTOR_REQ. Expected message of format FACTOR_REQ|clientId|numberToFactorize, but got: " + msg);
			return;
		}

		// add jobs to jobs vector for request
		for (int i=0; i < numberOfJobsPerClientReq; i++)
			jobs.push_back(std::make_tuple(-1, stoi(clientId), stoi(numberToFactorize), false, false));
		log("INFO: added " + std::to_string(numberOfJobsPerClientReq) + " of following job: (-1, " + clientId + ", " + numberToFactorize + ", " + "false, false)");

	} else if (messageType.compare("POLLARD_RESP") == 0) {
		std::string slaveNodeId;
		std::string clientId;
		std::string numberToFactorize;
		std::string primes;

		try {
			slaveNodeId = splitMessage.at(1);
			clientId = splitMessage.at(2);
			numberToFactorize = splitMessage.at(3);
			primes = splitMessage.at(4);
		} catch (std::exception& e) {
			log("WARN: failed to receive POLLARD_RESP. Expected message of format POLLARD_RESP|slaveConnId|clientId|numberToFactorize|prime1,prime2,...,primeN, but got: " + msg);
			return;
		}

		jobsMutex.lock();
		if (!checkIfJobCancelled(stoi(slaveNodeId))) { // make sure this job wasn't cancelled before doing the following...
			// set job to done in jobs
			setJobToDone(stoi(slaveNodeId)); 

			// set all other jobs with this (clientId, numberToFactorize) pair to cancelled
			auto cancelledSlaveNodeIds = setJobsToCancelled(stoi(slaveNodeId), stoi(clientId), stoi(numberToFactorize));
			jobsMutex.unlock(); // releasing lock as soon as possible to avoid bottleneck

			// send cancellation requests to cancelled nodes
			for (auto cancelledNodeId : cancelledSlaveNodeIds) {
				auto cancellationMessage = "CANCEL_REQ|" + std::to_string(cancelledNodeId);
				sendMessage(cancelledNodeId, cancellationMessage);
				log("DEBUG: sent cancellation message to slave with node id: " + std::to_string(cancelledNodeId));
			}

			// add record to completed jobs
			completedJobs.push(std::make_tuple(clientId, numberToFactorize, primes));
			log("INFO: added (clientId=" + clientId + ",numberToFactorize=" + numberToFactorize + ",primes=" + primes + ") to completed jobs.");
		} else {
			jobsMutex.unlock();
		}
	} else if (messageType.compare("CANCEL_RESP") == 0) {
		std::string slaveNodeId;

		try {
			slaveNodeId = splitMessage.at(1);
		} catch (std::exception& e) {
			log("WARN: failed to receive CANCEL_RESP. Expected message of format CANCEL_RESP|slaveConnId, but got: " + msg);
			return;
		}

		// mark job as done
		jobsMutex.lock();
		setJobToDone(stoi(slaveNodeId));
		jobsMutex.unlock();
	} else { // unknown message type
		log("WARN: Unknown message type in message. Cannot handle! Message was: " + msg);
	}
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

void TCPServer::markSlaveConnAsDead(int connId) {
	deadSlaveConns.push_back(connId); // show that this conn is so outbound jobs assigned to this conn can be re-assigned
	slaveConns.erase(std::remove(slaveConns.begin(), slaveConns.end(), connId)); // remove conn from our list of active slave nodes
}

bool TCPServer::checkIfJobCancelled(int inSlaveNodeId) {
	for (auto& job : jobs) {
		auto slaveNodeId = std::get<0>(job);
		auto cancelled = std::get<4>(job);

		if (slaveNodeId == inSlaveNodeId)
			return cancelled;
	}

	log("DEBUG: when checking if job assigned to slave node " + std::to_string(inSlaveNodeId) + " was cancelled, failed to find a job in jobs with this slave node id");
	return false; // otherwise, no entry found, so a non-existent job can't be cancelled...
}

/*
	This method should be mutexed with jobsMutex before calling!
*/
void TCPServer::setJobToDone(int inSlaveNodeId) {
	for (auto& job : jobs) {
		auto slaveNodeId = std::get<0>(job);

		if (slaveNodeId == inSlaveNodeId) {
			std::get<3>(job) = true; // set job to complete
			return;
		} 
	}

	log("DEBUG: when trying to set job to done for slave node " + std::to_string(inSlaveNodeId) + ", failed to find a job in jobs with this slave node id");
}

/*
	This method should be mutexed with jobsMutex before calling!
*/
std::vector<int> TCPServer::setJobsToCancelled(int inSlaveNodeId, int inClientId, int inNumberToFactorize) {
	std::vector<int> cancelledSlaveNodeIds;
	for (auto& job : jobs) {
		auto slaveNodeId = std::get<0>(job);
		auto clientId = std::get<1>(job);
		auto numberToFactorize = std::get<2>(job);

		if (slaveNodeId != inSlaveNodeId && clientId == inClientId && numberToFactorize == inNumberToFactorize) {
			std::get<4>(job) = true; // set job to cancelled
			log("DEBUG: cancelling job (slaveNodeId=" + std::to_string(slaveNodeId) + ",clientId=" + std::to_string(clientId) + ",numberToFactorize=" + std::to_string(numberToFactorize) + ") ");
			cancelledSlaveNodeIds.push_back(slaveNodeId);
		}
	}

	return cancelledSlaveNodeIds;
}

// Daemon services below...

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
			auto numberToFactorize = std::get<2>(job);
			auto done = std::get<3>(job);
			auto cancelled = std::get<4>(job);

			// check if no slave node working on this job, and that this job wasn't done or cancelled
			if (slaveNodeId == -1 && !done && !cancelled) { 
				auto availableSlaveNodes = getAvailableSlaveNodeIds();

				// if there are available slave nodes, assign one to this job
				if (availableSlaveNodes.size() > 0) {
					auto newSlaveNodeId = availableSlaveNodes[0];
					auto logStr = "INFO: JMD :: assigned (clientId=" + std::to_string(clientId) + ", numberToFactorize=" + std::to_string(numberToFactorize) + ", done=" + std::to_string(done) + ", cancelled=" + std::to_string(cancelled) + ") to slave node " + std::to_string(newSlaveNodeId);
					log(logStr);

					jobsMutex.lock();
					std::get<0>(job) = newSlaveNodeId; // assign new slave node id to job
					jobsMutex.unlock();

					// send job to slave node!
					auto messageToSend = "POLLARD_REQ|" + std::to_string(newSlaveNodeId) + "|" + std::to_string(clientId) + "|" + std::to_string(numberToFactorize);
					log("INFO: JMD :: sending message: " + messageToSend + " to slave node " + std::to_string(newSlaveNodeId));
					sendMessage(newSlaveNodeId, messageToSend);
				}
			} else if (std::count(deadSlaveConns.begin(), deadSlaveConns.end(), slaveNodeId)) { // check if this job is assigned to a dead slave node
				auto logStr = "WARN: JMD:: slave node " + std::to_string(slaveNodeId) + " disconnected before we received a response. Resetting job (clientId=" + std::to_string(clientId) + ", numberToFactorize=" + std::to_string(numberToFactorize) + ", done=" + std::to_string(done) + ", cancelled=" + std::to_string(cancelled) + ") back to slave node -1 (for reassignment)";
				log(logStr);

				jobsMutex.lock();
				std::get<0>(job) = -1; // reset back to -1 so it will be reassigned to a slave node that is alive
				jobsMutex.unlock();
			} else if (done) { // remove job if it is complete
				jobsMutex.lock();
				jobs.erase(std::remove(jobs.begin(), jobs.end(), job));
				jobsMutex.unlock();
				log("DEBUG: JMD :: removed job (clientId=" + std::to_string(clientId) + ", numberToFactorize=" + std::to_string(numberToFactorize) + ", done=" + std::to_string(done) + ", cancelled=" + std::to_string(cancelled) + ") from jobs. Adding to completed jobs.");
			}
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(100)); // sleep thread
	}
}

void TCPServer::cjd() {
	while (true) {
		if (!completedJobs.empty()) {
			auto completedJob = completedJobs.front();
			completedJobs.pop();

			auto clientId = std::get<0>(completedJob);
			auto numberToFactorize = std::get<1>(completedJob);
			auto primes = std::get<2>(completedJob);

			auto messageToSend = "FACTOR_RESP|" + clientId + "|" + numberToFactorize + "|" + primes;

			if (mainServerAlive) {
				sendMessage(mainServerConnId, messageToSend);
				log("INFO: CJD:: sent message to main server: " + messageToSend);
			} else {
				completedJobs.push(completedJob); // add job back to queue for resending
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
