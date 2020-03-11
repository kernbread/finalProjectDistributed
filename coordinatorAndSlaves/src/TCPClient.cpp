#include "TCPClient.h"
#include <thread>
#include <ctime>
#include <regex>
#include "exceptions.h"

/**********************************************************************************************
 * TCPClient (constructor) - Creates a Stdin file descriptor to simplify handling of user input. 
 *
 **********************************************************************************************/

TCPClient::TCPClient() {
}

/**********************************************************************************************
 * TCPClient (destructor) - No cleanup right now
 *
 **********************************************************************************************/

TCPClient::~TCPClient() {

}

/**********************************************************************************************
 * connectTo - Opens a File Descriptor socket to the IP address and port given in the
 *             parameters using a TCP connection.
 *
 *    Throws: socket_error exception if failed. socket_error is a child class of runtime_error
 **********************************************************************************************/

void TCPClient::connectTo(const char *ip_addr, unsigned short port) {
	// create socket
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);

	if (sockfd == 0) 
		throw socket_error("Failed to make socket!");

	// BELOW IS FOR TESTING PURPOSES ONLY!	
	// explicitly set client ip address
	if (clientTestMode) {
		struct sockaddr_in myAddr;
		myAddr.sin_family = AF_INET;
		myAddr.sin_addr.s_addr = inet_addr("127.0.0.6");
	
		if (bind(sockfd, (struct sockaddr*) &myAddr, sizeof(struct sockaddr_in)) == 0) 
			std::cout << "Bound client" << std::endl;
		else
			std::cout << "Failed to bind client" << std::endl;

	}

	// connect to server
	this->server.sin_addr.s_addr = inet_addr(ip_addr);
	this->server.sin_family = AF_INET;
	this->server.sin_port = htons(port);
	int connection = connect(sockfd, (struct sockaddr*)&this->server, sizeof(this->server));

	if (connection < 0) 
		throw socket_error("Failed to connect to server!");
	
	this->sockfd = sockfd;

	// start receiving thread
	std::thread receivingThread(&TCPClient::receivingThread, this);
	receivingThread.detach(); // make thread a daemon

	// start sending thread
	std::thread sendingThread(&TCPClient::sendingThread, this);
	sendingThread.detach(); // make thread a daemon
}

/**********************************************************************************************
 * handleConnection - Performs a loop that checks if the connection is still open, then 
 *                    looks for user input and sends it if available. Finally, looks for data
 *                    on the socket and sends it.
 * 
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/

void TCPClient::handleConnection() {

	while (!connClosed && !connectionBroke) {
		// check if we got any new messages from the server
		this->mtx1.lock();
		if(!this->receivedMessages.empty()) {
			auto message = this->receivedMessages.front();
			
			if (sanitizeUserInput(message).compare("") != 0) // only display messages that have data
				std::cout << std::endl << message;

			this->receivedMessages.pop();
		}
		this->mtx1.unlock();
	}

	// check for broken connection
	if (this->connectionBroke) 
		throw std::runtime_error("Failed to receive heartbeat from server for 8 seconds!");
}

bool TCPClient::sendData(std::string data) {
	if (send(this->sockfd, data.c_str(), data.length(), 0) < 0) {
		std::cout << "Failed to send.\n";
		return false;
	}
	return true;
}

std::string TCPClient::receiveData() {
	char buffer[2048] = "";

	if (recv(sockfd, buffer, sizeof(buffer), 0) < 0) {
		std::cout << "Failed to receive.\n";
	}

	std::string response(buffer);

	return response;
}

void TCPClient::receivingThread() {
	while (!connClosed && !connectionBroke) {
		auto response = receiveData();

		// check for heartbeat from server
		std::chrono::system_clock::time_point now = std::chrono::system_clock::now(); // get current time
		if (response.compare("HEARTBEAT\n") == 0) {
			this->lastTimeHeartBeatReceived = now;
			continue; // don't push HB's to end user
		} else { // check if it has been > 8 seconds since last hb
			if (now - this->lastTimeHeartBeatReceived > std::chrono::seconds(8))
				this->connectionBroke = true; // signal we have a broken connection
		}

		this->mtx1.lock();
		this->receivedMessages.push(response);
		this->mtx1.unlock();
	}
}

void TCPClient::sendingThread() {
	while (!connClosed && !connectionBroke) {
		std::string clientMessage;
		std::cin >> clientMessage;

		auto sent = sendData(clientMessage);

		if (sanitizeUserInput(clientMessage).compare("exit") == 0 || !sent) {
			this->connClosed = true;
			break;
		}
	}
}

std::string TCPClient::sanitizeUserInput(const std::string& s) {
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

/**********************************************************************************************
 * closeConnection - Your comments here
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/
void TCPClient::closeConn() {
	close(sockfd);
}


