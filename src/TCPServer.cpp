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
			this->clientConns.push_back(connection);
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
 * authenticateClient - engages client to gather username and password. User gets one attempt to enter a 
 * valid username, otherwise connection closes. User gets two attempts to enter valid password for user
 * , otherwise connection closes. 
 *
 *   Params: client - client struct defining the client to survey
 *
 *   Returns: boolean true if authentication success, else false.
 *
 *   Throws: runtime_error if unable to send/receive messages from client.
 */
bool TCPServer::authenticateClient(Client &client) {
	std::string usernamePrompt = "username:\n";
	std::string passwordPrompt = "password:\n";
	unsigned int attempts = 0;

	sendMessage(client.conn, usernamePrompt);
	auto username = receiveMessage(client.conn);
	client.name = username; // populate client name

	m.lock();
	auto userExists = pwm.checkUser(client.name.c_str());
	m.unlock();

	if (!userExists) {
		log("Client " + client.ipAddress + " provided an invalid username of " + username);
		std::string errorMessage = client.name + " is not a valid username. Closing connection.\n";
		sendMessage(client.conn, errorMessage);
		return false;
	} else { // lets try to get a password
		while (attempts < 2) { // give user 2 tries to get password
			sendMessage(client.conn, passwordPrompt);
			auto password = receiveMessage(client.conn);	
		
			m.lock();
			auto validPasswordForUser = pwm.checkPasswd(client.name.c_str(), password.c_str());
			m.unlock();

			if (validPasswordForUser) return true;
			else attempts++;
		}
	}

	if (attempts >=2) {
		log("User " + client.name + " failed to input their password twice. IP address: " + client.ipAddress);
		std::string errorMessage2 = "You provided an incorrect password twice. Closing connection.\n";
		sendMessage(client.conn, errorMessage2);
	}

	return false;
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
 *   Throws: runtime_error if unable to receive message from client.
 */
std::string TCPServer::receiveMessage(int conn) {
	char buffer[2048] = "";
	try {
		auto bytesToRead = read(conn, buffer, sizeof(buffer));
	} catch (std::exception& e) {
		throw std::runtime_error("Failed to read from client socket!");
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

	// start heartbeat thread with client
	std::thread hbThread(&TCPServer::heartbeatThread, this, conn);
	hbThread.detach();

	// authenticate client
	bool authenticated = authenticateClient(client);

	if (!authenticated) {
		close(conn);
		return;
	}
	log("Client " + client.name + " authenticated. IP address is: " + client.ipAddress);

	// send client menu
	auto menuStr = getClientMenu();
	sendMessage(conn, menuStr);

	std::string promptMessage = "\nEnter a command: \n";
	while (true) {
		sendMessage(conn, promptMessage);
		auto userString = receiveMessage(conn);

		auto sanitizedInput = sanitizeUserInput(userString); // sanitize user input

		// respond to user request
		if (sanitizedInput.compare("exit") == 0) // if user wants to exit, break
			break;

		auto response = handleUserString(sanitizedInput, client) + "\n";
		sendMessage(conn, response);
	}

	close(conn);
	log("Closing connection with client " + client.name + ". IP address is :" + ipAddrStr);
}

/*
 * handleUserString - handles client input. Navigation point for how to respond to a client based on their
 * input to the server.
 *
 *   Params: userString - a string of what the client sent to us
 *           client - client object encapsulating client engaged with
 *
 *   Returns: string, which is the response to send back to the client for their request.
 */
std::string TCPServer::handleUserString(std::string userString, Client client) {
	if (userString.compare("hello") == 0) {
		return "hello client!";
	} else if (userString.compare("1") == 0) {
		return this->serverName;
	} else if (userString.compare("2") == 0) {
		char *s = inet_ntoa(sockaddr.sin_addr);
		return (std::string) s;
	} else if (userString.compare("3") == 0) {
		return this->serverOwner;
	} else if (userString.compare("4") == 0) {
		return "Java and Python";
	} else if (userString.compare("5") == 0) {
		return "Bellbrook, Ohio, USA";
	} else if (userString.compare("passwd") == 0) {
		return handlePasswordChange(client);
	} else if (userString.compare("menu") == 0) {
		return getClientMenu();
	} else {
		return "Warning: unknown command: " + userString;
	}
}

/*
 * handlePasswordChange - if user enters passwd, prompts user to enter a new password twice. If the
 * passwords match, calls the password manager to change the password. If user fails to provide same 
 * password twice, this function returns telling them they failed.
 *
 *   Params: client - client object encapsulating client engaged with
 *
 *   Returns: string, which is the response to whether they successfully changed their password or not.
 *
 *   Throws: runtime_error if fail to send/receive from client.
 */
std::string TCPServer::handlePasswordChange(Client client) {
	std::string newPasswordPrompt = "New password:\n";
	std::string newPasswordPrompt2 = "Enter the password again:\n";

	sendMessage(client.conn, newPasswordPrompt);
	auto password1 = receiveMessage(client.conn);
	sendMessage(client.conn, newPasswordPrompt2);
	auto password2 = receiveMessage(client.conn);

	if (password1.compare(password2) != 0) { // passwords don't match
		return "Passwords don't match. Try again.";
	} else { // passwords match, change it!
		m.lock();
		pwm.changePasswd(client.name.c_str(), password1.c_str());
		m.unlock();
		log("Client " + client.name + " successfully changed their password.");
		return "Password successfully changed!";
	}
}

/*
 * getClientMenu - returns a string menu that is used to help the client navigate this app.
 *
 *   Returns: string, which is the menu below.
 */
std::string TCPServer::getClientMenu() {
	std::stringstream ss;

	ss << "Available Commands:\n";
	ss << "hello - displays a greeting\n";
	ss << "1 - displays server name\n";
	ss << "2 - displays server address\n";
	ss << "3 - displays server owner\n";
	ss << "4 - displays server owners favorite programming languages\n";
	ss << "5 - displays server owners location\n";
	ss << "passwd - allows a user to change their password\n";
	ss << "exit - closes connection to server\n";
	ss << "menu - displays this menu of available commands\n";

	return ss.str();
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

/**********************************************************************************************
 * shutdown - Cleanly closes the socket FD.
 *
 *    Throws: socket_error for recoverable errors, runtime_error for unrecoverable types
 **********************************************************************************************/
void TCPServer::shutdown() {
	log("Shutting down server");

	// close all client sockets
	for(int cliConn : this->clientConns)
		close(cliConn);

	// close socket
	close(this->sockfd);
}
