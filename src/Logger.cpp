#include "Logger.h"
#include <iostream>
#include <fstream>
#include "FileDesc.h"
#include <chrono>
#include <ctime>
#include <sstream>
#include <iomanip>
#include <stdio.h>

Logger::Logger() {
}

Logger::~Logger() {
}

bool Logger::checkForLogFile() {
	std::ifstream f(logFileName.c_str());
	return f.good();
}

/*
 * Writes a message to the log file.
 * If the log file doesn't exist, this function creates the log file.
 *
 * Otherwise, if this log file exists, this function appends the message
 * to the log file. 
 *
 * Note! This function is NOT thread safe. Ensure to use a mutex before calling
 * if running in a multi-threaded environment.
 */
void Logger::log(const char *msg) {
	FileFD logFileObj(logFileName.c_str());

	// check if log file exists
	if (!checkForLogFile())
		std::ofstream file(logFileName.c_str());

	if (!logFileObj.openFile(FileFD::appendfd))
		throw std::runtime_error("Failed to open log file for appending!");

	// make a datetime string to append to each log message
	auto now = std::chrono::system_clock::now();
	auto timeT = std::chrono::system_clock::to_time_t(now);
	std::stringstream ss;
	ss << std::put_time(std::localtime(&timeT), "%Y-%m-%d %X");
	std::string timeStr = ss.str();

	std::string msgString = timeStr + " : " + msg + "\n";

	auto ret = logFileObj.writeFD(msgString);
	
	// write returns -1 if write failed
	if (ret == -1)
		throw std::runtime_error("Failed to write to log file!");

	logFileObj.closeFD();
}

/*
 * Wrapper for log function when string provided.
 */
void Logger::log(std::string msg) {
	log(msg.c_str());
}


