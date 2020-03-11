#ifndef LOGGER_H
#define LOGGER_H

#include <string>

/*
 * Logger - Manages log file generation
 */

class Logger {
	public:
		Logger();
		~Logger();

		void log(const char *msg);
		void log(std::string msg);
	private:
		std::string logFileName = "server.log";	
		bool checkForLogFile();
};

#endif
