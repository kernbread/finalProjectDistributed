/****************************************************************************************
 * tcp_server - program that sets up a basic TCP server
 *
 *              **Students should not modify this code! Or at least you can to test your
 *                code, but your code should work with the unmodified version
 *
 ****************************************************************************************/  

#include <stdexcept>
#include <iostream>
#include <getopt.h>
#include "TCPServer.h"
#include "exceptions.h"

using namespace std; 

void displayHelp(const char *execname) {
   std::cout << execname << " [-p <portnum>] [-a <ip_addr>]\n";
   std::cout << "   p: the port to bind the server to\n";
   std::cout << "   a: the IP address to bind the server\n";

}

// global default values
const unsigned short default_port = 9999;
const char default_IP[] = "127.0.0.1";

int main(int argc, char *argv[]) {


   unsigned short port = default_port;
   std::string ip_addr(default_IP);

   // Get the command line arguments and set params appropriately
   int c = 0;
   long portval;
   while ((c = getopt(argc, argv, "p:a:smw")) != -1) {
      switch (c) {
  
      // Set the max number to count up to	    
      case 'p':
	      portval = strtol(optarg, NULL, 10);
	      if ((portval < 1) || (portval > 65535)) {
            std::cout << "Invalid port. Value must be between 1 and 65535";
            std::cout << "Format: " << argv[0] << " [<max_range>] [<max_threads>]\n";
            exit(0);
	      }
	      port = (unsigned short) portval;
	      break;

      // IP address to attempt to bind to
      case 'a':
         ip_addr = optarg; 
         break;

      case '?':
	      displayHelp(argv[0]);
	      break;

      default:
	      std::cout << "Unknown command line option '" << c << "'\n";
	      displayHelp(argv[0]);
	      break;
      }

   }

   // Try to set up the server for listening
   TCPServer server;
   try {
      cout << "Binding server to " << ip_addr << " port " << port << endl;
      server.bindSvr(ip_addr.c_str(), port);

   } catch (invalid_argument &e) 
   {
      cerr << "Server initialization failed: " << e.what() << endl;
      return -1;
   }	   

   cout << "Server established.\n";

   try {
      cout << "Listening.\n";	   
      server.listenSvr();
   } catch (pwfile_error &e) {
      cerr << "Error with the password file. Make sure it exists and is readable/writeable by the server.\n";
      cerr << "Error is: " << e.what() << endl;
      return -1;
   } catch (socket_error &e) {
      cerr << "Unrecoverable socket error. Exiting.\n";
      cerr << "Error is: " << e.what() << endl;
      return -1;
   }


   server.shutdown();

   cout << "Server shut down\n";
   return 0;
}
