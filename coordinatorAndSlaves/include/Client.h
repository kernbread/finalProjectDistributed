#ifndef CLIENT_H
#define CLIENT_H

/******************************************************************************************
 * Client - Parent class for student's TCP client 
 *
 *  	   Client(Const): protected so you have to call it from your own constructor or the
 *                      compiler will complain
 *  	   ~Client(Dest): no cleanup required in parent
 *
 *  	   connectTo - your overloaded function should establish a connection to a server
 *                   with the given IP address and port
 *  	   handleConnection - your overloaded function should loop to handle both user
 *                          input from stdin (sending it to the server) and data sent
 *                          by the server itself
 *  	   closeConn - Your overloaded function should cleanly close the connection
 *  	   
 *  	   Exceptions: sub-classes should throw a std::exception with the what string field
 *  	               populated for any issues.
 *
 *****************************************************************************************/

class Client { 
   public:
      virtual ~Client();

      // Overload me!
      virtual void connectTo(const char *ip_addr, unsigned short port) = 0;

      // Overload me!
      virtual void handleConnection() = 0;

      // Overload me!
      virtual void closeConn() = 0;

   protected:

      // Do not forget, your constructor should call this constructor (always a good habit)
      Client();

   private:
 
      // Stuff to be left alone
};

#endif
