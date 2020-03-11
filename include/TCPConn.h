#ifndef TCPCONN_H
#define TCPCONN_H

#include "FileDesc.h"

const int max_attempts = 2;

// Methods and attributes to manage a network connection, including tracking the username
// and a buffer for user input. Status tracks what "phase" of login the user is currently in
class TCPConn 
{
public:
   TCPConn(/* LogMgr &server_log*/);
   ~TCPConn();

   bool accept(SocketFD &server);

   int sendText(const char *msg);
   int sendText(const char *msg, int size);

   void handleConnection();
   void startAuthentication();
   void getUsername();
   void getPasswd();
   void sendMenu();
   void getMenuChoice();
   void setPassword();
   void changePassword();
   
   bool getUserInput(std::string &cmd);

   void disconnect();
   bool isConnected();

   unsigned long getIPAddr() { return _connfd.getIPAddr(); };
   void getIPAddrStr(std::string &buf);
   const char *getUsernameStr() { return _username.c_str(); };

private:


   enum statustype { s_username, s_changepwd, s_confirmpwd, s_passwd, s_menu };

   statustype _status = s_username;

   SocketFD _connfd;
 
   std::string _username; // The username this connection is associated with

   std::string _inputbuf;

   std::string _newpwd; // Used to store user input for changing passwords

   int _pwd_attempts = 0;
};


#endif
