/****************************************************************************************
 * my_adduser_main - creates a user account and password from the command prompt
 *
 *              **Students should not modify this code! Or at least you can to test your
 *                code, but your code should work with the unmodified version
 *
 ****************************************************************************************/  

#include <stdexcept>
#include <iostream>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"

using namespace std; 

void displayHelp(const char *execname) {
   std::cout << execname << " <username>\n";
//   std::cout << "   t: maximum number of threads to use\n";
//   std::cout << "   n: calculate primes up to the given range\n";
//   std::cout << "   s: only run in single process mode\n";
//   std::cout << "   m: only run in multithreaded mode\n";
//   std::cout << "   w: skip writing to disk\n";
}


int main(int argc, char *argv[]) {

   // Check the command line input
   if (argc < 2) {
      displayHelp(argv[0]);
      exit(0);
   }

   // Read in the username to add to the password file
   std::string username(argv[1]);

   // Check if the user already exists
   std::vector<uint8_t> hash, salt;
   PasswdMgr pwm("passwd");
   
   if (pwm.checkUser(username.c_str()))
   {
      cerr << "That user already has an account.\n";
      exit(-1); 
   }

   TermFD stdinFD;

   stdinFD.setEchoFD(false);
   std::string passwd1, passwd2;

   bool valid_passwd = false;
   while (!valid_passwd) {
      cout << "\nAdding user\nNew Password: ";
      fflush(stdout);

      stdinFD.readStr(passwd1);
      clrNewlines(passwd1);      

      cout << "\nEnter the password again: ";
      fflush(stdout);      

      stdinFD.readStr(passwd2);
      clrNewlines(passwd2);

      if (passwd2.compare(passwd1) == 0)
         valid_passwd = true;
      else{
         cout << "Passwords must match. Try again.\n";
      } 
   }

   stdinFD.setEchoFD(true);

   pwm.addUser(username.c_str(), passwd2.c_str());
   cout << "User added.\n";
   

   return 0;
}
