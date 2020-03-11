#ifndef PASSWDMGR_H
#define PASSWDMGR_H

#include <string>
#include <stdexcept>
#include "FileDesc.h"
#include <vector>
#include <fstream>

/****************************************************************************************
 * PasswdMgr - Manages user authentication through a file
 *
 ****************************************************************************************/

class PasswdMgr {
   public:
      PasswdMgr(const char *pwd_file);
      ~PasswdMgr();

      bool checkUser(const char *name);
      bool checkPasswd(const char *name, const char *passwd);
      bool changePasswd(const char *name, const char *newpassd);
   
      void addUser(const char *name, const char *passwd);
 
      void hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, const char *passwd, std::string &in_salt);

   private:
      bool findUser(const char *name, std::string &hashString, std::string &saltString);
      bool readUser(FileFD &pwfile, std::string &name, std::string &hashString, std::string &saltString);
      int writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt);
      std::string convertHashToIntegerString(std::vector<uint8_t> &hash);
      std::string getSaltString(std::vector<uint8_t> &salt);

      std::string _pwd_file;
      std::string _temp_file = "temp_passwd";

      std::vector<std::string> splitPasswdFileLine(std::string line);
      std::ofstream createTempPasswdFileWithNewPasswordForUser(const char *name, std::string newPassword);
};

#endif
