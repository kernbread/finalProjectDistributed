#include <argon2.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <algorithm>
#include <cstring>
#include <list>
#include "PasswdMgr.h"
#include "FileDesc.h"
#include "strfuncts.h"
#include <fstream>
#include <sstream>
#include <iterator>
#include <ostream>
#include <inttypes.h>
#include <random>

const int hashlen = 32;
const int saltlen = 16;

/*
 * Assumptions/Notes
 *
 * Usernames and passwords are limited in length to 1000. Nobody in their right mind makes a 
 * username or password of greater length, so I forbid it in my code :)
 *
 * Also, it is assumed that the file passwd exists already. If it does not, it is expected that an admin
 * would create it first.
 *
 * If you are an admin, simply run 'touch passwd' in order to create the file.
 */


PasswdMgr::PasswdMgr(const char *pwd_file):_pwd_file(pwd_file) {
}


PasswdMgr::~PasswdMgr() {

}

/*******************************************************************************************
 * checkUser - Checks the password file to see if the given user is listed
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkUser(const char *name) {
   std::string hashString;
   std::string saltString;

   // ensure the user isn't trying to do anything nefarious...
   std::string nameStr(name);
   if (nameStr.length() > 1000) {
	std::cout << "User trying to look up username of length > 1000! Aborting, too large." << std::endl;
	return false;
   }

   bool result = findUser(name, hashString, saltString);

   return result;
     
}

/*******************************************************************************************
 * checkPasswd - Checks the password for a given user to see if it matches the password
 *               in the passwd file
 *
 *    Params:  name - username string to check (case insensitive)
 *             passwd - password string to hash and compare (case sensitive)
 *    
 *    Returns: true if correct password was given, false otherwise
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            reading
 *******************************************************************************************/

bool PasswdMgr::checkPasswd(const char *name, const char *passwd) {
	std::string hashStr;
	std::string saltStr;

	if (!findUser(name, hashStr, saltStr))
		return false;

	// make sure user not doing anything nefarious...
	std::string passStr(passwd);
	if (passStr.length() > 1000) {
		std::cout << "User trying to lookup password of size > 1000! Aborting, too large." << std::endl;
		return false;
	}

	std::vector<uint8_t> generatedHash;
	std::vector<uint8_t> generatedSalt; // not used by hashArgon2 funct below

	// compute hash for this user	
	hashArgon2(generatedHash, generatedSalt, passwd, saltStr); 

	std::string generatedHashStr = convertHashToIntegerString(generatedHash);

	// compare generated hash to the one in the passwd file
	if (generatedHashStr.compare(hashStr) == 0)
		return true;

	return false;
}

/*******************************************************************************************
 * changePasswd - Changes the password for the given user to the password string given
 *
 *    Params:  name - username string to change (case insensitive)
 *             passwd - the new password (case sensitive)
 *
 *    Returns: true if successful, false if the user was not found
 *
 *    Throws: pwfile_error if there were unanticipated problems opening the password file for
 *            writing
 *
 *******************************************************************************************/

bool PasswdMgr::changePasswd(const char *name, const char *passwd) {
	// first, check if user exists
	auto found = checkUser(name);
	if (!found) {
		return false;	
	}
	// next, generate a new password hash for the user (also making a new salt FYI)	
	std::vector<uint8_t> generatedHash;
	std::vector<uint8_t> generatedSalt;
	std::string inSalt = "";

	hashArgon2(generatedHash, generatedSalt, passwd, inSalt);

	std::string hashString = convertHashToIntegerString(generatedHash);
	std::string saltString = getSaltString(generatedSalt);

	std::stringstream ss;
	ss << hashString << ":" << saltString;
	std::string passwdString = ss.str();

	// check length of new password to ensure they aren't trying to do something funny...
	if (passwdString.length() > 1000) {
		std::cout << "User trying to enter a password of length > 1000! Aborting, too large." << std::endl;
		return false;
	}

	// next, create a temp file with the line after the provided name replaced with passwdString
	auto tempFile = createTempPasswdFileWithNewPasswordForUser(name, passwdString);

	// finally, replace the old passwd file with the new one
	if (remove(_pwd_file.c_str()) != 0) { // failed to delete old password file
		throw pwfile_error("Failed to replace password file! (1)");
	} else { // successfully deleted old password file, not rename the temp one
		if (rename(_temp_file.c_str(), _pwd_file.c_str()) != 0) 
			throw pwfile_error("Failed to replace password file! (2)");
	}

	return true;
}

/*
 * createTempPasswdFileWithNewPasswordForUser - creates a temporary file with the password line of the 
 * input username changed to the provided new password line.
 * Influence from: https://stackoverflow.com/questions/9505085/replace-a-line-in-text-file
 *
 *   Params: name - string of the name of the user to update password for
 *           newPasswordLine - a new hash:salt combination for the provided user
 *
 *   Returns: handle to the temporary file created.
 *
 *   Throws: pwfile_error exception if unable to open the original passwd file, or if failed to open/write
 *   to the temporary passwd file.
 */
std::ofstream PasswdMgr::createTempPasswdFileWithNewPasswordForUser(const char *name, std::string newPasswordLine) {
	std::string lineToReplace(name);
	std::ifstream passwdFile(_pwd_file.c_str()); // open password file for reading
	std::ofstream tempFile(_temp_file.c_str()); // open temp file for writing

	if(!passwdFile || !tempFile)
		throw pwfile_error("Failed to open password file!");

	std::string tempStr;
	bool found = false;
	while (passwdFile >> tempStr) {
		if (tempStr.compare(lineToReplace) == 0) 
			found = true; // signal for next iteration to replace line
		else if (found) { 
			tempStr = newPasswordLine;
			found = false; // set back to false so we continue copying lines
		}
		tempStr += "\n";
		tempFile << tempStr;
	}

	return tempFile;
}

/*****************************************************************************************************
 * readUser - Taking in an opened File Descriptor of the password file, reads in a user entry and
 *            loads the passed in variables
 * 
 *    Params:  pwfile - FileDesc of password file already opened for reading
 *             name - std string to store the name read in
 *             hash, salt - strings to store the read-in hash and salt respectively
 *
 *    Returns: true if a new entry was read, false if eof reached 
 * 
 *    Throws: pwfile_error exception if the file appeared corrupted
 *
 *****************************************************************************************************/

bool PasswdMgr::readUser(FileFD &pwfile, std::string &name, std::string &hashString, std::string &saltString)
{
	// reading 2 lines at a time; as long as no one tampers w/ passwds, this will work
	// we are guranteed to have an even number of lines (1st line is name, second is hash:salt)
	// so long as the addUser function is used.
	auto bytesRead = pwfile.readStr(name);
	std::string password;
	bytesRead = pwfile.readStr(password);

	// password is a combination of the hash:salt. Lets split that and store into the vectors above...
	std::istringstream ss(password);
	std::string token;

	std::vector<std::string> ssVec;
	while(std::getline(ss, token, ':'))
		ssVec.push_back(token);

	if (ssVec.size() >= 2) {
		hashString = ssVec[0];
		saltString = ssVec[1];
	}

	if (bytesRead == 0) // no more bytes to read
		return false;
	else if (bytesRead == -1) // something went wrong
		throw pwfile_error("Failed to read from passwd file!");
	else
		return true;
}

/*****************************************************************************************************
 * writeUser - Taking in an opened File Descriptor of the password file, writes a user entry to disk
 *
 *    Params:  pwfile - FileDesc of password file already opened for writing
 *             name - std string of the name 
 *             hash, salt - vectors of the hash and salt to write to disk
 *
 *    Returns: bytes written
 *
 *    Throws: pwfile_error exception if the writes fail
 *
 *****************************************************************************************************/

int PasswdMgr::writeUser(FileFD &pwfile, std::string &name, std::vector<uint8_t> &hash, std::vector<uint8_t> &salt)
{
	std::string hashString = convertHashToIntegerString(hash); // convert hash to integer string for storage
	std::string saltString = getSaltString(salt); // get salt as string

	std::stringstream ss;

	// combine hash and salt into following format - hash:salt ; for storage in passwds
	ss << name << "\n" << hashString << ":" << saltString << "\n";
	std::string passwdString = ss.str();

	auto ret = pwfile.writeFD(passwdString);

	// write returns -1 if write failed
	if (ret == -1)
		throw pwfile_error("Failed to write to passwd file!");

	return ss.tellp(); // returns number of bytes written to stream 
}

/*
 * convertHashToIntegerString - Converts a std::vector<uint8_t> hash to a string of integers. This
 * is what is stored in the passwd file for the hash.
 *
 *   Params: hash - vector of hash to convert to string of integers.
 *
 *   Returns: string of integers representing hash.
 */
std::string PasswdMgr::convertHashToIntegerString(std::vector<uint8_t> &hash) {
	std::string hashString;
	for (auto elem : hash) {
		int elemIntVal = static_cast<int>(elem);
		hashString += std::to_string(elemIntVal);
	}

	return hashString;
}

/*
 * getSaltString - Converts a std::vector<uint8_t> salt to a string. This is what is stored in the
 * passwd file for the salt.
 *
 *   Params: salt - vector of salt to convert to string.
 *
 *   Returns: string representation of the salt vector.
 */
std::string PasswdMgr::getSaltString(std::vector<uint8_t> &salt) {
	std::string saltString;
	for (auto elem : salt) 
		saltString += elem;

	return saltString;
}

/*****************************************************************************************************
 * findUser - Reads in the password file, finding the user (if they exist) and populating the two
 *            passed in strings with their hash and salt
 *
 *    Params:  name - the username to search for
 *             hash - string to store the user's password hash
 *             salt - string to store the user's salt string
 *
 *    Returns: true if found, false if not
 *
 *    Throws: pwfile_error exception if the pwfile could not be opened for reading
 *
 *****************************************************************************************************/

bool PasswdMgr::findUser(const char *name, std::string &hashString, std::string &saltString) {
   FileFD pwfile(_pwd_file.c_str());

   if (!pwfile.openFile(FileFD::readfd))
      throw pwfile_error("Could not open passwd file for reading");

   // Password file should be in the format username\n{32 byte hash}{16 byte salt}\n
   bool eof = false;
   while (!eof) {
      std::string uname;

      if (!readUser(pwfile, uname, hashString, saltString)) {
         eof = true;
         continue;
      }

      if (!uname.compare(name)) {
         pwfile.closeFD();
         return true;
      }
   }

   pwfile.closeFD();
   return false;
}


/*****************************************************************************************************
 * hashArgon2 - Performs a hash on the password using the Argon2 library. Implementation algorithm
 *              taken from the http://github.com/P-H-C/phc-winner-argon2 example. 
 *
 *    Params:  dest - the std string object to store the hash
 *             passwd - the password to be hashed
 *	       
 *    Throws: runtime_error if the salt passed in is not the right size
 *****************************************************************************************************/
void PasswdMgr::hashArgon2(std::vector<uint8_t> &ret_hash, std::vector<uint8_t> &ret_salt, 
                           const char *in_passwd, std::string &in_salt) {
	uint8_t hash[hashlen];
	uint8_t salt[saltlen];
	memset(salt, 0x00, saltlen);

	if (in_salt.compare("") != 0) { // get user salt from passwd file
		// copy user supplied salt into salt buffer
		for (unsigned int i=0; i < saltlen; i++)
			salt[i] = static_cast<uint8_t>(in_salt.at(i));
	} else { // generate a salt for user
		std::string str("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"); // random letters/symbols that the salt could compose of
		std::random_device rd;
		std::mt19937 generator(rd());

		std::shuffle(str.begin(), str.end(), generator); // randomize str for salt
		std::string randomString = str.substr(0, saltlen);
		
		// move random string into salt buffer
		for (unsigned int i=0; i < saltlen; i++)
			salt[i] = static_cast<uint8_t>(randomString[i]);
	}	


	uint8_t *pwd = (uint8_t *)strdup(in_passwd);
	uint32_t pwdlen = strlen((char *)pwd);

	uint32_t t_cost = 2;
	uint32_t m_cost = (1<<16); // 64 mebibytes memory usage
	uint32_t parallelism = 1; // number of threads and lanes

	argon2i_hash_raw(t_cost,m_cost,parallelism,pwd,pwdlen,salt,saltlen,hash,hashlen);

	// copy hash and salt into the return vectors
	ret_hash.clear();
	ret_hash.reserve(hashlen);
	ret_salt.clear();
	ret_salt.reserve(saltlen);

	for(unsigned int i=0; i < hashlen; i++)
		ret_hash.push_back(hash[i]);
	for(unsigned int i=0; i < saltlen; i++)
		ret_salt.push_back(salt[i]);	
}

/****************************************************************************************************
 * addUser - First, confirms the user doesn't exist. If not found, then adds the new user with a new
 *           password and salt
 *
 *    Throws: pwfile_error if issues editing the password file
 ****************************************************************************************************/

void PasswdMgr::addUser(const char *name, const char *passwd) {
	auto found = checkUser(name);

	// ensure user isn't trying to do something nefarious	
	std::string nameStr(name);
	std::string passStr(passwd);
	if (nameStr.length() > 1000 || passStr.length() > 1000) {
		std::cout << "User trying to enter a username or password of size > 1000!. Aborting, too large." << std::endl;
		return;
	}


	if (found) { 
		std::cout << "User already exists! Nothing to add." << std::endl;
	} else { // add new user
		FileFD pwfile(_pwd_file.c_str());

		if(!pwfile.openFile(FileFD::appendfd))
			throw pwfile_error("Could not open passwd file for appending!");
		
		// create hashed password and a salt
		std::vector<uint8_t> generatedHash;
		std::vector<uint8_t> generatedSalt;
		std::string inSalt = ""; 

		hashArgon2(generatedHash, generatedSalt, passwd, inSalt);

		std::string nameStr(name);
		// write user&pass:hash to passwds file
		writeUser(pwfile, nameStr, generatedHash, generatedSalt);

		pwfile.closeFD(); 
	}
}

