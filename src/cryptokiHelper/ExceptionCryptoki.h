/*
 * ExceptionCryptoki.h
 *
 *  Created on: 27 Ağu 2013
 *      Author: hakilic
 */

#ifndef EXCEPTIONCRYPTOKI_H_
#define EXCEPTIONCRYPTOKI_H_

#include "CryptokiHelperTypes.h"
#include <exception>
#include <string>
#include <map>

class ExceptionCryptoki: public std::exception {
public:
	const static ulong ERROR_MEMORY_ALLOCATION = 0x100001A1;
	const static ulong OBJECT_NOT_FOUND 	   = 0x100001A2;
	const static ulong ATTRIBUTE_NOT_FOUND 	   = 0x10000012;

	ExceptionCryptoki() throw();
	virtual ~ExceptionCryptoki() throw();
	ExceptionCryptoki(ulong errorCode, const char* file, int line ) throw();
	ExceptionCryptoki(ulong errorCode, const std::string& message, const char* file, int line ) throw();
	const char* what( ) const throw ();
	std::string mMessage;
	uint mExceptionType;
	inline uint getErrorCode() { return mExceptionType;};
private:
	std::map<uint, std::string> errorDictionary;
	void initializeErrorDictionary();
};

#endif /* EXCEPTIONCRYPTOKI_H_ */
