/*
 * util.h
 *
 *  Created on: Sep 11, 2013
 *      Author: suyuti
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <string>

class util {
public:
	util();
	virtual ~util();

	static int str2bcd(std::string in, unsigned char* pBcdBuffer, int expectedLen = 0);
	static int long2bcd(long in, unsigned char* pBcdBuffer, int expectedLen = 0);

	static std::string toStr(int val, std::string format="D4");
	static std::string toHexStr(const unsigned char *pData, int len, char delimiter= ' ');
};

#endif /* UTIL_H_ */
