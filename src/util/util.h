/*
 * util.h
 *
 *  Created on: Sep 11, 2013
 *      Author: suyuti
 */

#ifndef UTIL_H_
#define UTIL_H_

#include <string>
#include <vector>
#include "../../include/SafenetHelperTypes.h"

#define AES256_BLOCKSIZE 32

class util {
public:
	util();
	virtual ~util();

	static int str2bcd(std::string in, unsigned char* pBcdBuffer, int expectedLen = 0);
	static int long2bcd(long in, unsigned char* pBcdBuffer, int expectedLen = 0);

	static std::string toStr(int val, std::string format="D4");
	static std::string toHexStr(const unsigned char *pData, int len, char delimiter= ' ');

	static VectorUChar pad(const VectorUChar &data);
	static VectorUChar unpad(const VectorUChar &data);
};

#endif /* UTIL_H_ */
