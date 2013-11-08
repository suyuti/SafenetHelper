/*
 * util.cpp
 *
 *  Created on: Sep 11, 2013
 *      Author: suyuti
 */

#include "util.h"
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <sstream>
#include <string.h>
#include <iomanip>

using namespace std;

util::util() {
}

util::~util() {
}

int util::str2bcd(std::string in, unsigned char* pBcdBuffer, int expectedLen)
{
	int val;
	int i = 0;
	bool firstNibble = false;
	int calcLen = (in.size() / 2) + (in.size() % 2);

	if (expectedLen != 0) {
		memset(pBcdBuffer, 0x00, expectedLen);
		i = expectedLen - calcLen;
	}

	if (in.size() % 2) {
		pBcdBuffer[0] = 0x00;
		firstNibble = true;
	}

	for(std::string::iterator it = in.begin(); it != in.end(); ++it) {
		if (*it >= '0' && *it <= '9') {
			val = *it - '0';
		}
		else if (*it >= 'A' && *it <= 'F') {
			val = *it - 'A' + 0x0A;
		}

		if (firstNibble) {
			pBcdBuffer[i] |= val;
			++i;
		}
		else {
			pBcdBuffer[i] = (val << 4);
		}

		firstNibble = !firstNibble;
	}
	return i;
}

int util::long2bcd(long in, unsigned char* pBcdBuffer, int expectedLen)
{
	std::ostringstream ss;
	ss << in;
	return str2bcd(ss.str(), pBcdBuffer, expectedLen);
}

std::string util::toStr(int val, string format)
{
	std::stringstream ss;

	if (format[0] == 'H')
		ss << std::uppercase << std::hex;
	else if (format[0] == 'O')
		ss << std::oct;
	else ss << std::dec;

	string str = format.substr(1, string::npos);
	int widthCount = atoi( str.c_str() );

	ss << setw(widthCount) << setfill('0');

	ss << val;

	return ss.str();
}

std::string util::toHexStr(const unsigned char* pData, int len, char delimiter)
{
	std::stringstream ss;

	ss << uppercase << std::hex;

	while(len--)
	   ss << setw(2) << setfill('0') << static_cast<int>(*pData++) << delimiter;

	return ss.str();
}
