/*
 * Buffer.cpp
 *
 *  Created on: 16 Eyl 2013
 *      Author: hakilic
 */

#include <cstring>
#include <algorithm>

#include "../cryptokiHelper/CryptokiHelperTypes.h"
#include "Buffer.h"

namespace Util {

PUBLIC STATIC uchar* Buffer::RotateLeft(uchar* inoutBuf, int bufLen, int n)
{
	while(n--)
	{
		uchar tmp = inoutBuf[0];
		memmove(inoutBuf, inoutBuf+1, bufLen-1);
		inoutBuf[bufLen-1] = tmp;
	}

	return inoutBuf;
}

PUBLIC STATIC uchar* Buffer::RotateRight(uchar* inoutBuf, int bufLen, int n)
{

	while(n--)
	{
		uchar tmp = inoutBuf[bufLen-1];
		memmove(inoutBuf+1, inoutBuf, bufLen-1);
		inoutBuf[0] =tmp;
	}

	return inoutBuf;
}

PUBLIC STATIC uchar* Buffer::Reverse(uchar* inoutBuf, int bufLen)
{
	std::reverse(inoutBuf, inoutBuf+bufLen);
	return inoutBuf;
}

PUBLIC STATIC uchar* Buffer::Not(uchar* inoutBuf, int bufLen)
{
	for(int i=0; i<bufLen; ++i)
		inoutBuf[i] = ~inoutBuf[i];

	return inoutBuf;
}

PUBLIC STATIC uchar* Buffer::Xor(uchar* inoutBuf, const uchar *buf1, int bufLen)
{
	for(int i=0; i<bufLen; ++i)
		inoutBuf[i] ^= buf1[i];

	return inoutBuf;
}

PUBLIC STATIC uchar* Buffer::Or(uchar* inoutBuf, const uchar* buf1, int bufLen)
{
	for(int i=0; i<bufLen; ++i)
		inoutBuf[i] |= buf1[i];

	return inoutBuf;
}

PUBLIC STATIC uchar* Buffer::And(uchar* inoutBuf, const uchar* buf1, int bufLen)
{
	for(int i=0; i<bufLen; ++i)
		inoutBuf[i] &= buf1[i];

	return inoutBuf;
}
} //namespace Util

