/*
 * Buffer.h
 *
 *  Created on: 16 Eyl 2013
 *      Author: hakilic
 */

#ifndef BUFFER_H_
#define BUFFER_H_

namespace Util {

class Buffer {
public:
	static uchar *RotateLeft(uchar *inoutBuf, int bufLen, int n);
	static uchar *RotateRight(uchar *inoutBuf, int bufLen, int n);
	static uchar *Reverse(uchar *inoutBuf, int bufLen);
	static uchar *Not(uchar *inoutBuf, int bufLen);
	static uchar *Xor(uchar* inoutBuf, const uchar *buf1, int bufLen);
	static uchar *Or(uchar* inoutBuf, const uchar *buf1, int bufLen);
	static uchar *And(uchar* inoutBuf, const uchar *buf1, int bufLen);
};

}

#endif /* BUFFER_H_ */
