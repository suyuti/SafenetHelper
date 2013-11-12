#ifndef _UTIL_TESTS_H_
#define _UTIL_TESTS_H_

#include <string>
#include <string>
#include <algorithm>
#include "gtest/gtest.h"
#include "../src/util/util.h"

TEST(UtilTest, pad) {
  //	EXPECT_NO_THROW({
	    unsigned char data[] = { 0x12, 0x34, 0x56, 0x78 };
	    unsigned char paddedData[] = { 0x12, 0x34, 0x56, 0x78, 0x80, 
					   0x00, 0x00, 0x00, 0x00, 0x00, 
					   0x00, 0x00, 0x00, 0x00, 0x00, 
					   0x00 };

	    VectorUChar vecData;
	    vecData.assign(data, data + sizeof(data));
	    VectorUChar vecPadded = util::pad(vecData);

	    EXPECT_EQ(0, memcmp(paddedData, vecPadded.data(), vecPadded.size()));
	    //	  });
}

TEST(UtilTest, unpad) {
  //	EXPECT_NO_THROW({
	    unsigned char data[] = { 0x12, 0x34, 0x56, 0x78 };
	    unsigned char paddedData[] = { 0x12, 0x34, 0x56, 0x78, 0x80, 
					   0x00, 0x00, 0x00, 0x00, 0x00, 
					   0x00, 0x00, 0x00, 0x00, 0x00, 
					   0x00 };

	    VectorUChar vecPaddedData;
	    vecPaddedData.assign(paddedData, paddedData + sizeof(paddedData));
	    VectorUChar vecData = util::unpad(vecPaddedData);

	    EXPECT_EQ(0, memcmp(data, vecData.data(), vecData.size()));
	    //	  });
}

#endif //_UTIL_TESTS_H_
