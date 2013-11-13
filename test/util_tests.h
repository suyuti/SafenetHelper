#ifndef _UTIL_TESTS_H_
#define _UTIL_TESTS_H_

#include <string>
#include <string>
#include <algorithm>
#include "gtest/gtest.h"
#include "../src/util/util.h"

TEST(UtilTest, pad) {
	unsigned char data[] 		= { 0x12, 0x34, 0x56, 0x78 };
	unsigned char expected[] 	= { 0x12, 0x34, 0x56, 0x78, 0x80, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	EXPECT_NO_THROW({
	    VectorUChar vecData;
	    vecData.assign(data, data + sizeof(data));

	    VectorUChar expectedData;
	    expectedData.assign(expected, expected + sizeof(expected));

	    VectorUChar vecPadded = util::pad(vecData);

	    EXPECT_EQ(expectedData, vecPadded);
	});
}

TEST(UtilTest, unpad) {
	unsigned char expected[] 	= { 0x12, 0x34, 0x56, 0x78 };
	unsigned char paddedData[] 	= { 0x12, 0x34, 0x56, 0x78, 0x80, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
									0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	EXPECT_NO_THROW({
		VectorUChar	expectedData;
		expectedData.assign(expected, expected + sizeof(expected));

		VectorUChar vecPaddedData;
	    vecPaddedData.assign(paddedData, paddedData + sizeof(paddedData));
	    VectorUChar vecData = util::unpad(vecPaddedData);

	    EXPECT_EQ(expectedData, vecData);
	});
}

#endif //_UTIL_TESTS_H_
