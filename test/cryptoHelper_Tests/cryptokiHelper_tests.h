#ifndef _CRYPTOKI_HELPER_TESTS_H_
#define _CRYPTOKI_HELPER_TESTS_H_

#include "gtest/gtest.h"
#include "../../src/cryptokiHelper/CryptokiHelper.h"
#include "../../src/cryptokiHelper/DataObject.h"
#include "../../src/cryptokiHelper/ExceptionCryptoki.h"
#include "cryptokiHelperTestUtil.h"

class CryptokiHelperTests : public ::testing::Test
{
public:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    	CryptokiHelperTestUtil::ClearSlot(1L, "1234");
    }
};

//-----------------------------------------------------------------------------
/**
 * Tries to open non existent slot.
 * Should throw Exception.
 *
 * */

TEST_F(CryptokiHelperTests, negative_open_with_wrong_slot) {
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			unsigned long nonExistentSlot = 99L;
			p->close();
			p->open(nonExistentSlot, "1234");
			p->close();
		},
		ExceptionCryptoki);
}

//-----------------------------------------------------------------------------
/**
 * Tries to open slot with wrong PIN
 * Should throw exception
 *
 * */

TEST_F(CryptokiHelperTests, negative_open_with_wrong_pin) {
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string wrongPin("9999");
			unsigned long slot = 1L;
			p->open(slot, wrongPin);
			p->close();
		},
		ExceptionCryptoki);
}

//-----------------------------------------------------------------------------
/**
 * Should open and login successfully.
 * Should not throw any exception.
 *
 * */

TEST_F(CryptokiHelperTests, open_success) {
	EXPECT_NO_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string wrongPin("1234");
			unsigned long slot = 1L;
			p->open(slot, wrongPin);
			p->close();
		});
}

//-----------------------------------------------------------------------------
/**
 * Should not throw any exception.
 *
 * */

TEST_F(CryptokiHelperTests, close_twice) {
	EXPECT_NO_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string wrongPin("1234");
			unsigned long slot = 1L;
			p->open(slot, wrongPin);
			p->close();
			p->close();
		});
}

//-----------------------------------------------------------------------------

TEST_F(CryptokiHelperTests, sha1sum) {

    char data[] = { 'C', 'R', 'Y', 'P', 'T', 'O', 'K', 'I' };

    char sha1Data[] = { '\xdb', '\x47', '\xc8', '\x57', '\x44', '\x3e', '\x19', '\xab', '\xaa', '\xb5', 
			'\x9d', '\x54', '\x9a', '\xb0', '\x62', '\x5c', '\x61', '\x58', '\xe2', '\xfd' };
    
    EXPECT_NO_THROW(
		    {
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long slot = 1L;
			p->open(slot, pin);
			
			VectorUChar vecSha1 = p->generateSHA1(data, sizeof(data));
			
			p->close();

			EXPECT_EQ(0, memcmp(sha1Data, vecSha1.data(), vecSha1.size()));
		    });
}

//-----------------------------------------------------------------------------

TEST_F(CryptokiHelperTests, sha256sum) {

    char data[] = { 'C', 'R', 'Y', 'P', 'T', 'O', 'K', 'I' };

    char sha256Data[] = { '\xcf', '\xb3', '\xe4', '\xb9', '\x1d', '\xd0', '\x40', '\x81', '\x1b', '\xa8', 
			  '\x3f', '\x24', '\x83', '\xef', '\x16', '\x5b', '\xe1', '\xc0', '\x78', '\x59', 
			  '\x4d', '\x0b', '\x4a', '\x36', '\x67', '\xe3', '\xbd', '\xbe', '\xc9', '\xb9', 
			  '\x0a', '\x35' };
    
    EXPECT_NO_THROW(
		    {
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long slot = 1L;
			p->open(slot, pin);
			
			VectorUChar vecSha256 = p->generateSHA256(data, sizeof(data));
			
			p->close();

			EXPECT_EQ(0, memcmp(sha256Data, vecSha256.data(), vecSha256.size()));
		    });
}

#endif //_CRYPTOKI_HELPER_TESTS_H_
