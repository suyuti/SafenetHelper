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

#endif //_CRYPTOKI_HELPER_TESTS_H_
