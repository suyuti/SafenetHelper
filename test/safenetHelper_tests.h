//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_TESTS_H_
#define _SAFENET_HELPER_TESTS_H_

#include <string>

#include "gtest/gtest.h"
#include "../src/SafenetHelper.h"
#include "../include/SafenetHelperErr.h"
//#include "../src/cryptokiHelper/ExceptionCryptoki.h"

//-----------------------------------------------------------------------
// NOTICE
//
// Slot 1 should be exist on HSM also pin must be '1234'
//-----------------------------------------------------------------------

class SafenetHelperTests : public ::testing::Test {
public:
	static void DeleteAllItems(unsigned long slotId, std::string& pin) {
		// TODO CryptokiHelper ile slotdaki tum itemlerin isimleri alinacak. Daha sonra filtre de eklenebilir.
		// CryptokiHelper* _pC = CryptokiHelper::instance();
	}

};

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, negative_you_cannot_login_into_nonexistent_slot) {
	unsigned long nonExistentSlot = 9999L;
	std::string pin("1234");
	SafenetHelper* pS = SafenetHelper::instance();

	EXPECT_THROW({
		pS->login(nonExistentSlot, pin);
	}, ExceptionCryptoki);
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, negative_wrong_pin_should_throw_exception) {
	unsigned long nonExistentSlot = 1L;
	std::string pin("9999");
	SafenetHelper* pS = SafenetHelper::instance();

	EXPECT_THROW({
		pS->login(nonExistentSlot, pin);
	}, ExceptionCryptoki);
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, should_login) {
	unsigned long existentSlot = 1L;
	std::string pin("1234");
	SafenetHelper* pS = SafenetHelper::instance();

	EXPECT_NO_THROW({
		pS->login(existentSlot, pin);
	});
}

//-----------------------------------------------------------------------

TEST_F(SafenetHelperTests, create_key_token) {
	VectorUChar outKey;
	VectorUChar outKcv;
	int err;
	std::string keyName;
	int lmkIndex = 0;

	SafenetHelper* pS = SafenetHelper::instance();
	err = pS->GenerateAES256Key(keyName, lmkIndex, outKey, outKcv, true);

	EXPECT_EQ(SUCCESS, err);

	// TODO login() seklinde de cagirilabilmeli

	unsigned long slot = 1L;
	std::string pin("1234");
	pS->login(slot, pin);

}

//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------
//-----------------------------------------------------------------------


#endif //_SAFENET_HELPER_TESTS_H_
