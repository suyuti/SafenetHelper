#ifndef _CRYPTOKI_HELPER_TESTS_H_
#define _CRYPTOKI_HELPER_TESTS_H_

#include "gtest/gtest.h"
#include "../../src/cryptokiHelper/CryptokiHelper.h"
#include "../../src/cryptokiHelper/DataObject.h"
#include "../../src/cryptokiHelper/ExceptionCryptoki.h"

class CryptokiHelperTests : public ::testing::Test
{
public:
	class CryptokiHelperEx : public Cryptoki::CryptokiHelper {
	public:
		static void ClearSlot(unsigned long slotId) {
			string pin("1234");
			Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
			pC->close();
			pC->open(slotId, pin);

			int rv;
		    CK_ULONG numObjectsToFind = 500;
		    CK_ULONG numObjectsFound = 0;

		    rv = C_FindObjectsInit(pC->getSessionHandle(), NULL, 0);
		    if (rv != CKR_OK)
		    	return;

		    CK_OBJECT_HANDLE h[500];
		    rv = C_FindObjects(pC->getSessionHandle(), h, numObjectsToFind,  &numObjectsFound);
		    if (rv != CKR_OK) {
		    	return;
		    }

		    rv = C_FindObjectsFinal(pC->getSessionHandle());
		    if (rv != CKR_OK)
		    	return;

		    if (numObjectsFound == 0) {
				pC->close();
		    	return;
		    }

			for (CK_ULONG i = 0; i < numObjectsFound; ++i) {
				C_DestroyObject(pC->getSessionHandle(), h[i]);
			}
			pC->close();
		};
	};
public:
    virtual void SetUp() {
    }

    virtual void TearDown() {
		CryptokiHelperEx::ClearSlot(1L);
    }
};

TEST_F(CryptokiHelperTests, negative_open_slot) {
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long nonExistentSlot = 99L;
			p->open(nonExistentSlot, pin);
			p->close();
		},
		ExceptionCryptoki);
}

TEST_F(CryptokiHelperTests, negative_open_pin) {
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
//
//// Key
//
TEST_F(CryptokiHelperTests, create_key) {
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;
	p->open(slot, pin);
	Cryptoki::KeyAttribute attr;
	Cryptoki::MechanismInfo mInfo;
	attr._token = TRUE;
	mInfo._type = MT_DES2_KEY_GEN;
	p->createKey("TestKey", attr, mInfo);
	p->close();
}

TEST_F(CryptokiHelperTests, create_and_find_token_key) {
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;
	p->open(slot, pin);
	Cryptoki::KeyAttribute attr;
	Cryptoki::MechanismInfo mInfo;
	attr._token = TRUE;
	mInfo._type = MT_DES2_KEY_GEN;
	p->createKey("TokenBasedTestKey", attr, mInfo);
	p->close();

	// find
	p->open(slot, pin);
	Cryptoki::Key k = p->getKeyByName(OC_SECRET_KEY, "TokenBasedTestKey");
	p->close();
}

TEST_F(CryptokiHelperTests, create_and_find_session_key) {
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;
	p->open(slot, pin);
	Cryptoki::KeyAttribute attr;
	Cryptoki::MechanismInfo mInfo;
	attr._token = TRUE;
	mInfo._type = MT_DES2_KEY_GEN;
	p->createKey("SessionBasedTestKey", attr, mInfo);
	// find
	Cryptoki::Key k = p->getKeyByName(OC_SECRET_KEY, "SessionBasedTestKey");
	p->close();
}

TEST_F(CryptokiHelperTests, negative_find_key) {
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long slot = 1L;
			p->open(slot, pin);
			Cryptoki::Key k = p->getKeyByName(OC_SECRET_KEY, "TestKey");
			p->close();
		},
		ExceptionCryptoki);
}

TEST_F(CryptokiHelperTests, negative_create_and_not_found_Session_key) {
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long slot = 1L;
			p->open(slot, pin);
			Cryptoki::KeyAttribute attr;
			Cryptoki::MechanismInfo mInfo;
			attr._token = FALSE;
			mInfo._type = MT_DES2_KEY_GEN;
			p->createKey("SessionBasedTestKey", attr, mInfo);
			p->close();

			// find
			p->open(slot, pin);
			Cryptoki::Key k = p->getKeyByName(OC_SECRET_KEY, "SessionBasedTestKey");
			p->close();
		},
		ExceptionCryptoki);
}

// Data object
TEST_F(CryptokiHelperTests, create_dataObject) {
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;
	p->open(slot, pin);
	unsigned char data[] = {0x01, 0x23, 0x45};
	p->createData("TestApp", "TestData", data, sizeof(data));
	p->close();
}

TEST_F(CryptokiHelperTests, create_and_get_dataObject) {
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;
	p->open(slot, pin);
	unsigned char data[] = {0x01, 0x23, 0x45};
	p->createData("TestApp", "TestData", data, sizeof(data));
	Cryptoki::DataObject d = p->getDataByName("TestApp", "TestData");
	VectorUChar val = d.getValue();
	p->close();
	EXPECT_EQ(sizeof(data), val.size());
	EXPECT_EQ(0, memcmp(data, val.data(), sizeof(data)));
}

TEST_F(CryptokiHelperTests, create_and_get_dataObject_token) {
	char data[] = {0x01, 0x23, 0x45};
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;

	p->open(slot, pin);
	Cryptoki::DataAttribute attr;
	attr._token = TRUE;
	attr._data = data;
	attr._dataLen = sizeof(data);
	p->createData("TestApp", "TestData_token", attr);
	p->close();

	p->open(slot, pin);
	Cryptoki::DataObject d = p->getDataByName("TestApp", "TestData_token");
	VectorUChar val = d.getValue();
	p->close();

	EXPECT_EQ(sizeof(data), val.size());
	EXPECT_EQ(0, memcmp(data, val.data(), sizeof(data)));
}

TEST_F(CryptokiHelperTests, create_and_get_dataObject_session) {
	char data[] = {0x01, 0x23, 0x45};
	EXPECT_THROW(
		{
			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
			std::string pin("1234");
			unsigned long slot = 1L;

			p->open(slot, pin);
			Cryptoki::DataAttribute attr;
			attr._token = FALSE;
			attr._data = data;
			attr._dataLen = sizeof(data);
			p->createData("TestApp", "TestData_session", attr);
			p->close();

			p->open(slot, pin);
			Cryptoki::DataObject d = p->getDataByName("TestApp", "TestData_session");
			p->close();
		},
		ExceptionCryptoki);
}

TEST_F(CryptokiHelperTests, get_set_dataObject) {
	char data[] = {0x01, 0x23, 0x45};
	char newData[] = {0x98, 0x76};
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;

	p->open(slot, pin);
	Cryptoki::DataAttribute attr;
	attr._token = TRUE;
	attr._data = data;
	attr._dataLen = sizeof(data);
	p->createData("TestApp", "TestData_token", attr);
	p->close();

	p->open(slot, pin);
	Cryptoki::DataObject d = p->getDataByName("TestApp", "TestData_token");
	d.setValue(newData, sizeof(newData));
	VectorUChar val = d.getValue();
	p->close();

	EXPECT_EQ(sizeof(newData), val.size());
	EXPECT_EQ(0, memcmp(newData, val.data(), sizeof(newData)));
}

TEST_F(CryptokiHelperTests, get_set_dataObject_2) {
	char data[] = {0x01, 0x23, 0x45};
	char newData[] = {0x98, 0x76};
	Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
	std::string pin("1234");
	unsigned long slot = 1L;

	p->open(slot, pin);
	Cryptoki::DataAttribute attr;
	attr._token 	= TRUE;
	attr._data 		= data;
	attr._dataLen 	= sizeof(data);
	p->createData("TestApp", "TestData_token", attr);
	p->close();

	p->open(slot, pin);
	Cryptoki::DataObject d = p->getDataByName("TestApp", "TestData_token");
	VectorUChar v;
	v.assign(newData, newData + sizeof(newData));
	d.setValue(v);
	VectorUChar val = d.getValue();
	p->close();

	EXPECT_EQ(sizeof(newData), val.size());
	EXPECT_EQ(0, memcmp(newData, val.data(), sizeof(newData)));
}



//TEST_F(CryptokiHelperTests, negative_closed) {
//	EXPECT_THROW(
//		{
//			Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
//			std::string pin("1234");
//			unsigned long slot = 1L;
//			p->open(slot, pin);
//			p->close();
//		},
//		ExceptionCryptoki);
//}
//
//
//TEST_F(CryptokiHelperTests, negative_nonExist_DataObject) {
//	Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
//	//EXPECT_EQ(NULL, pC->getDataObject("GIB", "NonExistDataObject"));
//}
//
//TEST_F(CryptokiHelperTests, create_DataObject) {
//	unsigned char data[] = {0x01, 0x23};
//	EXPECT_NO_THROW(
//	{
//		Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
//		//DataObject* pData = pC->createDataObject("GIB", "Test_Data_Object", data, sizeof(data));
//		//DataObject* pData2 = pC->getDataObject("GIB", "Test_Data_Object");
//		//EXPECT_TRUE(pData != NULL);
//		//EXPECT_TRUE(pData2 != NULL);
//	});
//}
//
//TEST_F(CryptokiHelperTests, getDataObject) {
//	unsigned char data[] = {0x01, 0x23};
//	VectorUChar expected_;
//	expected_.assign(data, data + sizeof(data));
//	VectorUChar retVal;
//
//	Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
//	//DataObject* pData = pC->createDataObject("GIB", "Test_Data_Object", data, sizeof(data));
//	//EXPECT_TRUE(pData != NULL);
//	//retVal = pData->getValue();
//
//		//EXPECT_EQ(expected_.size(), retVal.size());
//}

#endif //_CRYPTOKI_HELPER_TESTS_H_
