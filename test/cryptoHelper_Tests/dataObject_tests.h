#ifndef _DATA_OBJECT_TESTS_H_
#define _DATA_OBJECT_TESTS_H_

#include "gtest/gtest.h"
#include "../../src/cryptokiHelper/CryptokiHelper.h"
#include "../../src/cryptokiHelper/DataObject.h"
#include "../../src/cryptokiHelper/ExceptionCryptoki.h"
#include "cryptokiHelperTestUtil.h"

class dataObjectTests : public ::testing::Test {
public:
    virtual void SetUp() {
    }

    virtual void TearDown() {
    	std::string pin("1234");
    	CryptokiHelperTestUtil::ClearSlot(1L, pin);
    }
};

//-----------------------------------------------------------------------------

TEST_F(dataObjectTests, create_dataObject) {
	unsigned char data[] = {0x01, 0x23, 0x45};

	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
		std::string pin("1234");
		unsigned long slot = 1L;
		p->open(slot, pin);
		p->createData("TestApp", "TestData", data, sizeof(data));
		p->close();
	});
}

//-----------------------------------------------------------------------------

TEST_F(dataObjectTests, create_and_get_dataObject) {
	unsigned char data[] = {0x01, 0x23, 0x45};
	EXPECT_NO_THROW({
		Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
		std::string pin("1234");
		unsigned long slot = 1L;
		p->open(slot, pin);
		p->createData("TestApp", "TestData", data, sizeof(data));
		Cryptoki::DataObject d = p->getDataByName("TestApp", "TestData");
		VectorUChar val = d.getValue();
		p->close();
		EXPECT_EQ(sizeof(data), val.size());
		EXPECT_EQ(0, memcmp(data, val.data(), sizeof(data)));
	});
}

//-----------------------------------------------------------------------------

TEST_F(dataObjectTests, create_and_get_dataObject_token) {
	char data[] = {0x01, 0x23, 0x45};
	EXPECT_NO_THROW({
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
	});
}

//-----------------------------------------------------------------------------

TEST_F(dataObjectTests, create_and_get_dataObject_session) {
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
			d.getValue(); // to avoid not used variable warning
			p->close();
		},
		ExceptionCryptoki);
}

//-----------------------------------------------------------------------------


TEST_F(dataObjectTests, get_set_dataObject) {
	char data[] = {0x01, 0x23, 0x45};
	char newData[] = {0x98, 0x76};
	EXPECT_NO_THROW({
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
	});
}
//-----------------------------------------------------------------------------

TEST_F(dataObjectTests, get_set_dataObject_2) {
	char data[] = {0x01, 0x23, 0x45};
	char newData[] = {0x98, 0x76};
	EXPECT_NO_THROW({
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
	});
}
//-----------------------------------------------------------------------------

TEST_F(dataObjectTests, get_dataObject_value_as_str) {
	char data[] = {'1', '2', '3'};
	EXPECT_NO_THROW({
		std::string expected(data, data + sizeof(data));
		Cryptoki::CryptokiHelper* p = Cryptoki::CryptokiHelper::instance();
		std::string pin("1234");
		unsigned long slot = 1L;

		p->open(slot, pin);
		Cryptoki::DataAttribute attr;
		attr._token 	= TRUE;
		attr._data 		= data;
		attr._dataLen 	= sizeof(data);
		p->createData("TestApp", "TestData_token_str", attr);
		p->close();

		p->open(slot, pin);
		Cryptoki::DataObject d = p->getDataByName("TestApp", "TestData_token_str");
		std::string val = d.getValueAsStr();
		p->close();
		EXPECT_EQ(0, val.compare(expected));
	});
}

TEST_F(dataObjectTests, negative_nonExist_DataObject) {
	//Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
	//EXPECT_EQ(NULL, pC->getDataObject("GIB", "NonExistDataObject"));
}
//-----------------------------------------------------------------------------

TEST_F(dataObjectTests, create_DataObject) {
	//unsigned char data[] = {0x01, 0x23};
	EXPECT_NO_THROW(
	{
		//Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
		//DataObject* pData = pC->createDataObject("GIB", "Test_Data_Object", data, sizeof(data));
		//DataObject* pData2 = pC->getDataObject("GIB", "Test_Data_Object");
		//EXPECT_TRUE(pData != NULL);
		//EXPECT_TRUE(pData2 != NULL);
	});
}
//-----------------------------------------------------------------------------

TEST_F(dataObjectTests, getDataObject) {
	unsigned char data[] = {0x01, 0x23};
	VectorUChar expected_;
	expected_.assign(data, data + sizeof(data));
	VectorUChar retVal;

	//Cryptoki::CryptokiHelper* pC = Cryptoki::CryptokiHelper::instance();
	//DataObject* pData = pC->createDataObject("GIB", "Test_Data_Object", data, sizeof(data));
	//EXPECT_TRUE(pData != NULL);
	//retVal = pData->getValue();

		//EXPECT_EQ(expected_.size(), retVal.size());
}

#endif //_DATA_OBJECT_TESTS_H_
