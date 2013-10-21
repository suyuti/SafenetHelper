//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#include <iostream>
#include <iomanip>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include "cryptoki.h"
#include "SafenetHelperImpl.h"
#include "../include/SafenetHelperErr.h"
#include "cryptokiHelper/CryptokiHelper.h"

#define HSM_SLOT_GIB		1
#define HSM_SLOT_GIB_PIN	"1234"
#define GIB_ACTIVE_LMK_INDEX	"ActiveLmkIndex"
#define GIB_LMK_PREFIX			"LMK_"
#define GIB_APPNAME				"GIB"

SafenetHelperImpl::SafenetHelperImpl()
{
	std::string pin(HSM_SLOT_GIB_PIN);
	_pCryptoki = Cryptoki::CryptokiHelper::instance();

//	_pCryptoki = CryptokiHelper::instance();
//	_pCryptoki->closeSession();
//	_pCryptoki->openSession(HSM_SLOT_GIB);
//	_pCryptoki->login(pin);
}

int SafenetHelperImpl::login(unsigned long slotId, std::string& pin)
{
	_pCryptoki->close();
	_pCryptoki->open(slotId, pin);
	return SUCCESS;
}

int SafenetHelperImpl::setup()
{
	std::string name(GIB_ACTIVE_LMK_INDEX);
	std::string app(GIB_APPNAME);
	char data[] = {'0','0','0','0'};//{0x00,0x00,0x00};

	Cryptoki::DataAttribute attr;
	attr._application 	= app;
	attr._label 		= name;
	attr._token 		= TRUE;
	attr._private 		= TRUE;
	attr._data 			= data;
	attr._dataLen 		= sizeof(data);
	_pCryptoki->createData(app, name, attr);

	std:string keyName(GIB_LMK_PREFIX "000");
	Cryptoki::MechanismInfo mInfo;
	mInfo._type = MT_DES2_KEY_GEN;

	Cryptoki::KeyAttribute kAttr;
	kAttr._decrypt 		= TRUE;
	kAttr._encrypt 		= TRUE;
	kAttr._extractable 	= FALSE;
	kAttr._keyType 		= KT_DES2;
	kAttr._private 		= TRUE;
	kAttr._sensitive 	= TRUE;
	kAttr._token 		= TRUE;
	kAttr._unwrap 		= TRUE;
	kAttr._wrap 		= TRUE;

	_pCryptoki->createKey(keyName, kAttr, mInfo);

	return SUCCESS;
}

int SafenetHelperImpl::addLmk()
{
	int index = this->getLastLmkIndex();
	index++;

	char lmkName[32] = {0x00};
	sprintf(lmkName, GIB_LMK_PREFIX "%03d", index);

	std::string keyName(lmkName);
	Cryptoki::MechanismInfo mInfo;
	mInfo._type = MT_DES2_KEY_GEN;

	Cryptoki::KeyAttribute kAttr;
	kAttr._decrypt 		= TRUE;
	kAttr._encrypt 		= TRUE;
	kAttr._extractable 	= FALSE;
	kAttr._keyType 		= KT_DES2;
	kAttr._private 		= TRUE;
	kAttr._sensitive 	= TRUE;
	kAttr._token 		= TRUE;
	kAttr._unwrap 		= TRUE;
	kAttr._wrap 		= TRUE;

	_pCryptoki->createKey(keyName, kAttr, mInfo);

	stringstream ss;
	ss << std::setfill('0') << std::setw(4) << index;
	this->setLastLmkIndex(ss.str());

	return SUCCESS;
}



int SafenetHelperImpl::GenerateAES256Key(VectorUChar& key,
										 VectorUChar& kcv)
{
	int index = this->getLastLmkIndex();
	char lmkName[32];
	sprintf(lmkName, GIB_LMK_PREFIX "%03d", index);
	Cryptoki::Key k = _pCryptoki->getKeyByName(OC_SECRET_KEY, string(lmkName));
	// lmkIndex'deki lmk keyi var mi
	// yoksa activeLmk'yi kullan

//	Key _key = _pCryptoki->generateSecretKey(keyName, isTokenObject);

	return SUCCESS;
}

int SafenetHelperImpl::getLastLmkIndex()
{
	Cryptoki::DataObject d = _pCryptoki->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
	VectorUChar val = d.getValue();
	int activeLmkIndex = atol((char*)val.data());
	return activeLmkIndex;
}

int SafenetHelperImpl::setLastLmkIndex(std::string val)
{
	Cryptoki::DataObject d = _pCryptoki->getDataByName(GIB_APPNAME, GIB_ACTIVE_LMK_INDEX);
	d.setValue(val.c_str(), val.length());
	return SUCCESS;
}

