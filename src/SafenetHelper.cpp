//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#include <stdio.h>
#include "SafenetHelper.h"
#include "SafenetHelperImpl.h"
#include "../include/SafenetHelperErr.h"

SafenetHelper* SafenetHelper::_sInstance = NULL;

SafenetHelper::SafenetHelper() :
		_pImpl(new SafenetHelperImpl())
{
}


SafenetHelper::~SafenetHelper()
{
	if (_pImpl != NULL) {
		delete _pImpl;
	}
}

SafenetHelper* SafenetHelper::instance()
{
	if (_sInstance == NULL) {
		_sInstance = new SafenetHelper();
	}
	return _sInstance;
}

int SafenetHelper::login(unsigned long slotId, std::string& pin)
{
	return _pImpl->login(slotId, pin);
}

int SafenetHelper::setup()
{
	return _pImpl->setup();
}

int SafenetHelper::addLmk()
{
	return _pImpl->addLmk();
}


int SafenetHelper::GenerateAES256Key(VectorUChar& key,
									 VectorUChar& kcv)
{
	return _pImpl->GenerateAES256Key(key, kcv);
}

int SafenetHelper::getFisCalNo(const VectorUChar inData, VectorUChar& outData)
{
	return _pImpl->getFisCalNo(inData, outData);
}

int SafenetHelper::getTraek(const VectorUChar pgTrmk, KeyExchangeResponse& outData)
{
	return _pImpl->getTraek(pgTrmk, outData);
}

int SafenetHelper::processFirst(const ProcessFirstRequest& inData, ProcessFirstResponse& outData)
{
	return _pImpl->processFirst(inData, outData);
}

int SafenetHelper::processNext(const ProcessNextRequest& inData, ProcessNextResponse& outData)
{
	return _pImpl->processNext(inData, outData);
}


