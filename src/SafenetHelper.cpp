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

