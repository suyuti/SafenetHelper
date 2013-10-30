#ifndef _SAFENET_ENVIRONMENT_H_
#define _SAFENET_ENVIRONMENT_H_

#include "../src/SafenetHelper.h"

class SafenetEnviroment : public ::testing::Environment {
public:
	SafenetEnviroment() :
		_slot(1L),
		_pin("1234")
	{
	}
  virtual ~SafenetEnviroment() {}
  virtual void SetUp() {
	  SafenetHelper* pS = SafenetHelper::instance();
	  pS->login(_slot, _pin);
	  pS->setup();
  }
  virtual void TearDown() {
	  CryptokiHelperTestUtil::ClearSlot(_slot, _pin, true);
  }
private:
  long 			_slot;
  std::string 	_pin;
};

#endif // _SAFENET_ENVIRONMENT_H_
