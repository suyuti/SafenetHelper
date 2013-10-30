#ifndef _CRYPTOKIHELPER_H_
#define _CRYPTOKIHELPER_H_

#include <string>
#include "CryptokiHelperTypes.h"
#include "Key.h"
#include "DataObject.h"

namespace Cryptoki {

class CryptokiHelper
{
private:
	CryptokiHelper();
public:
	virtual ~CryptokiHelper();
	static CryptokiHelper* instance();

	void open(unsigned long slot, std::string pin, int sessionType = FLG_RW_SESSION);
	void close();

	// Keys
	Key createKey(const std::string& name, const KeyAttribute& attr, const MechanismInfo& mInfo);
	Key createKey(const std::string& name, const MechanismInfo& mInfo);
	Key createKey(const std::string& name);
	Key createSecretKey(const std::string& name, const KeyAttribute& attr, const MechanismInfo& mInfo);
	KeyPair generateKeyPair(ulong keyLength, std::string pbKeyName, std::string prKeyName, bool isTokenObj);
	Key getKeyByName(ObjectClass objClass, const std::string& name);
	void deleteKey(const std::string& name);

	// Data objects
	DataObject getDataByName(const std::string& appName, const std::string& name);
	DataObject createData(const std::string& appName, const std::string& name, const DataAttribute& attr);
	DataObject createData(const std::string& appName, const std::string& name, const unsigned char* pData, int dataLen);
	DataObject createData(const std::string& appName, const std::string& name, const VectorUChar& data);
	void deleteData(const std::string& name);

	// get
	unsigned long getSessionHandle() const {
		return this->_sessionHandle;
	}
protected:
	void initialize();
	void login(std::string& pin, int userType);

protected:
	unsigned long _sessionHandle;

private:
	static CryptokiHelper* _instance;
};
}
#endif //_CRYPTOKIHELPER_H_
