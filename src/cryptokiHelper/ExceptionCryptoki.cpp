
#include "ExceptionCryptoki.h"
#include <string>
#include <sstream>
#include <iomanip>
#include <iostream>

using namespace std;


PRIVATE STATIC void ExceptionCryptoki::initializeErrorDictionary()
{
	errorDictionary[0x00000000] = "CKR_OK";
	errorDictionary[0x00000001] = "CKR_CANCEL";
	errorDictionary[0x00000002] = "CKR_HOST_MEMORY";
	errorDictionary[0x00000003] = "CKR_SLOT_ID_INVALID";
	errorDictionary[0x00000004] = "CKR_FLAGS_INVALID";
	errorDictionary[0x00000005] = "CKR_GENERAL_ERROR";
	errorDictionary[0x00000006] = "CKR_FUNCTION_FAILED";
	errorDictionary[0x00000007] = "CKR_ARGUMENTS_BAD";
	errorDictionary[0x00000008] = "CKR_NO_EVENT";
	errorDictionary[0x00000009] = "CKR_NEED_TO_CREATE_THREADS";
	errorDictionary[0x0000000A] = "CKR_CANT_LOCK";
	errorDictionary[0x00000010] = "CKR_ATTRIBUTE_READ_ONLY";
	errorDictionary[0x00000011] = "CKR_ATTRIBUTE_SENSITIVE";
	errorDictionary[0x00000012] = "CKR_ATTRIBUTE_TYPE_INVALID";
	errorDictionary[0x00000013] = "CKR_ATTRIBUTE_VALUE_INVALID";
	errorDictionary[0x00000020] = "CKR_DATA_INVALID";
	errorDictionary[0x00000021] = "CKR_DATA_LEN_RANGE";
	errorDictionary[0x00000030] = "CKR_DEVICE_ERROR";
	errorDictionary[0x00000031] = "CKR_DEVICE_MEMORY";
	errorDictionary[0x00000032] = "CKR_DEVICE_REMOVED";
	errorDictionary[0x00000040] = "CKR_ENCRYPTED_DATA_INVALID";
	errorDictionary[0x00000041] = "CKR_ENCRYPTED_DATA_LEN_RANGE";
	errorDictionary[0x00000050] = "CKR_FUNCTION_CANCELED";
	errorDictionary[0x00000051] = "CKR_FUNCTION_NOT_PARALLEL";
	errorDictionary[0x00000052] = "CKR_FUNCTION_PARALLEL";
	errorDictionary[0x00000054] = "CKR_FUNCTION_NOT_SUPPORTED";
	errorDictionary[0x00000060] = "CKR_KEY_HANDLE_INVALID";
	errorDictionary[0x00000061] = "CKR_KEY_SENSITIVE";
	errorDictionary[0x00000062] = "CKR_KEY_SIZE_RANGE";
	errorDictionary[0x00000063] = "CKR_KEY_TYPE_INCONSISTENT";
	errorDictionary[0x00000064] = "CKR_KEY_NOT_NEEDED";
	errorDictionary[0x00000065] = "CKR_KEY_CHANGED";
	errorDictionary[0x00000066] = "CKR_KEY_NEEDED";
	errorDictionary[0x00000067] = "CKR_KEY_INDIGESTABLE";
	errorDictionary[0x00000068] = "CKR_KEY_FUNCTION_NOT_PERMITTED";
	errorDictionary[0x00000069] = "CKR_KEY_NOT_WRAPPABLE";
	errorDictionary[0x0000006A] = "CKR_KEY_UNEXTRACTABLE";
	errorDictionary[0x0000006B] = "CKR_KEY_PARAMS_INVALID";
	errorDictionary[0x00000070] = "CKR_MECHANISM_INVALID";
	errorDictionary[0x00000071] = "CKR_MECHANISM_PARAM_INVALID";
	errorDictionary[0x00000080] = "CKR_OBJECT_CLASS_INCONSISTENT";
	errorDictionary[0x00000081] = "CKR_OBJECT_CLASS_INVALID";
	errorDictionary[0x00000082] = "CKR_OBJECT_HANDLE_INVALID";
	errorDictionary[0x00000090] = "CKR_OPERATION_ACTIVE";
	errorDictionary[0x00000091] = "CKR_OPERATION_NOT_INITIALIZED";
	errorDictionary[0x000000A0] = "CKR_PIN_INCORRECT";
	errorDictionary[0x000000A1] = "CKR_PIN_INVALID";
	errorDictionary[0x000000A2] = "CKR_PIN_LEN_RANGE";
	errorDictionary[0x000000A3] = "CKR_PIN_EXPIRED";
	errorDictionary[0x000000A4] = "CKR_PIN_LOCKED";
	errorDictionary[0x000000B0] = "CKR_SESSION_CLOSED";
	errorDictionary[0x000000B1] = "CKR_SESSION_COUNT";
	errorDictionary[0x000000B2] = "CKR_SESSION_EXCLUSIVE_EXISTS";
	errorDictionary[0x000000B3] = "CKR_SESSION_HANDLE_INVALID";
	errorDictionary[0x000000B4] = "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
	errorDictionary[0x000000B5] = "CKR_SESSION_READ_ONLY";
	errorDictionary[0x000000B6] = "CKR_SESSION_EXISTS";
	errorDictionary[0x000000B7] = "CKR_SESSION_READ_ONLY_EXISTS";
	errorDictionary[0x000000B8] = "CKR_SESSION_READ_WRITE_SO_EXISTS";
	errorDictionary[0x000000C0] = "CKR_SIGNATURE_INVALID";
	errorDictionary[0x000000C1] = "CKR_SIGNATURE_LEN_RANGE";
	errorDictionary[0x000000D0] = "CKR_TEMPLATE_INCOMPLETE";
	errorDictionary[0x000000D1] = "CKR_TEMPLATE_INCONSISTENT";
	errorDictionary[0x000000E0] = "CKR_TOKEN_NOT_PRESENT";
	errorDictionary[0x000000E1] = "CKR_TOKEN_NOT_RECOGNIZED";
	errorDictionary[0x000000E2] = "CKR_TOKEN_WRITE_PROTECTED";
	errorDictionary[0x000000F0] = "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
	errorDictionary[0x000000F2] = "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
	errorDictionary[0x000000F1] = "CKR_UNWRAPPING_KEY_SIZE_RANGE";
	errorDictionary[0x00000100] = "CKR_USER_ALREADY_LOGGED_IN";
	errorDictionary[0x00000101] = "CKR_USER_NOT_LOGGED_IN";
	errorDictionary[0x00000102] = "CKR_USER_PIN_NOT_INITIALIZED";
	errorDictionary[0x00000103] = "CKR_USER_TYPE_INVALID";
	errorDictionary[0x00000104] = "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
	errorDictionary[0x00000105] = "CKR_USER_TOO_MANY_TYPES";
	errorDictionary[0x00000110] = "CKR_WRAPPED_KEY_INVALID";
	errorDictionary[0x00000112] = "CKR_WRAPPED_KEY_LEN_RANGE";
	errorDictionary[0x00000113] = "CKR_WRAPPING_KEY_HANDLE_INVALID";
	errorDictionary[0x00000114] = "CKR_WRAPPING_KEY_SIZE_RANGE";
	errorDictionary[0x00000115] = "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
	errorDictionary[0x00000191] = "CKR_CRYPTOKI_ALREADY_INITIALIZED";
	errorDictionary[0x00000120] = "CKR_RANDOM_SEED_NOT_SUPPORTED";
	errorDictionary[0x00000121] = "CKR_RANDOM_NO_RNG";
	errorDictionary[0x00000130] = "CKR_DOMAIN_PARAMS_INVALID";
	errorDictionary[0x00000150] = "CKR_BUFFER_TOO_SMALL";
	errorDictionary[0x00000160] = "CKR_SAVED_STATE_INVALID";
	errorDictionary[0x00000170] = "CKR_INFORMATION_SENSITIVE";
	errorDictionary[0x00000180] = "CKR_STATE_UNSAVEABLE";
	errorDictionary[0x00000190] = "CKR_CRYPTOKI_NOT_INITIALIZED";
	errorDictionary[0x000001A0] = "CKR_MUTEX_BAD";
	errorDictionary[0x000001A1] = "CKR_MUTEX_NOT_LOCKED";
	errorDictionary[0x100001A1] = "ERROR_MEMORY_ALLOCATION";
	errorDictionary[0x100001A2] = "OBJECT_NOT_FOUND";
}

PUBLIC ExceptionCryptoki::ExceptionCryptoki() throw()
{
	initializeErrorDictionary();
	mExceptionType = 0;

}

PUBLIC ExceptionCryptoki::ExceptionCryptoki(ulong errorCode, const char* file, int line ) throw()
{
	initializeErrorDictionary();
	ostringstream mStatus;
	ostringstream mDescription;
	mExceptionType = errorCode;

	mStatus << "#Cryptoki Exception ";
	mStatus << setw(8) << uppercase << setfill('0') << hex << mExceptionType << dec << " at ";
	mStatus << file << " (" << line << ")" << endl;

	std::string desc = errorDictionary[errorCode];
	if(desc.length() != 0)
		mDescription << "ERROR: " << desc << endl;
	else mDescription <<"ERROR: " << "UNKNOWN ERROR CODE" << endl;

	mMessage = mStatus.str() + mDescription.str();
}

PUBLIC ExceptionCryptoki::ExceptionCryptoki(ulong errorCode, const std::string& message, const char* file, int line ) throw()
{
	initializeErrorDictionary();
	ostringstream mStatus;
	ostringstream mDescription;
	mExceptionType = errorCode;

	mStatus << "#Cryptoki Exception ";
	mStatus << setw(8) << uppercase << setfill('0') << hex << mExceptionType << dec << " at ";
	mStatus << file << " (" << line << ")" << endl;

	std::string desc = errorDictionary[errorCode];
	if(desc.length() != 0)
		mDescription << "ERROR: " << desc;
	else mDescription <<"ERROR: " << "UNKNOWN ERROR CODE";

	mDescription << " " << message << endl;
	mMessage = mStatus.str() + mDescription.str();
}

PUBLIC ExceptionCryptoki::~ExceptionCryptoki() throw()
{
}

PUBLIC const char* ExceptionCryptoki::what() const throw()
{
	return mMessage.c_str();
}

