//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_TYPES_H_
#define _SAFENET_HELPER_TYPES_H_

// TODO __TEST__ tanimi make dosyasında olmali.
#define __TEST__

#define HSM_SLOT_GIB			1
#define HSM_SLOT_GIB_PIN		"1234"
#define GIB_ACTIVE_LMK_INDEX	"ActiveLmkIndex"
#define GIB_LMK_PREFIX			"LMK_"
#define GIB_APPNAME				"GIB"
#define GIB_PUBLIC_KEY_NAME		"PbK_GIB"
#define GIB_PRIVATE_KEY_NAME	"PrK_GIB"

//TODO deprecated TRAK and TREK key names will be constructed random. Defined values used for test purposes.
#define GIB_TREK_NAME			"TREK"
#define GIB_TRAK_NAME			"TRAK"

#define GIB_SIGN_LENGTH					256

#define GIB_SIGN_HASH_CONSTANT 			"3031300d060960864801650304020105000420"
#define GIB_SIGN_HASH_CONSTANT_SIZE 	38

#define GIB_SIGN_SCHEMA_CONSTANT 		"0001"
#define GIB_SIGN_SCHEMA_CONSTANT_SIZE 	4

#define GIB_SIGN_PADDING_END			"00"
#define GIB_SIGN_PADDING_END_SIZE		2

#define GIB_SIGN_PADDING_CONSTANT		'F'

#include <vector>

using namespace std;

typedef std::vector<unsigned char> VectorUChar;
typedef std::vector<char> VectorChar;

typedef struct {
	long 		_lmkIndex;			// G
	VectorUChar	_lmk_TRAK;			// H
	VectorUChar	_lmk_TREK;			// I
	VectorUChar	_kcv_TRAK;			// J
	VectorUChar	_kcv_TREK;			// K
	VectorUChar	_TRMK_TRAK;			// L
	VectorUChar	_TRMK_TREK;			// M
	VectorUChar	_Signature;			// N
} KeyExchangeResponse;

typedef struct {
	long 		_lmkIndex;			// G
	VectorUChar	_lmk_TRAK;  		// H
	VectorUChar	_lmk_TREK;			// I
	VectorUChar	_kcv_TRAK;			// J
	VectorUChar	_kcv_TREK;			// K
	VectorUChar _sha256Data;		// O
	VectorUChar _trek_data;			// P
	VectorUChar _trak_sha256Data;	// Q
} ProcessFirstRequest;

typedef struct {
	VectorUChar _clearData;			// Data
} ProcessFirstResponse;

typedef struct {
	long 		_lmkIndex;			// G
	VectorUChar	_lmk_TRAK;			// H
	VectorUChar	_lmk_TREK;			// I
	VectorUChar	_kcv_TRAK;			// J
	VectorUChar	_kcv_TREK;			// K
	VectorUChar	_data;				// S
} ProcessNextRequest;

typedef struct {
	VectorUChar _treckData;			// U
	VectorUChar _trak_sha256_data;	// V
} ProcessNextResponse;


#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>

extern log4cxx::LoggerPtr g_logger;
extern log4cxx::LoggerPtr g_loggerCryptoki;
extern log4cxx::LoggerPtr g_loggerKey;
extern log4cxx::LoggerPtr g_loggerDataObject;
extern log4cxx::LoggerPtr g_loggerTest;

#endif //_SAFENET_HELPER_TYPES_H_
