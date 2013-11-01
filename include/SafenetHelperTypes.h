//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_TYPES_H_
#define _SAFENET_HELPER_TYPES_H_

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

#include <vector>

using namespace std;

typedef std::vector<unsigned char> VectorUChar;
typedef std::vector<char> VectorChar;

typedef struct {
	long 		_lmkIndex;
	VectorUChar	_lmk_TRAK;
	VectorUChar	_lmk_TREK;
	VectorUChar	_kcv_TRAK;
	VectorUChar	_kcv_TREK;
	VectorUChar	_TRMK_TRAK;
	VectorUChar	_TRMK_TREK;
	VectorUChar	_Signature;
} KeyExchangeResponse;

typedef struct {
	long 		_lmkIndex;
	VectorUChar	_lmk_TRAK;
	VectorUChar	_lmk_TREK;
	VectorUChar	_kcv_TRAK;
	VectorUChar	_kcv_TREK;
	VectorUChar _sha256Data;
	VectorUChar _trek_data;
	VectorUChar _trak_sha256Data;
} ProcessRequest;

typedef struct {
	VectorUChar _data;
	VectorUChar _trak_sha256Data;
	VectorUChar _trek_data;
} ProcessResponse;


#include <log4cxx/logger.h>
#include <log4cxx/xml/domconfigurator.h>

extern log4cxx::LoggerPtr g_logger;
extern log4cxx::LoggerPtr g_loggerCryptoki;
extern log4cxx::LoggerPtr g_loggerKey;
extern log4cxx::LoggerPtr g_loggerDataObject;

#endif //_SAFENET_HELPER_TYPES_H_
