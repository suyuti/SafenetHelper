//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_TYPES_H_
#define _SAFENET_HELPER_TYPES_H_

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

#endif //_SAFENET_HELPER_TYPES_H_
