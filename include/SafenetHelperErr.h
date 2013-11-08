//---------------------------------------------------------
// Mehmet Suyuti Dindar
// 11.10.2013
// SmartSoft
//---------------------------------------------------------

#ifndef _SAFENET_HELPER_ERR_H_
#define _SAFENET_HELPER_ERR_H_

#define SUCCESS 				0

// input data errors
#define ERR_INPUTDATA_BASE		(1000)
#define ERR_TRAK_KCV_INVALID	(-(ERR_INPUTDATA_BASE + 1))
#define ERR_TREK_KCV_INVALID	(-(ERR_INPUTDATA_BASE + 2))
#define ERR_SHA256DATA_INVALID	(-(ERR_INPUTDATA_BASE + 3))

// HSM key errors
#define ERR_HSM_KEY_BASE		(2000)

#endif// _SAFENET_HELPER_ERR_H_
