#include <stdio.h>

#include "logger.h"

namespace Util {
Logger* Logger::_sInstance = NULL;

Logger::Logger()
{
	_sInstance = NULL;
}

Logger* Logger::instance()
{
	if (_sInstance == NULL) {
		_sInstance = new Logger();
	}
	return _sInstance;
}
}
