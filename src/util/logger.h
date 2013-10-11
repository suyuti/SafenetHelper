#ifndef _LOGGER_H_
#define _LOGGER_H_

namespace Util {
	class Logger
	{
	private:
		Logger();
		static Logger* _sInstance;
	public:
		static Logger* instance();
	};
}

#endif// _LOGGER_H_
