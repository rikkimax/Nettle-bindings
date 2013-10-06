#if defined(_WIN64)
	typedef __int64 time_t;
#else
	typedef long time_t;
#endif