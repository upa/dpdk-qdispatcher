#ifndef _UTIL_H_
#define _UTIL_H_

#include <stdio.h>

#define pr_info(fmt, ...) fprintf(stdout, "INFO:%s(): " fmt,    \
				  __func__, ##__VA_ARGS__)

#define pr_warn(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[33m"     \
				  "WARN:%s(): " fmt "\x1b[0m",  \
				  __func__, ##__VA_ARGS__)

#define pr_err(fmt, ...) fprintf(stderr, "\x1b[1m\x1b[31m"      \
				 "ERR:%s(): " fmt "\x1b[0m",    \
				 __func__, ##__VA_ARGS__)

#define pr_debug(fmt, ...)					\
	do {							\
		if (debug)					\
			fprintf(stdout, "DEBUG:%s(): " fmt,	\
				__func__, ##__VA_ARGS__);	\
	} while (0)


#define min(a, b) (a > b) ? b : a
#define max(a, b) (a > b) ? a : b

#endif /* _UTIL_H_ */
