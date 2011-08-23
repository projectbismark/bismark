#ifndef __COMMON_H__
#define __COMMON_H__

//#define USEPCAP 1

#include <sys/time.h>

/* Some basic type definitions */
typedef unsigned int	uint32;
typedef signed   int	sint32;
typedef unsigned short	uint16;
typedef signed   short	sint16;
typedef unsigned char	uint8;
typedef signed   char	sint8;

// Debug stuffs

// Log levels
#define FATAL	0	// Log "fatal error" messages, abord
#define ERROR	1	// Log "error" messages, continue
#define WARN	2	// Log "warning" and "todo" messages
#define INFO	3	// Log "info" messages	( -quiet )
#define DUMP	4	// Log "debug" messages	( -v )

void set_log_level (int lvl);
int  get_log_level ();

#define STR_FATAL	"FATAL"
#define STR_ERROR	"ERROR"
#define STR_WARN	"WARN"
#define STR_INFO	"INFO"
#define STR_DUMP	"DEBUG"
#define STR_UNKNOW	"UNKNOW"
const char* lvl2str (int lvl);

/* Log functions
 *
 * lvl  : severity level of the message
 * args : message in a 'printf' friendly form
 */
#ifdef __GNUC__
void log_c (int lvl, const char* file, int line, const char* format, ...)
		__attribute__ ((format (printf, 4, 5)));
#define log(lvl, args... ) \
	if (lvl <= get_log_level()) log_c(lvl, __FILE__, __LINE__, ## args )

const char* str_log_c (int lvl, const char* file, int line,
	const char* format, ...) __attribute__ ((format (printf, 4, 5)));
#define str_log(lvl, args...) str_log_c(lvl, __FILE__, __LINE__, ## args )

#else // __GNUC__
void log_c (int lvl, const char* file, int line, const char* format, ...);
#define log(lvl, ...) \
	if (lvl <= get_log_level()) log_c(lvl, __FILE__, __LINE__, __VA_ARGS__)
const char* str_log_c (int lvl, const char* file, int line,
	const char* fortmat, ...);
#define str_log(lvl, ...) str_log_c(lvl, __FILE__, __LINE__, __VA_ARGS__)
#endif // __GNUC__

void dumpRawData (int lvl, uint8* data, int len);

#endif // __COMMON_H__
