#include "common.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/// Level minimum of debug message to log
#ifdef DEBUG
static int log_level = INFO;
#else
static int log_level = WARN;
#endif

/// Set the logging level (from DUMP to ERROR)
void
set_log_level (int lvl) {
  log_level = lvl;
}

/// Get the logging level
int
get_log_level () {
  return log_level;
}

/// Return the name of a debug level
const char* lvl2str (int lvl) {
  switch (lvl) {
    case FATAL: return STR_FATAL;
    case ERROR: return STR_ERROR;
    case WARN:  return STR_WARN;
    case INFO:  return STR_INFO;
    case DUMP:  return STR_DUMP;
    default:    return STR_UNKNOW;
  }
}

#define MSGSIZE_MAX 1024
/// Print a log message
void
log_c (int lvl, const char* file, int line, const char* format, ...) {
  va_list va;
  char tmp[MSGSIZE_MAX];

  snprintf(tmp, MSGSIZE_MAX, "[%s](%s, %d)", lvl2str(lvl), file, line);
  tmp[MSGSIZE_MAX-2] = '\n';
  tmp[MSGSIZE_MAX-1] = '\0';

  int length = strlen(tmp);
  va_start(va, format);
  vsnprintf(tmp + length, MSGSIZE_MAX - length, format, va);
  va_end(va);
  tmp[MSGSIZE_MAX-2] = '\n';
  tmp[MSGSIZE_MAX-1] = '\0';

  if (lvl <= ERROR) { 
    fprintf(stderr, "%s\n", tmp);
    fflush(stderr);
  } else {
    fprintf(stderr, "%s\n", tmp);
    fflush(stderr);
  }
}

char str_log_msg[MSGSIZE_MAX];

/// Forge a log message
const char*
str_log_c (int lvl, const char* file, int line, const char* format, ...) {
  va_list va;

  snprintf(str_log_msg, MSGSIZE_MAX, "[%s](%s, %d)", lvl2str(lvl), file, line);
  str_log_msg[MSGSIZE_MAX-2] = '\n';
  str_log_msg[MSGSIZE_MAX-1] = '\0';

  int length = strlen(str_log_msg);
  va_start(va, format);
  vsnprintf(str_log_msg + length, MSGSIZE_MAX - length, format, va);
  va_end(va);
  str_log_msg[MSGSIZE_MAX-2] = '\n';

  return str_log_msg;
}

/// Dump a char array in an hexadecimal notation
void
dumpRawData (int lvl, uint8* data, int len) {
  if (lvl <= log_level) {
    int i = 0;
    while (i < len) {
      if (lvl <= ERROR) {
        if ((i % 8) == 0) fprintf(stderr, "[%s]", lvl2str(lvl));
        fprintf(stderr, "0x%02x ", data[i]);
        if ((i % 8) == 7) fprintf(stderr, "\n");
        fflush(stderr);
      } else {
        if ((i % 8) == 0) fprintf(stdout, "[%s]", lvl2str(lvl));
        fprintf(stdout, "0x%02x ", data[i]);
        if ((i % 8) == 7) fprintf(stdout, "\n");
        fflush(stdout);
      }
      i++;
    }
    if (lvl <= ERROR) fprintf(stderr, "\n");
    else fprintf(stdout, "\n");
  }
}

