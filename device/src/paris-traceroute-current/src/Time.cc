#include "Time.h"

#include "common.h"
#include "TrException.h"

#include <stdlib.h>
#include <errno.h>

Time::Time () {
  int res = gettimeofday(&init_time, NULL);
  if (res != 0) throw TrException(str_log(ERROR, "Init time : %s",
				strerror(errno)));
}

long
Time::getCurrentTime () {
  struct timeval current_time;
  int res = gettimeofday(&current_time, NULL);
  if (res < 0) throw TrException(str_log(ERROR, "Get current time : %s",
				strerror(errno)));
  long diff_sec   = current_time.tv_sec  - init_time.tv_sec;
  long diff_micro = current_time.tv_usec - init_time.tv_usec;
  long diff_total = diff_sec * 1000000 + diff_micro;

  return diff_total;
}

long
Time::getCurrentSeconds () {
	struct timeval current_time;
  int res = gettimeofday(&current_time, NULL);
  if (res < 0) throw TrException(str_log(ERROR, "Get current time : %s",
				strerror(errno)));
  long diff_sec   = current_time.tv_sec  - init_time.tv_sec;
  
  return diff_sec;
}

long
Time::getNormalizedTime (struct timeval *tv) {
	long diff_sec   = tv->tv_sec  - init_time.tv_sec;
  long diff_micro = tv->tv_usec - init_time.tv_usec;
  long diff_total = diff_sec * 1000000 + diff_micro;

  return diff_total;
}
