#ifndef TREXCEPTION_H_
#define TREXCEPTION_H_

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

class TrException {
  private:
    char*	reason;

  public:
    TrException(const char* r) {
      printf("Exception : %s", r);
      reason	= strdup(r);
    }

    ~TrException() {
      free(reason);
    }

    char* getReason () {
      return reason;
    }
};

#endif // TREXCEPTION_H_
