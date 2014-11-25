/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
#include "config.h"
#include "breakpad.h"
#if defined(WIN32)
#  include "client/windows/handler/exception_handler.h"
#else
#  include "client/linux/handler/exception_handler.h"
#endif
#include <stdlib.h>

using namespace google_breakpad;

// typedef ExceptionHandler::MinidumpCallback MinidumpCallback;
// typedef ExceptionHandler::FilterCallback FilterCallback;

// ExceptionHandler::FilterCallback filter;

// ExceptionHandler::MinidumpCallback callback;


static bool dumpCallback(const google_breakpad::MinidumpDescriptor& descriptor,
                         void* context,
                         bool succeeded) {
	printf("Dump path: %s\n", descriptor.path());
	return succeeded;
}

#if 0
void crash()
{
  volatile int* a = (int*)(NULL);
  *a = 1;
}
#endif

void initialize_breakpad(){

	google_breakpad::MinidumpDescriptor descriptor("/tmp");
	google_breakpad::ExceptionHandler eh(descriptor,
                                       NULL,
                                       dumpCallback,
                                       NULL,
                                       true,
                                       -1);

  //  crash();
	// (void)handler;
}
