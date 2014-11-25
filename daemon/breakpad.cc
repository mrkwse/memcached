/* -*- Mode: C; tab-width: 4; c-basic-offset: 4; indent-tabs-mode: nil -*- */
/*
 *     Copyright 2014 Couchbase, Inc
 *
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 */
#include "config.h"
#include "breakpad.h"
#if defined(WIN32)
#  include "client/windows/handler/exception_handler.h"
#elif defined(APPLE)
/* Check OS X path */
#  include "client/macosx/handler/exeception_handler.h"
#elif defined(linux)
#  include "client/linux/handler/exception_handler.h"
#else
#error Unsupported platform for breakpad, cannot compile.
#endif
#include <stdlib.h>
#include "memcached/extension_loggers.h"

using namespace google_breakpad;

#if defined(WIN32)
  typedef ExceptionHandler::MinidumpCallback MinidumpCallback;
  typedef ExceptionHandler::FilterCallback FilterCallback;

  wchar_t* pipe_name = NULL;
  CustomClientInfo* custom_info = NULL;
  FilterCallback filter;
#endif



static bool dumpCallback(const google_breakpad::MinidumpDescriptor& descriptor,
                         void* context,
                         bool succeeded) {
	get_stderr_logger()->log(EXTENSION_LOG_WARNING, NULL,
                                 "Breakpad caught crash in memcached. Writing crash dump to %s before terminating.",
                                 descriptor.path());
	return succeeded;
}

void initialize_breakpad(){
    #if defined(WIN32) && defined(HAVE_BREAKPAD)
        ExceptionHandler* handler = new ExceptionHandler(L"C:\\dumps\\", filter, dumpCallback, NULL,
                                                         ExceptionHandler::HANDLER_ALL,
                                                         MiniDumpWithDataSegs, pipe_name, custom_info);

    #elif defined(linux) && defined(HAVE_BREAKPAD)
      	google_breakpad::MinidumpDescriptor descriptor("/tmp");
      	ExceptionHandler* handler = new ExceptionHandler(descriptor, /*filter*/NULL, dumpCallback,
                                             /*callback-context*/NULL, /*install_handler*/true, /*server_fd*/-1);

        (void)handler;
    #endif
}
