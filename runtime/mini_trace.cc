/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mini_trace.h"


#include <fstream>
#include <sys/uio.h>
#include <grp.h>
#include <unistd.h>

#include "base/stl_util.h"
#include "base/unix_file/fd_file.h"
#include "class_linker.h"
#include "common_throws.h"
#include "debugger.h"
#include "mirror/object_array-inl.h"
#include "mirror/object-inl.h"
#include "os.h"
#include "scoped_thread_state_change.h"
#include "ScopedLocalRef.h"
#include "thread.h"
#include "thread_list.h"
#include "private/android_filesystem_config.h"
#if !defined(ART_USE_PORTABLE_COMPILER)
#include "entrypoints/quick/quick_entrypoints.h"
#endif

#include <sys/socket.h>
#include <sys/un.h>
#include <endian.h>
#include "ringbuf.h"

namespace art {

enum MiniTraceAction {
    kMiniTraceMethodEnter = 0x00,       // method entry
    kMiniTraceMethodExit = 0x01,        // method exit
    kMiniTraceUnroll = 0x02,            // method exited by exception unrolling
    kMiniTraceFieldRead = 0x03,         // field read
    kMiniTraceFieldWrite = 0x04,        // field write
    kMiniTraceMonitorEnter = 0x05,      // monitor enter
    kMiniTraceMonitorExit = 0x06,       // monitor exit
    kMiniTraceExceptionCaught = 0x07,   // exception caught
    kMiniTraceActionMask = 0x07,        // three bits
};

enum MiniTraceEventLength {
  kMiniTraceMethodEventLength = 6,
  kMiniTraceFieldEventLength = 14,
  kMiniTraceMonitorEventLength = 10,
  kMiniTraceLargestEventLength = kMiniTraceFieldEventLength,
};

MiniTrace* volatile MiniTrace::the_trace_ = NULL;

#if _BYTE_ORDER == _LITTLE_ENDIAN

static void Append2LE(char* buf, uint16_t val) {
  *(uint16_t *)buf = val;
}

static void Append4LE(char* buf, uint32_t val) {
  *(uint32_t *)buf = val;
}

#else /* _BYTE_ORDER == _BIG_ENDIAN */
static_assert(_BYTE_ORDER == _BIG_ENDIAN);

static void Append2LE(char* buf, uint16_t val) {
  *buf++ = static_cast<char>(val);
  *buf++ = static_cast<char>(val >> 8);
}

static void Append4LE(char* buf, uint32_t val) {
  *buf++ = static_cast<char>(val);
  *buf++ = static_cast<char>(val >> 8);
  *buf++ = static_cast<char>(val >> 16);
  *buf++ = static_cast<char>(val >> 24);
}

#endif /* _BYTE_ORDER */

static int read_with_timeout (int socket_fd, void *buf, int size, int timeout_sec) {
  int total_written = 0;
  int written;
  if (timeout_sec <= 0 || timeout_sec > 10) {
    return 0;
  }
  uint32_t run_until = (uint32_t) time(NULL) + timeout_sec;
  int attempt = 0;
  while (total_written < size) {
    written = read(socket_fd, (char *) buf + total_written, size - total_written);
    attempt++;

    if ((uint32_t) time(NULL) >= run_until)
      break;
    total_written += written;
  }
  if (attempt != 1)
    LOG(INFO) << "MiniTrace: read attempt " << attempt;

  return total_written;
}

static bool CreateSocketAndCheckUIDAndPrefix(void *buf, uid_t uid) {
  int socket_fd;
  sockaddr_un server_addr;
  if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    PLOG(ERROR) << "MiniTrace: socket " << errno;
    return false;
  }

  memset(&server_addr, 0, sizeof server_addr);
  server_addr.sun_family = AF_UNIX;
  strcpy(&server_addr.sun_path[1], "/dev/mt/server");
  int addrlen = sizeof server_addr.sun_family + strlen(&server_addr.sun_path[1]) + 1;

  if (connect(socket_fd, (sockaddr *)&server_addr, addrlen) < 0) {
    PLOG(ERROR) << "MiniTrace: connect " << errno;
    close(socket_fd);
    return false;
  }
  LOG(INFO) << "MiniTrace: connect success!";

  uid_t targetuid;
  int32_t prefix_length;
  int written = read_with_timeout(socket_fd, &targetuid, sizeof (uid_t), 3);
  if (written == sizeof (uid_t)) {
    // check uid
    LOG(INFO) << "MiniTrace: read success, written " << written << " targetuid " << targetuid << " uid " << (uid&0xFFFF);
    if (targetuid == uid) {
      int32_t pid = getpid();
      int32_t SPECIAL_VALUE = 0x7415963;
      write(socket_fd, &pid, 4);
      write(socket_fd, &SPECIAL_VALUE, 4);

      // read available path
      written = read_with_timeout(socket_fd, &prefix_length, 4, 3);
      if (written == 4 && prefix_length > 0 && prefix_length < 256) {
        written = read_with_timeout(socket_fd, buf, prefix_length + 1, 3);
        if (written == prefix_length + 1) {
          close(socket_fd);
          return true;
        } else {
          LOG(ERROR) << "MiniTrace: Read Prefix " << errno;
        }
      } else {
        PLOG(ERROR) << "MiniTrace: Read Prefix length " << errno;
      }
    } else {
      PLOG(INFO) << "MiniTrace: Mismatch UID " << targetuid << " != " << (uid & 0xFFFF);
    }
  } else {
    PLOG(ERROR) << "MiniTrace: Read UID " << errno;
  }
  close(socket_fd);
  return false;
}

bool MiniTrace::CreateSocketAndAlertTheEnd(
    const std::string &trace_method_info_filename,
    const std::string &trace_field_info_filename,
    const std::string &trace_thread_info_filename,
    const std::string &trace_data_filename
  ) {
  int socket_fd;
  sockaddr_un server_addr;
  if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    PLOG(ERROR) << "MiniTrace: socket " << errno;
    return false;
  }

  memset(&server_addr, 0, sizeof server_addr);
  server_addr.sun_family = AF_UNIX;
  strcpy(&server_addr.sun_path[1], "/dev/mt/server");
  int addrlen = sizeof server_addr.sun_family + strlen(&server_addr.sun_path[1]) + 1;

  if (connect(socket_fd, (sockaddr *)&server_addr, addrlen) < 0) {
    PLOG(ERROR) << "MiniTrace: connect " << errno;
    close(socket_fd);
    return false;
  }
  LOG(INFO) << "MiniTrace: connect success!";

  uid_t targetuid;
  int written = read_with_timeout(socket_fd, &targetuid, sizeof (uid_t), 3);
  if (written == sizeof (uid_t)) {
    // check uid
    LOG(INFO) << "MiniTrace: read success on uid " << getuid();
    if (targetuid == getuid()) {
      int32_t pid = getpid();
      int32_t SPECIAL_VALUE = 0xDEAD;
      write(socket_fd, &pid, 4);
      write(socket_fd, &SPECIAL_VALUE, 4);

      LOG(INFO) << "data method info name " << trace_method_info_filename;
      write(socket_fd, trace_method_info_filename.c_str(), trace_method_info_filename.length() + 1);
      LOG(INFO) << "data field info name " << trace_field_info_filename;
      write(socket_fd, trace_field_info_filename.c_str(), trace_field_info_filename.length() + 1);
      LOG(INFO) << "data thread info name " << trace_thread_info_filename;
      write(socket_fd, trace_thread_info_filename.c_str(), trace_thread_info_filename.length() + 1);
      LOG(INFO) << "info file name " << trace_data_filename;
      write(socket_fd, trace_data_filename.c_str(), trace_data_filename.length() + 1);
      close(socket_fd);
      return true;
    } else {
      PLOG(INFO) << "MiniTrace: Mismatch UID " << targetuid << " != " << getuid();
    }
  } else {
    PLOG(ERROR) << "MiniTrace: Read UID " << errno;
  }
  close(socket_fd);
  return false;
}

void MiniTrace::ReadBuffer(char *dest, size_t offset, size_t len) {
  // Must be called after ringbuf_consume
  uint8_t *ptr = buf_.get();
  if (offset + len <= buffer_size_) {
    memcpy(dest, ptr + offset, len);
  } else {
    // wrap around
    size_t first_size = buffer_size_ - offset;
    memcpy(dest, ptr + offset, first_size);
    memcpy(dest + first_size, ptr, len - first_size);
  }
}

void MiniTrace::WriteBuffer(const char *src, size_t offset, size_t len) {
  // Must be called after ringbuf_acquire
  uint8_t *ptr = buf_.get();
  if (offset + len <= buffer_size_) {
    memcpy(ptr + offset, src, len);
  } else {
    // wrap around
    size_t first_size = buffer_size_ - offset;
    memcpy(ptr + offset, src, first_size);
    memcpy(ptr, src + first_size, len - first_size);
  }
}

bool MiniTrace::Setup(const char *file_prefix) {
  Thread *self = Thread::Current();
  MutexLock mu(self, *on_change_);
  if (trace_method_info_file_ != NULL || trace_field_info_file_ != NULL ||
    trace_thread_info_file_ != NULL || trace_data_file_ != NULL) {
    return false;
  }

  trace_method_info_file_ = OS::CreateEmptyFile(StringPrintf("%sinfo_m.log", file_prefix).c_str());
  CHECK(trace_method_info_file_ != NULL);

  trace_field_info_file_ = OS::CreateEmptyFile(StringPrintf("%sinfo_f.log", file_prefix).c_str());
  CHECK(trace_field_info_file_ != NULL);

  trace_thread_info_file_ = OS::CreateEmptyFile(StringPrintf("%sinfo_t.log", file_prefix).c_str());
  CHECK(trace_thread_info_file_ != NULL);

  trace_data_file_ = OS::CreateEmptyFile(StringPrintf("%sdata.bin", file_prefix).c_str());
  CHECK(trace_data_file_ != NULL);

  return true;
}

void MiniTrace::Start() {
  uid_t uid = getuid();
  if ((uid % AID_USER) < AID_APP) {
    // Do not target system app
    return;
  }

  static const uint32_t events = instrumentation::Instrumentation::kMethodEntered |
                                 instrumentation::Instrumentation::kMethodExited |
                                 instrumentation::Instrumentation::kMethodUnwind |
                                 instrumentation::Instrumentation::kFieldRead |
                                 instrumentation::Instrumentation::kFieldWritten |
                                 instrumentation::Instrumentation::kExceptionCaught |
                                 kDoCoverage;
  char prefix[100];
  Thread* self = Thread::Current();
  MiniTrace *the_trace;
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_trace_ != NULL)
      return;
    else if (!CreateSocketAndCheckUIDAndPrefix(prefix, uid))
      return;
    LOG(INFO) << "MiniTrace: Connection with server was success, received prefix " << prefix;
    the_trace = the_trace_ = new MiniTrace(events, 1024 * 1024);
  }
  Runtime* runtime = Runtime::Current();
  runtime->GetThreadList()->SuspendAll();

  runtime->GetInstrumentation()->AddListener(the_trace, events);
  runtime->GetInstrumentation()->EnableMethodTracing();
  runtime->GetThreadList()->ResumeAll();

  the_trace->Setup(prefix);
}

void MiniTrace::Stop() {
  // Stop would not be called...
  Runtime* runtime = Runtime::Current();
  runtime->GetThreadList()->SuspendAll();
  MiniTrace* the_trace = NULL;
  {
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    if (the_trace_ == NULL) {
      LOG(ERROR) << "MiniTrace: Trace stop requested, but no trace currently running";
    } else {
      the_trace = the_trace_;
      the_trace_ = NULL;
    }
  }
  if (the_trace != NULL) {
    LOG(INFO) << "MiniTrace: Stop() called";
    /* uint32_t events = instrumentation::Instrumentation::kMethodEntered |
                      instrumentation::Instrumentation::kMethodExited |
                      instrumentation::Instrumentation::kMethodUnwind |
                      instrumentation::Instrumentation::kFieldRead |
                      instrumentation::Instrumentation::kFieldWritten;*/

    runtime->GetInstrumentation()->DisableMethodTracing();
    runtime->GetInstrumentation()->RemoveListener(the_trace, the_trace->events_);

    std::string trace_method_info_filename(the_trace->trace_method_info_file_->GetPath());
    std::string trace_field_info_filename(the_trace->trace_field_info_file_->GetPath());
    std::string trace_thread_info_filename(the_trace->trace_thread_info_file_->GetPath());
    std::string trace_data_filename(the_trace->trace_data_file_->GetPath());

    if (the_trace->trace_method_info_file_ != nullptr) {
      // Do not try to erase, so flush and close explicitly.
      if (the_trace->trace_method_info_file_->Flush() != 0)
        PLOG(ERROR) << "MiniTrace: Could not flush method info file.";
      if (the_trace->trace_method_info_file_->Close() != 0)
        PLOG(ERROR) << "MiniTrace: Could not close method info file.";
    }
    if (the_trace->trace_field_info_file_ != nullptr) {
      // Do not try to erase, so flush and close explicitly.
      if (the_trace->trace_field_info_file_->Flush() != 0)
        PLOG(ERROR) << "MiniTrace: Could not flush field info file.";
      if (the_trace->trace_field_info_file_->Close() != 0)
        PLOG(ERROR) << "MiniTrace: Could not close field info file.";
    }
    if (the_trace->trace_thread_info_file_ != nullptr) {
      // Do not try to erase, so flush and close explicitly.
      if (the_trace->trace_thread_info_file_->Flush() != 0)
        PLOG(ERROR) << "MiniTrace: Could not flush thread info file.";
      if (the_trace->trace_thread_info_file_->Close() != 0)
        PLOG(ERROR) << "MiniTrace: Could not close thread info file.";
    }
    if (the_trace->trace_data_file_ != nullptr) {
      // Do not try to erase, so flush and close explicitly.
      if (the_trace->trace_data_file_->Flush() != 0)
        PLOG(ERROR) << "MiniTrace: Could not flush trace data file.";
      if (the_trace->trace_data_file_->Close() != 0)
        PLOG(ERROR) << "MiniTrace: Could not close trace data file.";
    }

    if (!the_trace->CreateSocketAndAlertTheEnd(
          trace_method_info_filename,
          trace_field_info_filename,
          trace_thread_info_filename,
          trace_data_filename
        )) {
      LOG(ERROR) << "MiniTrace: Alerting the end failed.";
    }

    delete the_trace->registered_threads_lock_;
    delete the_trace->traced_method_lock_;
    delete the_trace->traced_field_lock_;
    delete the_trace->traced_thread_lock_;
    free(the_trace->ringbuf_);

    delete the_trace;
  }
  runtime->GetThreadList()->ResumeAll();
}

void MiniTrace::Shutdown() {
  if (GetMethodTracingMode() != kTracingInactive) {
    LOG(INFO) << "MiniTrace: Shutdown...";
    Stop();
  }
}

void MiniTrace::Checkout() {
  Thread *self = Thread::Current();
  MiniTrace *the_trace = NULL;
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_trace_ != NULL) {
      the_trace = the_trace_;
    }
  }
  if (the_trace == NULL) {
    // Just start the MiniTrace
    Start();
  } else {
    // @TODO If Stop is called..??

    // Wait consumer thread first, since it needs locks
    MutexLock mu(self, *the_trace->on_change_);
    the_trace->consumer_runs_ = false;
    CHECK_PTHREAD_CALL(pthread_join, (the_trace->consumer_thread_, NULL), 
        "consumer thread shutdown");

    // Prevent Logging
    MutexLock mu1(self, *the_trace->traced_method_lock_);
    MutexLock mu2(self, *the_trace->traced_field_lock_);
    MutexLock mu3(self, *the_trace->traced_thread_lock_);

    // Flush remaining outputs
    // Similar to consumer_func, but no lock
    char databuf[the_trace->buffer_size_];
    size_t len, woff;
    // Dump Buffer
    len = ringbuf_consume(the_trace->ringbuf_, &woff);
    if (len > 0) {
      the_trace->ReadBuffer(databuf, woff, len);
      ringbuf_release(the_trace->ringbuf_, len);

      // Save to data binary file
      if (!the_trace->trace_data_file_->WriteFully(databuf, len)) {
        std::string detail(StringPrintf("MiniTrace: Trace data write failed: %s", strerror(errno)));
        PLOG(ERROR) << detail;
        {
          Locks::mutator_lock_->ExclusiveLock(self);
          ThrowRuntimeException("%s", detail.c_str());
          Locks::mutator_lock_->ExclusiveUnlock(self);
        }
      }
    }

    // Dump Method
    std::ostringstream os;
    the_trace->FlushMethod(os);
    std::string buf(os.str());
    if (!the_trace->trace_method_info_file_->WriteFully(buf.c_str(), buf.length())) {
      std::string detail(StringPrintf("MiniTrace: Trace method info write failed: %s", strerror(errno)));
      PLOG(ERROR) << detail;
      {
        Locks::mutator_lock_->ExclusiveLock(self);
        ThrowRuntimeException("%s", detail.c_str());
        Locks::mutator_lock_->ExclusiveUnlock(self);
      }
    }

    // Dump Field
    os.str("");
    the_trace->FlushField(os);
    buf.assign(os.str());
    if (!the_trace->trace_field_info_file_->WriteFully(buf.c_str(), buf.length())) {
      std::string detail(StringPrintf("MiniTrace: Trace field info write failed: %s", strerror(errno)));
      PLOG(ERROR) << detail;
      {
        Locks::mutator_lock_->ExclusiveLock(self);
        ThrowRuntimeException("%s", detail.c_str());
        Locks::mutator_lock_->ExclusiveUnlock(self);
      }
    }

    // Dump Thread
    os.str("");
    the_trace->FlushThread(os);
    buf.assign(os.str());
    if (!the_trace->trace_thread_info_file_->WriteFully(buf.c_str(), buf.length())) {
      std::string detail(StringPrintf("MiniTrace: Trace thread info write failed: %s", strerror(errno)));
      PLOG(ERROR) << detail;
      {
        Locks::mutator_lock_->ExclusiveLock(self);
        ThrowRuntimeException("%s", detail.c_str());
        Locks::mutator_lock_->ExclusiveUnlock(self);
      }
    }
    CHECK(the_trace->trace_data_file_->Close());
    CHECK(the_trace->trace_method_info_file_->Close());
    CHECK(the_trace->trace_field_info_file_->Close());
    CHECK(the_trace->trace_thread_info_file_->Close());
    the_trace->trace_data_file_ = NULL;
    the_trace->trace_method_info_file_ = NULL;
    the_trace->trace_field_info_file_ = NULL;
    the_trace->trace_thread_info_file_ = NULL;

    char prefix[100];
    if(!CreateSocketAndCheckUIDAndPrefix(prefix, getuid()) || !the_trace->Setup(prefix)) {
      // @TODO server connection failed, so delete the trace...
      return;
    }

    // restart consumer
    CHECK_PTHREAD_CALL(pthread_create, (&the_trace->consumer_thread_, NULL, &ConsumerFunction,
                                        the_trace),
                                        "Consumer thread");
    the_trace->consumer_runs_ = true;
  }
}


TracingMode MiniTrace::GetMethodTracingMode() {
  MutexLock mu(Thread::Current(), *Locks::trace_lock_);
  if (the_trace_ == NULL) {
    return kTracingInactive;
  } else {
    return kMethodTracingActive;
  }
}

void *MiniTrace::ConsumerFunction(void *arg) {
  Runtime* runtime = Runtime::Current();
  MiniTrace *the_trace = (MiniTrace *)arg;
  Thread *self = Thread::Current();

  CHECK(runtime->AttachCurrentThread("Consumer", true, runtime->GetSystemThreadGroup(),
                                     !runtime->IsCompiler()));

  char databuf[the_trace->buffer_size_];
  size_t len, woff;
  while (the_trace->consumer_runs_) {
    // Dump Buffer
    len = ringbuf_consume(the_trace->ringbuf_, &woff);
    if (len > 0) {
      the_trace->ReadBuffer(databuf, woff, len);
      ringbuf_release(the_trace->ringbuf_, len);

      // Save to data binary file
      if (!the_trace->trace_data_file_->WriteFully(databuf, len)) {
        std::string detail(StringPrintf("MiniTrace: Trace data write failed: %s", strerror(errno)));
        PLOG(ERROR) << detail;
        {
          Locks::mutator_lock_->ExclusiveLock(self);
          ThrowRuntimeException("%s", detail.c_str());
          Locks::mutator_lock_->ExclusiveUnlock(self);
        }
      }
    }

    // Dump Method
    std::ostringstream os;
    {
      MutexLock mu(self, *the_trace->traced_method_lock_);
      the_trace->FlushMethod(os);
    }
    std::string buf(os.str());
    if (!the_trace->trace_method_info_file_->WriteFully(buf.c_str(), buf.length())) {
      std::string detail(StringPrintf("MiniTrace: Trace method info write failed: %s", strerror(errno)));
      PLOG(ERROR) << detail;
      {
        Locks::mutator_lock_->ExclusiveLock(self);
        ThrowRuntimeException("%s", detail.c_str());
        Locks::mutator_lock_->ExclusiveUnlock(self);
      }
    }

    // Dump Field
    os.str("");
    {
      MutexLock mu(self, *the_trace->traced_field_lock_);
      the_trace->FlushField(os);
    }
    buf.assign(os.str());
    if (!the_trace->trace_field_info_file_->WriteFully(buf.c_str(), buf.length())) {
      std::string detail(StringPrintf("MiniTrace: Trace field info write failed: %s", strerror(errno)));
      PLOG(ERROR) << detail;
      {
        Locks::mutator_lock_->ExclusiveLock(self);
        ThrowRuntimeException("%s", detail.c_str());
        Locks::mutator_lock_->ExclusiveUnlock(self);
      }
    }

    // Dump Thread
    os.str("");
    {
      MutexLock mu(self, *the_trace->traced_thread_lock_);
      the_trace->FlushThread(os);
    }
    buf.assign(os.str());
    if (!the_trace->trace_thread_info_file_->WriteFully(buf.c_str(), buf.length())) {
      std::string detail(StringPrintf("MiniTrace: Trace thread info write failed: %s", strerror(errno)));
      PLOG(ERROR) << detail;
      {
        Locks::mutator_lock_->ExclusiveLock(self);
        ThrowRuntimeException("%s", detail.c_str());
        Locks::mutator_lock_->ExclusiveUnlock(self);
      }
    }
  }

  runtime->DetachCurrentThread();
  return 0;
}

MiniTrace::MiniTrace(uint32_t events, uint32_t buffer_size)
    : buf_(new uint8_t[buffer_size]()),
      consumer_runs_(true),
      on_change_(new Mutex("MiniTrace main status lock")),
      events_(events), do_coverage_((events & kDoCoverage) != 0),
      do_filter_((events & kDoFilter) != 0), buffer_size_(buffer_size), start_time_(MicroTime()) {

  traced_method_lock_ = new Mutex("MiniTrace method lock");
  traced_field_lock_ = new Mutex("MiniTrace field lock");
  traced_thread_lock_ = new Mutex("MiniTrace thread lock");

  registered_threads_lock_ = new Mutex("MiniTrace thread lock 2");

  size_t ringbuf_obj_size;
  ringbuf_get_sizes(MAX_THREAD_COUNT, &ringbuf_obj_size, NULL);

  ringbuf_ = (ringbuf_t *) malloc(ringbuf_obj_size);
  ringbuf_setup(ringbuf_, MAX_THREAD_COUNT, buffer_size);
  for (int i=0; i<MAX_THREAD_COUNT; i++)
    is_registered_[i] = false;

  CHECK_PTHREAD_CALL(pthread_create, (&consumer_thread_, NULL, &ConsumerFunction,
                                      this),
                                      "Consumer thread");
}

void MiniTrace::DexPcMoved(Thread* thread, mirror::Object* this_object,
                       mirror::ArtMethod* method, uint32_t new_dex_pc) {
  // We're not recorded to listen to this kind of event, so complain.
  LOG(ERROR) << "MiniTrace: Unexpected dex PC event in tracing " << PrettyMethod(method) << " " << new_dex_pc;
};

void MiniTrace::FieldRead(Thread* thread, mirror::Object* this_object,
                       mirror::ArtMethod* method, uint32_t dex_pc, mirror::ArtField* field) {
  LogFieldTraceEvent(thread, this_object, field, dex_pc, true);
}

void MiniTrace::FieldWritten(Thread* thread, mirror::Object* this_object,
                          mirror::ArtMethod* method, uint32_t dex_pc, mirror::ArtField* field,
                          const JValue& field_value) {
  UNUSED(field_value);
  LogFieldTraceEvent(thread, this_object, field, dex_pc, false);
}

void MiniTrace::MethodEntered(Thread* thread, mirror::Object* this_object,
                          mirror::ArtMethod* method, uint32_t dex_pc) {
  LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodEntered);
}

void MiniTrace::MethodExited(Thread* thread, mirror::Object* this_object,
                         mirror::ArtMethod* method, uint32_t dex_pc,
                         const JValue& return_value) {
  UNUSED(return_value);
  LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodExited);

  // log for android.app.activity performDestroy and performPause
  // if (PrettyDescriptor(method->GetDeclaringClassDescriptor()).compare("android.app.Activity") == 0) {
  //   if (strcmp(method->GetName(), "performDestroy") == 0 || strcmp(method->GetName(), "performPause") == 0)
  //       ??
  // }
  // @TODO Should I wait for at least one loop for consumer thread?
}

void MiniTrace::MethodUnwind(Thread* thread, mirror::Object* this_object,
                         mirror::ArtMethod* method, uint32_t dex_pc) {
  LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodUnwind);
}

void MiniTrace::ExceptionCaught(Thread* thread, const ThrowLocation& throw_location,
                            mirror::ArtMethod* catch_method, uint32_t catch_dex_pc,
                            mirror::Throwable* exception_object) {
  MiniTraceAction action = kMiniTraceExceptionCaught;

  std::string content = exception_object->Dump();
  uint16_t record_size = content.length() + 2 + 4 + 1;
  char *buf = new char[record_size]();
  ssize_t off;

  Append2LE(buf, thread->GetTid());
  Append4LE(buf + 2, (record_size << 3) | action);
  strcpy(buf + 6, content.c_str());

  ringbuf_worker_t *w = GetRingBufWorker();
  while ((off = ringbuf_acquire(ringbuf_, w, record_size)) == -1) {}
  WriteBuffer(buf, off, record_size);
  ringbuf_produce(ringbuf_, w);

  delete buf;
}

void MiniTrace::LogMethodTraceEvent(Thread* thread, mirror::ArtMethod* method, uint32_t dex_pc,
                                instrumentation::Instrumentation::InstrumentationEvent event) {
  MiniTraceAction action = kMiniTraceMethodEnter;
  switch (event) {
    case instrumentation::Instrumentation::kMethodEntered:
      action = kMiniTraceMethodEnter;
      break;
    case instrumentation::Instrumentation::kMethodExited:
      action = kMiniTraceMethodExit;
      break;
    case instrumentation::Instrumentation::kMethodUnwind:
      action = kMiniTraceUnroll;
      break;
    default:
      UNIMPLEMENTED(FATAL) << "MiniTrace: Unexpected event: " << event;
  }

  LogNewMethod(method);

  char buf[6];
  ssize_t off;
  uint32_t method_ptr = PointerToLowMemUInt32(method);
  DCHECK(~(method_ptr & kMiniTraceActionMask));
  Append2LE(buf, thread->GetTid());
  Append4LE(buf + 2, method_ptr | action);

  ringbuf_worker_t *w = GetRingBufWorker();
  while ((off = ringbuf_acquire(ringbuf_, w, 6)) == -1) {}
  WriteBuffer(buf, off, 6);
  ringbuf_produce(ringbuf_, w);
}

void MiniTrace::LogFieldTraceEvent(Thread* thread, mirror::Object *this_object, mirror::ArtField* field,
                                uint32_t dex_pc, bool read_event) {

  if (!field->IsMiniTraceable()) {
    return;
  }

  MiniTraceAction action;
  if (read_event) {
    action = kMiniTraceFieldRead;
  } else {
    action = kMiniTraceFieldWrite;
  }

  LogNewField(field);

  char buf[14];
  ssize_t off;
  Append2LE(buf, thread->GetTid());
  Append4LE(buf + 2, PointerToLowMemUInt32(field) | action);
  Append4LE(buf + 6, PointerToLowMemUInt32(this_object));
  Append4LE(buf + 10, dex_pc);

  ringbuf_worker_t *w = GetRingBufWorker();
  while ((off = ringbuf_acquire(ringbuf_, w, 14)) == -1) {}
  WriteBuffer(buf, off, 14);
  ringbuf_produce(ringbuf_, w);
}

void MiniTrace::LogMonitorTraceEvent(Thread* thread, mirror::Object* lock_object,
    uint32_t dex_pc, bool enter_event) {
  MiniTraceAction action;
  if (enter_event) {
    action = kMiniTraceMonitorEnter;
  } else {
    action = kMiniTraceMonitorExit;
  }

  char buf[10];
  ssize_t off;
  Append2LE(buf, thread->GetTid());
  Append4LE(buf + 2, PointerToLowMemUInt32(lock_object) | action);
  Append4LE(buf + 6, dex_pc);

  ringbuf_worker_t *w = GetRingBufWorker();
  while ((off = ringbuf_acquire(ringbuf_, w, 10)) == -1) {}
  WriteBuffer(buf, off, 10);
  ringbuf_produce(ringbuf_, w);
}

void MiniTrace::StoreExitingThreadInfo(Thread* thread) {
  MutexLock mu(thread, *Locks::trace_lock_);
  if (the_trace_ != nullptr) {
    the_trace_->UnregisterRingBufWorker(thread);
  }
}

void MiniTrace::FlushMethod(std::ostringstream &os) {
  Thread *self = Thread::Current();
  traced_method_lock_->AssertHeld(self);
  for (auto& it: methods_not_stored_) {
    (&it)->Dump(os);
  }
  methods_not_stored_.clear();
}

void MiniTrace::FlushField(std::ostringstream &os) {
  Thread *self = Thread::Current();
  traced_field_lock_->AssertHeld(self);
  for (auto& it: fields_not_stored_) {
    (&it)->Dump(os);
  }
  fields_not_stored_.clear();
}

void MiniTrace::FlushThread(std::ostringstream &os) {
  Thread *self = Thread::Current();
  traced_thread_lock_->AssertHeld(self);
  for (auto& it : threads_not_stored_) {
    (&it)->Dump(os);
  }
  threads_not_stored_.clear();
}

void MiniTrace::LogNewMethod(mirror::ArtMethod *method) {
  MutexLock mu(Thread::Current(), *traced_method_lock_);
  auto it = visited_methods_.insert(method);
  if (it.second)
    methods_not_stored_.emplace_back(method);
}

void MiniTrace::LogNewField(mirror::ArtField *field) {
  MutexLock mu(Thread::Current(), *traced_field_lock_);
  auto it = visited_fields_.insert(field);
  if (it.second)
    fields_not_stored_.emplace_back(field);
}

bool* MiniTrace::GetExecutionData(Thread* self, mirror::ArtMethod* method) {
  if (method->IsRuntimeMethod() || method->IsProxyMethod()) {  // No profile for execution data
    return NULL;
  }

  if (!method->IsMiniTraceable()) {
    return NULL;
  }

  {
    DCHECK_EQ(self, Thread::Current());
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    MiniTrace* the_trace = the_trace_;
    if (the_trace == NULL) {
      return NULL;
    }

    if (!the_trace->do_coverage_) {
      return NULL;
    }

    if (the_trace->do_filter_ && !method->IsMiniTraceable()) {
      return NULL;
    }

    SafeMap<mirror::ArtMethod*, bool*>::const_iterator it = the_trace->execution_data_.find(method);
    if (it == the_trace_->execution_data_.end()) {
      const DexFile::CodeItem* code_item = method->GetCodeItem();
      uint16_t insns_size = code_item->insns_size_in_code_units_;
      if (insns_size == 0) {
        return NULL;
      }

      bool* execution_data = new bool[insns_size];
      memset(execution_data, 0, insns_size * sizeof(bool));

      the_trace->LogNewMethod(method);
      the_trace->execution_data_.Put(method, execution_data);
      return execution_data;
    }
    return it->second;
  }
}

void MiniTrace::PostClassPrepare(mirror::Class* klass) {
  if (klass->IsArrayClass() || klass->IsInterface() || klass->IsPrimitive()) {
    return;
  }

  std::string temp;
  const char* descriptor = klass->GetDescriptor(&temp);
  if ((strncmp(descriptor, "Ljava/", 6) == 0)
      || (strncmp(descriptor, "Ljavax/", 7) == 0)
      || (strncmp(descriptor, "Lsun/", 5) == 0)
      || (strncmp(descriptor, "Lcom/sun/", 9) == 0)
      || (strncmp(descriptor, "Lcom/ibm/", 9) == 0)
      || (strncmp(descriptor, "Lorg/xml/", 9) == 0)
      || (strncmp(descriptor, "Lorg/w3c/", 9) == 0)
      || (strncmp(descriptor, "Lapple/awt/", 11) == 0)
      || (strncmp(descriptor, "Lcom/apple/", 11) == 0)
      || (strncmp(descriptor, "Landroid/", 9) == 0)
      || (strncmp(descriptor, "Lcom/android/", 13) == 0)) {
    return;
  }

  klass->SetIsMiniTraceable();

  for (size_t i = 0, e = klass->NumDirectMethods(); i < e; i++) {
    klass->GetDirectMethod(i)->SetIsMiniTraceable();
  }
  for (size_t i = 0, e = klass->NumVirtualMethods(); i < e; i++) {
    klass->GetVirtualMethod(i)->SetIsMiniTraceable();
  }

  {
    size_t num_fields = klass->NumInstanceFields();
    mirror::ObjectArray<mirror::ArtField>* fields = klass->GetIFields();

    for (size_t i = 0; i < num_fields; i++) {
      mirror::ArtField* f = fields->Get(i);
      f->SetIsMiniTraceable();
    }
  }

  {
    size_t num_fields = klass->NumStaticFields();
    mirror::ObjectArray<mirror::ArtField>* fields = klass->GetSFields();

    for (size_t i = 0; i < num_fields; i++) {
      mirror::ArtField* f = fields->Get(i);
      f->SetIsMiniTraceable();
    }
  }
}

ringbuf_worker_t *MiniTrace::GetRingBufWorker() {
  Thread *self = Thread::Current();
  if (self->GetRingBufWorker() != NULL) {
    return self->GetRingBufWorker();
  } else {
    // Not found
    // Find empty id
    LOG(INFO) << "MiniTrace: Register ring buf worker with thread " << self->GetTid();
    MutexLock mu(self, *registered_threads_lock_);
    uint32_t empty_id;
    for (empty_id=0; empty_id<MAX_THREAD_COUNT; empty_id++) {
      if (is_registered_[empty_id] == false)
        break;
    }
    if (empty_id == MAX_THREAD_COUNT) {
      LOG(ERROR) << "MiniTrace: Failed to allocate new ringbuf worker";
      return NULL;
    }

    ringbuf_worker_t *rworker = ringbuf_register(ringbuf_, empty_id);
    is_registered_[empty_id] = true;
    LOG(INFO) << "MiniTrace: Assigining id " << empty_id << " and rworker " << rworker;
    registered_threads_[self] = rworker;
    self->SetRingBufWorker(rworker);
    std::string name;
    self->GetThreadName(name);
    {
      MutexLock mu(self, *traced_thread_lock_);
      threads_not_stored_.emplace_back(self->GetTid(), name);
    }
    return rworker;
  }
}

void MiniTrace::UnregisterRingBufWorker(Thread *thread) {
  Thread *self = Thread::Current();
  {
    MutexLock mu(self, *registered_threads_lock_);
    std::map<Thread *, ringbuf_worker_t *>::iterator it;
    it = registered_threads_.find(thread);
    if (it == registered_threads_.end()) {
      LOG(ERROR) << "MiniTrace: Failed to unregister ringbuf worker, not found";
    } else {
      thread->SetRingBufWorker(NULL);
      ringbuf_unregister(ringbuf_, it->second);
      is_registered_[ringbuf_w2i(ringbuf_, it->second)] = false;
      registered_threads_.erase(it);
    }
  }
}

}  // namespace art
