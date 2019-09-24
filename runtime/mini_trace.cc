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
#include "dex_instruction.h"
#include <utils/Timers.h>

namespace art {

/**
 * File format:
 *     header
 *     record 0
 *     record 1
 *     ...
 *
 * Header format:
 *     u4  magic ('MiTr')
 *     u2  version
 *     u2  offset to data
 *     u4  log_flag
 *     u8  starting timestamp in milliseconds
 *         in C:
 *           gettimeofday(&now, NULL); int64_t timestamp = now.tv_sec * 1000LL + now.tv_usec / 1000;
 *         in JAVA:
 *           System.currentTimeMillis();
 *         interpret in Python:
 *           datetime.datetime.fromtimestamp(timestamp/1000.0)
 *
 * Method event - length 6 (action 0, 1, 2)
 *   u2 tid;
 *   u4 art_method_with_action;
 *
 * Field event - length 16 (action 3, 4)
 *   u2 tid;
 *   u4 art_field_with_action;
 *   u4 this_obj;
 *   u4 dex_pc;
 *   u2 idx;
 *
 * Exception / Message event - variable length (action 5, 6)
 *   u2 tid;
 *   u4 dump_length_with_action;
 *   char dumped[];
 *
 *
 * Idle event - length 10 (no action, differentiate this with tid=0)
 *   u2 tid=0;
 *   u8 timestamp_in_ms;
 *
 * Pinging event - length 10 (no action, differentiate this with tid=0)
 *   u2 tid=1;
 *   u8 timestamp_in_ms;
 */
enum MiniTraceAction {
    kMiniTraceMethodEnter = 0x00,       // method entry
    kMiniTraceMethodExit = 0x01,        // method exit
    kMiniTraceUnwind = 0x02,            // method exited by exception unwinding
    kMiniTraceFieldRead = 0x03,         // field read
    kMiniTraceFieldWrite = 0x04,        // field write
    kMiniTraceExceptionCaught = 0x05,   // exception caught
    kMiniTraceMessageEvent = 0x06,      // message
    kMiniTraceActionMask = 0x07,        // three bits
};

static const uint16_t kMiniTraceHeaderLength     = 4+2+2+4+8;
static const uint16_t kMiniTraceVersion          = 2;
static const uint32_t kMiniTraceMagic            = 0x7254694D; // MiTr
void *MiniTrace::nativePollOnce_originalEntry = NULL;

MiniTrace* volatile MiniTrace::the_trace_ = NULL;
const char *MiniTrace::threadnames_to_exclude[] = {
  THREAD_FinalizerDaemon,
  THREAD_ReferenceQueueDaemon,
  THREAD_GCDaemon,
  THREAD_FinalizerWatchdogDaemon,
  THREAD_HeapTrimmerDaemon
};

#if _BYTE_ORDER == _LITTLE_ENDIAN

static void Append2LE(char* buf, uint16_t val) {
  *(uint16_t *)buf = val;
}

static void Append4LE(char* buf, uint32_t val) {
  *(uint32_t *)buf = val;
}

static void Append8LE(char* buf, uint64_t val) {
  *(uint64_t *)buf = val;
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

static void Append8LE(char* buf, uint64_t val) {
  *buf++ = static_cast<char>(val);
  *buf++ = static_cast<char>(val >> 8);
  *buf++ = static_cast<char>(val >> 16);
  *buf++ = static_cast<char>(val >> 24);
  *buf++ = static_cast<char>(val >> 32);
  *buf++ = static_cast<char>(val >> 40);
  *buf++ = static_cast<char>(val >> 48);
  *buf++ = static_cast<char>(val >> 56);
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

static int CreateSocketAndCheckUIDAndPrefix(void *buf, uid_t uid, uint32_t *log_flag) {
  int socket_fd;
  sockaddr_un server_addr;
  if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    PLOG(ERROR) << "MiniTrace: socket " << errno;
    return -1;
  }

  memset(&server_addr, 0, sizeof server_addr);
  server_addr.sun_family = AF_UNIX;
  strcpy(&server_addr.sun_path[1], "/dev/mt/server");
  int addrlen = sizeof server_addr.sun_family + strlen(&server_addr.sun_path[1]) + 1;

  if (connect(socket_fd, (sockaddr *)&server_addr, addrlen) < 0) {
    if (errno != 111)
      PLOG(ERROR) << "MiniTrace: connect " << errno;
    close(socket_fd);
    return -1;
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
      written = read_with_timeout(socket_fd, log_flag, 4, 3);
      if (written == 4 && (*log_flag & ~MiniTrace::MiniTraceFlag::kFlagAll) == 0) {
        written = read_with_timeout(socket_fd, &prefix_length, 4, 3);
        if (written == 4 && prefix_length > 0 && prefix_length < 256) {
          written = read_with_timeout(socket_fd, buf, prefix_length + 1, 3);
          if (written == prefix_length + 1) {
            return socket_fd;
          } else {
            LOG(ERROR) << "MiniTrace: Read Prefix " << errno;
          }
        } else {
          PLOG(ERROR) << "MiniTrace: Read Prefix length " << errno;
        }
      } else {
        LOG(ERROR) << "MiniTrace: Read flag " << errno;
      }
    } else {
      PLOG(INFO) << "MiniTrace: Mismatch UID " << targetuid << " != " << uid;
    }
  } else {
    PLOG(ERROR) << "MiniTrace: Read UID " << errno;
  }
  close(socket_fd);
  return -1;
}

static int CreateSocketAndCheckAPE() {
  int socket_fd;
  sockaddr_un server_addr;
  if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
    PLOG(ERROR) << "MiniTrace::IdleCheck: socket " << errno;
    return -1;
  }

  memset(&server_addr, 0, sizeof server_addr);
  server_addr.sun_family = AF_UNIX;
  strcpy(&server_addr.sun_path[1], "/dev/mt/ape");
  int addrlen = sizeof server_addr.sun_family + strlen(&server_addr.sun_path[1]) + 1;

  if (connect(socket_fd, (sockaddr *)&server_addr, addrlen) < 0) {
    PLOG(ERROR) << "MiniTrace::IdleCheck: connect " << errno;
    close(socket_fd);
    return -1;
  }
  LOG(INFO) << "MiniTrace::IdleCheck: connect success!";
  return socket_fd;
}

void MiniTrace::ReadBuffer(char *dest, size_t offset, size_t len) {
  // Must be called after ringbuf_consume
  if (offset + len <= buffer_size_) {
    memcpy(dest, buf_ + offset, len);
  } else {
    // wrap around
    size_t first_size = buffer_size_ - offset;
    memcpy(dest, buf_ + offset, first_size);
    memcpy(dest + first_size, buf_, len - first_size);
  }
}

void MiniTrace::WriteRingBuffer(ringbuf_worker_t *worker, const char *src, size_t len) {
  ssize_t offset;
  while ((offset = ringbuf_acquire(ringbuf_, worker, len)) == -1) {}
  if (offset + len <= buffer_size_) {
    memcpy(buf_ + offset, src, len);
  } else {
    // wrap around
    size_t first_size = buffer_size_ - offset;
    memcpy(buf_ + offset, src, first_size);
    memcpy(buf_, src + first_size, len - first_size);
  }
  ringbuf_produce(ringbuf_, worker);
}

void MiniTrace::Start() {
  uid_t uid = getuid();
  // Do not target system app
  if (uid != 0 && ((uid % AID_USER) < AID_APP))
    return;

  char prefix[100];
  Thread* self = Thread::Current();
  MiniTrace *the_trace;
  uint32_t log_flag;
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_trace_ != NULL) // Already started
      return;

    int socket_fd = CreateSocketAndCheckUIDAndPrefix(prefix, uid, &log_flag);
    if (socket_fd == -1)
      return;
    LOG(INFO) << "MiniTrace: connection success, received prefix="
        << prefix << " log_flag=" << log_flag;

    CHECK((log_flag & ~kFlagAll) == 0);
    CHECK(!(log_flag & (kDoMethodEntered | kDoMethodExited | kDoMethodUnwind))
      || (log_flag & kLogMethodTypeFlags));
    CHECK(!(log_flag & (kDoFieldRead | kDoFieldWritten))
      || (log_flag & kLogFieldTypeFlags));

    // Currently UNUSED flags
    // CHECK(!(log_flag & kLogFieldType1));
    // CHECK(!(log_flag & kLogFieldType2));
    // CHECK(!(log_flag & kLogMethodType2));
    int ape_socket_fd = -1;
    if (log_flag & kConnectAPE) {
      ape_socket_fd = CreateSocketAndCheckAPE();
      CHECK(ape_socket_fd != -1);
    }
    the_trace = the_trace_ = new MiniTrace(socket_fd, prefix, log_flag, 1024 * 1024, ape_socket_fd);
  }
  Runtime* runtime = Runtime::Current();
  runtime->GetThreadList()->SuspendAll();
  CHECK_PTHREAD_CALL(pthread_create, (&the_trace->consumer_thread_, NULL, &ConsumerTask,
                                      the_trace),
                                      "Consumer thread");
  if (log_flag & kConnectAPE) {
    CHECK_PTHREAD_CALL(pthread_create, (&the_trace->idlecheck_thread_, NULL, &IdleCheckTask,
                                        the_trace),
                                        "IdleCheck thread");
  }
  if (log_flag & kLogOneSecPing) {
    CHECK_PTHREAD_CALL(pthread_create, (&the_trace->pinging_thread_, NULL, &PingingTask,
                                        the_trace),
                                        "Pinging thread");
  }
  if (log_flag & (kLogMessage | kConnectAPE))
    log_flag |= (kDoMethodEntered | kDoMethodExited);
  runtime->GetInstrumentation()->AddListener(the_trace, log_flag & kInstListener);
  runtime->GetInstrumentation()->EnableMethodTracing();
  runtime->GetThreadList()->ResumeAll();
}

void MiniTrace::Shutdown() {
  // Shutdown would not be called...
  Runtime* runtime = Runtime::Current();
  MiniTrace* the_trace = NULL;
  {
    // This block prevents more than one invocation for MiniTrace::Shutdown
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    if (the_trace_ == NULL)
      return;
    else {
      the_trace = the_trace_;
      the_trace_ = NULL;
    }
  }
  if (the_trace != NULL) {
    // kill IdleCheck
    if (the_trace->log_flag_ & kConnectAPE) {
      CHECK_PTHREAD_CALL(pthread_kill, (the_trace->idlecheck_thread_, SIGQUIT),
          "IdleCheck kill");
      close(the_trace->ape_socket_fd_);
    }
    if (the_trace->log_flag_ & kLogOneSecPing) {
      CHECK_PTHREAD_CALL(pthread_kill, (the_trace->pinging_thread_, SIGQUIT),
          "Pinging kill");
    }

    // Wait for consumer
    LOG(INFO) << "MiniTrace: Shutdown() called";
    Thread *consumer_thread = NULL;
    ThreadList *runtime_thread_list = runtime->GetThreadList();
    if (the_trace->consumer_runs_ && the_trace->consumer_tid_ != 0)
      consumer_thread = runtime_thread_list->FindThreadByThreadId(the_trace->consumer_tid_);

    runtime_thread_list->SuspendAll();
    runtime->GetInstrumentation()->DisableMethodTracing();
    runtime->GetInstrumentation()->RemoveListener(the_trace, the_trace->log_flag_ & kInstListener);

    // Wait for consumer
    if (consumer_thread != NULL) {
      the_trace->consumer_runs_ = false;
      runtime_thread_list->Resume(consumer_thread);
      CHECK_PTHREAD_CALL(pthread_join, (the_trace->consumer_thread_, NULL),
          "consumer thread join");
    }
    close(the_trace->socket_fd_);

    // delete trace objects
    delete the_trace->wids_registered_lock_;
    delete the_trace->traced_method_lock_;
    delete the_trace->traced_field_lock_;
    delete the_trace->traced_thread_lock_;
    delete the_trace->buf_;
    free(the_trace->ringbuf_);

    delete the_trace;
    runtime_thread_list->ResumeAll();
  }
}

void MiniTrace::Checkout() {
  Thread *self = Thread::Current();
  MiniTrace *the_trace = NULL;
  {
    MutexLock mu(self, *Locks::trace_lock_);
    the_trace = the_trace_;
  }
  if (the_trace == NULL)
    Start();
  else {
    LOG(INFO) << "MiniTrace: Checkout called";
    the_trace->data_bin_index_ ++;
  }
}

void *MiniTrace::ConsumerTask(void *arg) {
  MiniTrace *the_trace = (MiniTrace *)arg;
  Runtime* runtime = Runtime::Current();
  CHECK(runtime->AttachCurrentThread("Consumer", true, runtime->GetSystemThreadGroup(),
                                       !runtime->IsCompiler()));

  Thread *self = Thread::Current();
  LOG(INFO) << "MiniTrace: Consumer thread attached with tid " << self->GetTid();
  the_trace->consumer_tid_ = self->GetTid();
  // Create header
  char *header;
  {
    header = new char[kMiniTraceHeaderLength];
    Append4LE(header, kMiniTraceMagic);
    Append2LE(header + 4, kMiniTraceVersion);
    Append2LE(header + 6, kMiniTraceHeaderLength);
    Append4LE(header + 8, the_trace->log_flag_);

    uint64_t timestamp;
    {
      timeval now;
      gettimeofday(&now, NULL);
      timestamp = now.tv_sec * 1000LL + now.tv_usec / 1000;
    }
    Append8LE(header + 12, timestamp);
  }

  // Create empty file to log data
  int last_bin_index = the_trace->data_bin_index_;
  std::string trace_data_filename(StringPrintf("%sdata_%d.bin",
      the_trace->prefix_, last_bin_index));
  std::string trace_method_info_filename(StringPrintf("%sinfo_m.log", the_trace->prefix_));
  std::string trace_field_info_filename(StringPrintf("%sinfo_f.log", the_trace->prefix_));
  std::string trace_thread_info_filename(StringPrintf("%sinfo_t.log", the_trace->prefix_));

  File *trace_data_file_ = OS::CreateEmptyFile(trace_data_filename.c_str());
  CHECK(trace_data_file_ != NULL);

  // Write header
  if (!trace_data_file_->WriteFully(header, kMiniTraceHeaderLength)) {
    std::string detail(StringPrintf("MiniTrace: Trace data write failed: %s", strerror(errno)));
    PLOG(ERROR) << detail;
    {
      Locks::mutator_lock_->ExclusiveLock(self);
      ThrowRuntimeException("%s", detail.c_str());
      Locks::mutator_lock_->ExclusiveUnlock(self);
    }
  }

  File *trace_method_info_file_ = OS::CreateEmptyFile(trace_method_info_filename.c_str());
  CHECK(trace_method_info_file_ != NULL);

  File *trace_field_info_file_ = OS::CreateEmptyFile(trace_field_info_filename.c_str());
  CHECK(trace_field_info_file_ != NULL);

  File *trace_thread_info_file_ = OS::CreateEmptyFile(trace_thread_info_filename.c_str());
  CHECK(trace_thread_info_file_ != NULL);

  char *databuf = new char[the_trace->buffer_size_];
  size_t len, woff;
  std::string buffer;
  while (the_trace->consumer_runs_) {
    // Dump Buffer
    len = ringbuf_consume(the_trace->ringbuf_, &woff);
    if (len > 0) {
      // If data_bin_index_ is modified, flush previous data and create a new file
      if (last_bin_index != the_trace->data_bin_index_) {
        // release and send its filename to socket
        CHECK(trace_data_file_->Flush() == 0);
        CHECK(trace_data_file_->Close() == 0);
        write(the_trace->socket_fd_, trace_data_filename.c_str(), trace_data_filename.length() + 1);
        last_bin_index = the_trace->data_bin_index_;
        trace_data_filename.assign(StringPrintf("%sdata_%d.bin",
            the_trace->prefix_, last_bin_index));
        trace_data_file_ = OS::CreateEmptyFile(trace_data_filename.c_str());
        CHECK(trace_data_file_ != NULL);

        // Write header
        if (!trace_data_file_->WriteFully(header, kMiniTraceHeaderLength)) {
          std::string detail(StringPrintf("MiniTrace: Trace data write failed: %s", strerror(errno)));
          PLOG(ERROR) << detail;
          {
            Locks::mutator_lock_->ExclusiveLock(self);
            ThrowRuntimeException("%s", detail.c_str());
            Locks::mutator_lock_->ExclusiveUnlock(self);
          }
        }
      }
      the_trace->ReadBuffer(databuf, woff, len);
      ringbuf_release(the_trace->ringbuf_, len);

      // Save to data binary file
      if (!trace_data_file_->WriteFully(databuf, len)) {
        std::string detail(StringPrintf("MiniTrace: Trace data write failed: %s", strerror(errno)));
        PLOG(ERROR) << detail;
        {
          Locks::mutator_lock_->ExclusiveLock(self);
          ThrowRuntimeException("%s", detail.c_str());
          Locks::mutator_lock_->ExclusiveUnlock(self);
        }
      }

      // If size exceeds 1GB, release it
      // Same as checkout - @TODO differentiate those
      int64_t size = trace_data_file_->GetLength();
      if (size >= 1024 * 1024 * 1024)
        the_trace->data_bin_index_++;
    }

    // Dump Method
    {
      MutexLock mu(self, *the_trace->traced_method_lock_);
      the_trace->DumpMethod(buffer);
    }
    if (!buffer.empty()) {
      if (!trace_method_info_file_->WriteFully(buffer.c_str(), buffer.length())) {
        std::string detail(StringPrintf("MiniTrace: Trace method info write failed: %s", strerror(errno)));
        PLOG(ERROR) << detail;
        {
          Locks::mutator_lock_->ExclusiveLock(self);
          ThrowRuntimeException("%s", detail.c_str());
          Locks::mutator_lock_->ExclusiveUnlock(self);
        }
      }
    }

    // Dump Field
    {
      MutexLock mu(self, *the_trace->traced_field_lock_);
      the_trace->DumpField(buffer);
    }
    if (!buffer.empty()) {
      if (!trace_field_info_file_->WriteFully(buffer.c_str(), buffer.length())) {
        std::string detail(StringPrintf("MiniTrace: Trace field info write failed: %s", strerror(errno)));
        PLOG(ERROR) << detail;
        {
          Locks::mutator_lock_->ExclusiveLock(self);
          ThrowRuntimeException("%s", detail.c_str());
          Locks::mutator_lock_->ExclusiveUnlock(self);
        }
      }
    }

    // Dump Thread
    {
      MutexLock mu(self, *the_trace->traced_thread_lock_);
      the_trace->DumpThread(buffer);
    }
    if (!buffer.empty()) {
      if (!trace_thread_info_file_->WriteFully(buffer.c_str(), buffer.length())) {
        std::string detail(StringPrintf("MiniTrace: Trace thread info write failed: %s", strerror(errno)));
        PLOG(ERROR) << detail;
        {
          Locks::mutator_lock_->ExclusiveLock(self);
          ThrowRuntimeException("%s", detail.c_str());
          Locks::mutator_lock_->ExclusiveUnlock(self);
        }
      }
    }
  }

  delete databuf;
  delete header;
  CHECK(trace_data_file_->Flush() == 0);
  CHECK(trace_data_file_->Close() == 0);
  CHECK(trace_method_info_file_->Flush() == 0);
  CHECK(trace_method_info_file_->Close() == 0);
  CHECK(trace_field_info_file_->Flush() == 0);
  CHECK(trace_field_info_file_->Close() == 0);
  CHECK(trace_thread_info_file_->Flush() == 0);
  CHECK(trace_thread_info_file_->Close() == 0);

  write(the_trace->socket_fd_, trace_method_info_filename.c_str(),
      trace_method_info_filename.length() + 1);
  write(the_trace->socket_fd_, trace_field_info_filename.c_str(),
      trace_field_info_filename.length() + 1);
  write(the_trace->socket_fd_, trace_thread_info_filename.c_str(),
      trace_thread_info_filename.length() + 1);
  write(the_trace->socket_fd_, trace_data_filename.c_str(),
      trace_data_filename.length() + 1);
  runtime->DetachCurrentThread();
  return NULL;
}

void *MiniTrace::IdleCheckTask(void *arg) {
  MiniTrace *the_trace = (MiniTrace *)arg;
  Runtime* runtime = Runtime::Current();
  CHECK(runtime->AttachCurrentThread("IdleCheck", true, runtime->GetSystemThreadGroup(),
                                       !runtime->IsCompiler()));

  Thread *self = Thread::Current();
  JNIEnvExt *env = self->GetJniEnv();
  LOG(INFO) << "MiniTrace IdleCheck tid " << self->GetTid();

  while (the_trace->msg_taken_ == false) {
    usleep(500000); // 0.5 second
  }

  // Don't log for this thread,
  // just get ringbuf worker and log idle time
  ringbuf_worker_t *ringbuf_worker = NULL;
  {
    MutexLock mu(self, *the_trace->wids_registered_lock_);
    for (size_t i=0; i<MAX_THREAD_COUNT; i++) {
      if (the_trace->wids_registered_[i] == false) {
        ringbuf_worker = ringbuf_register(the_trace->ringbuf_, i);
        the_trace->wids_registered_[i] = true;
        break;
      }
    }
  }
  LOG(INFO) << "MiniTrace IdleCheck worker " << ringbuf_worker;
  CHECK(ringbuf_worker != NULL);

  /**
   * Wait for idle state of MainLooper
   * Technique borrowed from Instrumentation$waitForIdleSync
   * Implemented following JAVA code
   * $ mainLooper = Looper.getMainLooper();
   * $ mainQueue = mainlooper.getQueue();
   * $ mainHandler = new Handler(mainLooper);
   * $ Idler ider = new Idler(null);
   * $ Runnable emptyRunnable = new EmptyRunnable();
   */
  ScopedLocalRef<jclass> looperClass(env, env->FindClass("android/os/Looper"));
  ScopedLocalRef<jclass> queueClass(env, env->FindClass("android/os/MessageQueue"));
  ScopedLocalRef<jclass> handlerClass(env, env->FindClass("android/os/Handler"));
  ScopedLocalRef<jclass> idlerClass(env, env->FindClass("android/app/Instrumentation$Idler"));
  ScopedLocalRef<jclass> emptyRunnableClass(env, env->FindClass("android/app/Instrumentation$EmptyRunnable"));

  jmethodID getMainLooper = env->GetStaticMethodID(looperClass.get(),
      "getMainLooper", "()Landroid/os/Looper;");
  jmethodID getQueue = env->GetMethodID(looperClass.get(),
      "getQueue", "()Landroid/os/MessageQueue;");
  jmethodID addIdleHandler = env->GetMethodID(queueClass.get(),
      "addIdleHandler", "(Landroid/os/MessageQueue$IdleHandler;)V");
  jmethodID handlerInit = env->GetMethodID(handlerClass.get(),
      "<init>", "(Landroid/os/Looper;)V");
  jmethodID post = env->GetMethodID(handlerClass.get(),
      "post", "(Ljava/lang/Runnable;)Z");
  jmethodID idlerInit = env->GetMethodID(idlerClass.get(),
      "<init>", "(Ljava/lang/Runnable;)V");
  jmethodID waitForIdle = env->GetMethodID(idlerClass.get(),
      "waitForIdle", "()V");
  jmethodID runnableInit = env->GetMethodID(emptyRunnableClass.get(),
      "<init>", "()V");

  ScopedLocalRef<jobject> mainLooper(env, env->CallStaticObjectMethod(looperClass.get(), getMainLooper));
  ScopedLocalRef<jobject> mainQueue(env, env->CallObjectMethod(mainLooper.get(), getQueue));
  ScopedLocalRef<jobject> mainHandler(env, env->NewObject(handlerClass.get(), handlerInit, mainLooper.get()));

  /* Objects, idler and emptyRunnable, are used in main thread */
  jobject idler = env->NewGlobalRef(env->NewObject(idlerClass.get(), idlerInit, 0));
  jobject emptyRunnable = env->NewGlobalRef(env->NewObject(emptyRunnableClass.get(), runnableInit));
  Locks::mutator_lock_->SharedLock(self);
  the_trace->idlecheck_idler_ = self->DecodeJObject(idler);
  the_trace->idlecheck_emptyRunnable_ = self->DecodeJObject(emptyRunnable);
  Locks::mutator_lock_->SharedUnlock(self);

  timeval now;
  uint64_t now_long;
  char buf[10];
  Append2LE(buf, 0); // tid

  while (1) {
    /**
     * Implemented following JAVA code
     * $ mainQueue.addIdleHandler(idler);
     * $ mainHandler.post(emptyRunnable);
     * $ idler.waitForIdle();
     */
    env->CallVoidMethod(mainQueue.get(), addIdleHandler, idler);
    env->CallBooleanMethod(mainHandler.get(), post, emptyRunnable);
    env->CallVoidMethod(idler, waitForIdle);
    the_trace->msg_taken_ = false;
    gettimeofday(&now, NULL);
    now_long = now.tv_sec * 1000LL + now.tv_usec / 1000;

    // write all idle state
    Append8LE(buf + 2, now_long);
    the_trace->WriteRingBuffer(ringbuf_worker, buf, 10);
    write(the_trace->ape_socket_fd_, &now_long, sizeof (uint64_t));
    while (the_trace->msg_taken_ == false) {
      usleep(500000);
    }
  }

  runtime->DetachCurrentThread();
  return NULL;
}

void *MiniTrace::PingingTask(void *arg) {
  MiniTrace *the_trace = (MiniTrace *)arg;
  Runtime* runtime = Runtime::Current();
  CHECK(runtime->AttachCurrentThread("Pinging", true, runtime->GetSystemThreadGroup(),
                                       !runtime->IsCompiler()));

  Thread *self = Thread::Current();
  LOG(INFO) << "MiniTrace: Pinging thread attached with tid " << self->GetTid();

  // Don't log for this thread,
  // just get ringbuf worker and log idle time
  ringbuf_worker_t *ringbuf_worker = NULL;
  {
    MutexLock mu(self, *the_trace->wids_registered_lock_);
    for (size_t i=0; i<MAX_THREAD_COUNT; i++) {
      if (the_trace->wids_registered_[i] == false) {
        ringbuf_worker = ringbuf_register(the_trace->ringbuf_, i);
        the_trace->wids_registered_[i] = true;
        break;
      }
    }
  }
  CHECK(ringbuf_worker != NULL);

  char buf[10];
  Append2LE(buf, 1); // tid = 1

  timeval now;
  uint64_t timestamp;
  while (true) {
    gettimeofday(&now, NULL);
    timestamp = now.tv_sec * 1000LL + now.tv_usec / 1000;
    Append8LE(buf + 2, timestamp);
    the_trace->WriteRingBuffer(ringbuf_worker, buf, 10);

    usleep(1000000); // 1 second
  }
  runtime->DetachCurrentThread();

  return NULL;
}

void MiniTrace::new_android_os_MessageQueue_nativePollOnce(JNIEnv* env, jclass clazz,
        jlong ptr, jint timeoutMillis) {
  typedef void (fntype)(JNIEnv*, jclass, jlong, jint);
  LOG(INFO) << "MiniTrace: nativePollOnce";
  fntype* const fn = reinterpret_cast<fntype*>(MiniTrace::nativePollOnce_originalEntry);
  fn(env, clazz, ptr, timeoutMillis);
  LOG(INFO) << "MiniTrace: nativePollOnce exit...";
}

MiniTrace::MiniTrace(int socket_fd, const char *prefix,
        uint32_t log_flag, uint32_t buffer_size, int ape_socket_fd)
    : socket_fd_(socket_fd), data_bin_index_(0),
      buf_(new uint8_t[buffer_size]()),
      wids_registered_lock_(new Mutex("Ringbuf worker lock")),
      consumer_runs_(true), consumer_tid_(0),
      log_flag_(log_flag), do_coverage_((log_flag & kDoCoverage) != 0),
      buffer_size_(buffer_size), start_time_(MicroTime()),
      traced_method_lock_(new Mutex("MiniTrace method lock")),
      traced_field_lock_(new Mutex("MiniTrace field lock")),
      traced_thread_lock_(new Mutex("MiniTrace thread lock")),
      main_msgq_(NULL), msg_taken_(false),
      ape_socket_fd_(ape_socket_fd), idlecheck_idler_(0), idlecheck_emptyRunnable_(0),
      idlecheck_thread_(0), queueIdle_level_(0), pinging_thread_(0) {

  // Set prefix
  strcpy(prefix_, prefix);

  // Initialize MPSC ring buffer
  size_t ringbuf_obj_size;
  ringbuf_get_sizes(MAX_THREAD_COUNT, &ringbuf_obj_size, NULL);

  ringbuf_ = (ringbuf_t *) malloc(ringbuf_obj_size);
  ringbuf_setup(ringbuf_, MAX_THREAD_COUNT, buffer_size);

  for (size_t i=0; i<MAX_THREAD_COUNT; i++) {
    wids_registered_[i] = false;
  }

  main_thread_ = Thread::Current();
  env_ = main_thread_->GetJniEnv();

  ScopedObjectAccess soa(env_);
  ScopedLocalRef<jclass> queueClass(env_, env_->FindClass("android/os/MessageQueue"));
  jmethodID next = env_->GetMethodID(queueClass.get(), "next", "()Landroid/os/Message;");
  method_msgq_next_ = soa.DecodeMethod(next);
  jmethodID enqueueMessage = env_->GetMethodID(queueClass.get(), "enqueueMessage", "(Landroid/os/Message;J)Z");
  method_msgq_enqueueMessage_ = soa.DecodeMethod(enqueueMessage);


  // ScopedFastNativeObjectAccess soa_n(env_);
  mirror::Class* mirror_queueClass = soa.Decode<mirror::Class*>(queueClass.get());
  mirror::ArtMethod *method_nativePollOnce = mirror_queueClass->FindDirectMethod("nativePollOnce", "(JI)V");

  nativePollOnce_originalEntry = method_nativePollOnce->GetEntryPointFromJni();
  method_nativePollOnce->SetEntryPointFromJni((void* )&new_android_os_MessageQueue_nativePollOnce);
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
  if (log_flag_ & kDoMethodEntered)
    LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodEntered);

  // Assume the first called next() is called with MessageQueue from main thread
  if (UNLIKELY(method_msgq_next_ == method && main_msgq_ == NULL)) {
    main_msgq_ = this_object;
  }

  if (UNLIKELY(main_msgq_ == this_object
               && (log_flag_ & kConnectAPE)
               && method == method_msgq_enqueueMessage_
               && queueIdle_level_ > 0)) {
    {
      MiniTraceThreadFlag orig_flag = thread->GetMiniTraceFlag();
      thread->SetMiniTraceFlag(kMiniTraceExclude);

      // enqueueMessage uses elapsed time after booting
      // $ long uptimeMillis = SystemClock.uptimeMillis();
      // It returns different value with System.currentTimeMillis();
      int uptimeMillis = systemTime(SYSTEM_TIME_MONOTONIC) / 1000000;

      /**
       * Fetch 2nd argument of enqueueMessage "when"
       * enqueueMessage uses v9 as msg and v10 as when
       * Analyzed bytecode of enqueueMessage with following code
       *
       * const DexFile::CodeItem* code_item = method_msgq_enqueueMessage_->GetCodeItem();
       * const Instruction* inst;
       * for (int i=0; i<300; i++) {
       *   inst = Instruction::At(code_item->insns_ + dex_pc);
       *   LOG(INFO) << "enqueueMessage" << i << ": " << inst->DumpString(method->GetDexFile());
       *   dex_pc += inst->SizeInCodeUnits();
       * }
       */
      int64_t when = thread->GetManagedStack()->GetTopShadowFrame()->GetVRegLong(10);
      if (when < uptimeMillis + 50) {
        // The message is going to be handled soon
        // Then wait new idlehandler
        msg_enqueued_cnt_++;
      }
      thread->SetMiniTraceFlag(orig_flag);
    }
  }

  if (log_flag_ & kConnectAPE) {
    /* Check every queueIdle */
    if (UNLIKELY(thread == main_thread_ && method->GetMiniTraceType() == 2)) {
      queueIdle_level_++;
    }
  }
}

void MiniTrace::MethodExited(Thread* thread, mirror::Object* this_object,
                         mirror::ArtMethod* method, uint32_t dex_pc,
                         const JValue& return_value) {
  if (log_flag_ & kDoMethodExited)
    LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodExited);

  if (log_flag_ & kLogMessage) {
    if (UNLIKELY(method_msgq_next_ == method && main_msgq_ == this_object))
      LogMessage(thread, return_value);
  }

  if (log_flag_ & kConnectAPE) {
    if (UNLIKELY(method_msgq_next_ == method && main_msgq_ == this_object)) {
      msg_taken_ = true;
    }

    /* Check every queueIdle */
    if (UNLIKELY(thread == main_thread_ && method->GetMiniTraceType() == 2)) {
      queueIdle_level_--;

      MiniTraceThreadFlag orig_flag = thread->GetMiniTraceFlag();
      thread->SetMiniTraceFlag(kMiniTraceExclude);

      // get remaining mIdleHandlers


      thread->SetMiniTraceFlag(orig_flag);
    }
  }
}

void MiniTrace::MethodUnwind(Thread* thread, mirror::Object* this_object,
                         mirror::ArtMethod* method, uint32_t dex_pc) {
  LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodUnwind);
}

void MiniTrace::ExceptionCaught(Thread* thread, const ThrowLocation& throw_location,
                            mirror::ArtMethod* catch_method, uint32_t catch_dex_pc,
                            mirror::Throwable* exception_object) {
  MiniTraceAction action = kMiniTraceExceptionCaught;

  ringbuf_worker_t *ringbuf_worker = GetRingBufWorker();
  if (ringbuf_worker == NULL)
    return;
  std::string content = exception_object->Dump();
  uint16_t record_size = content.length() + 2 + 4 + 1;
  char *buf = new char[record_size]();

  Append2LE(buf, thread->GetTid());
  Append4LE(buf + 2, (record_size << 3) | action);
  strcpy(buf + 6, content.c_str());

  WriteRingBuffer(ringbuf_worker, buf, record_size);
  delete buf;
}

void MiniTrace::LogMessage(Thread* thread, const JValue& message) {
  ringbuf_worker_t *ringbuf_worker = GetRingBufWorker();
  if (ringbuf_worker == NULL)
    return;

  static Thread *_thread = NULL;
  static JNIEnvExt *env = NULL;
  static jclass queueClass;
  static jmethodID toString;
  if (_thread == NULL) {
    // initialize
    _thread = thread;
    env = thread->GetJniEnv();
    queueClass = jclass(env->NewGlobalRef(env->FindClass("android/os/MessageQueue")));
    toString = env->GetMethodID(queueClass, "toString", "()Ljava/lang/String;");
  } else CHECK(_thread == thread);

  MiniTraceThreadFlag orig_flag = thread->GetMiniTraceFlag();
  thread->SetMiniTraceFlag(kMiniTraceExclude);

  ScopedLocalRef<jobject> jmessage(env, env->NewLocalRef(message.GetL()));
  ScopedLocalRef<jobject> message_string(env,
      env->CallObjectMethod(jmessage.get(), toString));
  const char* message_cstring = env->GetStringUTFChars((jstring) message_string.get(), 0);

  int32_t length = strlen(message_cstring);
  int32_t record_size = length + 2 + 4 + 1;
  char *buf = new char[record_size]();
  Append2LE(buf, thread->GetTid());
  Append4LE(buf + 2, (record_size << 3) | kMiniTraceMessageEvent);
  strcpy(buf + 6, message_cstring);

  env->ReleaseStringUTFChars((jstring) message_string.get(), message_cstring);
  WriteRingBuffer(ringbuf_worker, buf, record_size);
  thread->SetMiniTraceFlag(orig_flag);
  delete buf;
}

void MiniTrace::LogMethodTraceEvent(Thread* thread, mirror::ArtMethod* method, uint32_t dex_pc,
                                instrumentation::Instrumentation::InstrumentationEvent event) {
  uint32_t minitrace_type = method->GetMiniTraceType();
  if ((minitrace_type == 0 && !(log_flag_ & kLogMethodType0))
      || (minitrace_type == 1 && !(log_flag_ & kLogMethodType1))
      || (minitrace_type == 2 && !(log_flag_ & kLogMethodType2))
      || (minitrace_type == 3 && !(log_flag_ & kLogMethodType3)))
    return;

  MiniTraceAction action = kMiniTraceMethodEnter;
  switch (event) {
    case instrumentation::Instrumentation::kMethodEntered:
      action = kMiniTraceMethodEnter;
      break;
    case instrumentation::Instrumentation::kMethodExited:
      action = kMiniTraceMethodExit;
      break;
    case instrumentation::Instrumentation::kMethodUnwind:
      action = kMiniTraceUnwind;
      break;
    default:
      UNIMPLEMENTED(FATAL) << "MiniTrace: Unexpected event: " << event;
  }

  ringbuf_worker_t *ringbuf_worker = GetRingBufWorker();
  if (ringbuf_worker == NULL)
    return;
  LogNewMethod(method);

  char buf[6];
  uint32_t method_ptr = PointerToLowMemUInt32(method);
  DCHECK(~(method_ptr & kMiniTraceActionMask));
  Append2LE(buf, thread->GetTid());
  Append4LE(buf + 2, method_ptr | action);

  WriteRingBuffer(ringbuf_worker, buf, 6);
}

void MiniTrace::LogFieldTraceEvent(Thread* thread, mirror::Object *this_object, mirror::ArtField* field,
                                uint32_t dex_pc, bool read_event) {
  uint32_t minitrace_type = field->GetMiniTraceType();
  if ((minitrace_type == 0 && !(log_flag_ & kLogFieldType0))
      || (minitrace_type == 1 && !(log_flag_ & kLogFieldType1))
      || (minitrace_type == 2 && !(log_flag_ & kLogFieldType2))
      || (minitrace_type == 3 && !(log_flag_ & kLogFieldType3)))
    return;

  MiniTraceAction action;
  if (read_event) {
    action = kMiniTraceFieldRead;
  } else {
    action = kMiniTraceFieldWrite;
  }

  ringbuf_worker_t *ringbuf_worker = GetRingBufWorker();
  if (ringbuf_worker == NULL)
    return;
  uint16_t fieldDetailIdx = LogNewField(field);

  char buf[16];
  Append2LE(buf, thread->GetTid());
  Append4LE(buf + 2, PointerToLowMemUInt32(field) | action);
  Append4LE(buf + 6, PointerToLowMemUInt32(this_object));
  Append4LE(buf + 10, dex_pc);
  Append2LE(buf + 14, fieldDetailIdx);

  WriteRingBuffer(ringbuf_worker, buf, 16);
}

void MiniTrace::StoreExitingThreadInfo(Thread* thread) {
  MutexLock mu(thread, *Locks::trace_lock_);
  if (the_trace_ != nullptr) {
    the_trace_->UnregisterThread(thread);
  }
}

void MiniTrace::DumpMethod(std::string &string) {
  Thread *self = Thread::Current();
  traced_method_lock_->AssertHeld(self);
  string.assign("");
  for (auto& it: methods_not_stored_) {
    (&it)->Dump(string);
  }
  methods_not_stored_.clear();
}

void MiniTrace::DumpField(std::string &string) {
  Thread *self = Thread::Current();
  traced_field_lock_->AssertHeld(self);
  string.assign("");
  for (auto it: fields_not_stored_) {
    (*it).Dump(string);
  }
  fields_not_stored_.clear();
}

void MiniTrace::DumpThread(std::string &string) {
  Thread *self = Thread::Current();
  traced_thread_lock_->AssertHeld(self);
  string.assign("");
  for (auto& it : threads_not_stored_) {
    (&it)->Dump(string);
  }
  threads_not_stored_.clear();
}

void MiniTrace::LogNewMethod(mirror::ArtMethod *method) {
  MutexLock mu(Thread::Current(), *traced_method_lock_);
  auto it = visited_methods_.insert(method);
  if (it.second)
    methods_not_stored_.emplace_back(method);
}

uint16_t MiniTrace::LogNewField(mirror::ArtField *field) {
  Thread *self = Thread::Current();
  MutexLock mu(self, *traced_field_lock_);
  auto it = visited_fields_.emplace(field);
  // std::set<ArtFieldDetail>::iterator it2 = it.first;
  // ArtFieldDetail fieldDetail = *it2;
  // std::set<ArtFieldDetail>::iterator it2 = it.first;
  const ArtFieldDetail *fieldDetail = &(*(it.first));
  if (it.second) {
    fields_not_stored_.push_back(fieldDetail);
    return 0;
  } else {
    // ArtFieldDetail fieldDetail = *(it.first);
    return fieldDetail->FindIdx(field);
  }
}

bool* MiniTrace::GetExecutionData(Thread* self, mirror::ArtMethod* method) {
  if (method->IsRuntimeMethod() || method->IsProxyMethod()) {  // No profile for execution data
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

    uint32_t minitrace_type = method->GetMiniTraceType();
    if ((minitrace_type == 0 && !(the_trace->log_flag_ & kLogMethodType0))
        || (minitrace_type == 1 && !(the_trace->log_flag_ & kLogMethodType1))
        || (minitrace_type == 2 && !(the_trace->log_flag_ & kLogMethodType2))
        || (minitrace_type == 3 && !(the_trace->log_flag_ & kLogMethodType3)))
      return NULL;

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

void MiniTrace::PostClassPrepare(mirror::Class* klass, const char *descriptor) {
  static mirror::Class *idleHandlerClass = NULL;
  if (idleHandlerClass == NULL && strcmp(descriptor, "Landroid/os/MessageQueue$IdleHandler;") == 0) {
    idleHandlerClass = klass;
  }

  if (klass->IsArrayClass() || klass->IsInterface() || klass->IsPrimitive()) {
    return;
  }

  static const DexFile *apkDexFile = NULL;
  const DexFile& dxFile = klass->GetDexFile();
  if (apkDexFile == NULL && (dxFile.GetLocation().rfind("/data/app/", 0) == 0))
    apkDexFile = &dxFile;
  CHECK((apkDexFile == NULL) || (dxFile.GetLocation().rfind("/data/app/", 0) != 0) || apkDexFile == &dxFile);

  // (strncmp(descriptor, "Ljava/", 6) == 0)
  //  || (strncmp(descriptor, "Ljavax/", 7) == 0)
  //  || (strncmp(descriptor, "Lsun/", 5) == 0)
  //  || (strncmp(descriptor, "Lcom/sun/", 9) == 0)
  //  || (strncmp(descriptor, "Lcom/ibm/", 9) == 0)
  //  || (strncmp(descriptor, "Lorg/xml/", 9) == 0)
  //  || (strncmp(descriptor, "Lorg/w3c/", 9) == 0)
  //  || (strncmp(descriptor, "Lapple/awt/", 11) == 0)
  //  || (strncmp(descriptor, "Lcom/apple/", 11) == 0)
  //  || (strncmp(descriptor, "Landroid/", 9) == 0)
  //  || (strncmp(descriptor, "Lcom/android/", 13) == 0)

  if (&dxFile == apkDexFile) {
    // App-specific fields
    {
      size_t num_fields = klass->NumInstanceFields();
      mirror::ObjectArray<mirror::ArtField>* fields = klass->GetIFields();

      for (size_t i = 0; i < num_fields; i++) {
        mirror::ArtField* f = fields->Get(i);
        f->SetMiniTraceType(3);
      }
    }

    {
      size_t num_fields = klass->NumStaticFields();
      mirror::ObjectArray<mirror::ArtField>* fields = klass->GetSFields();

      for (size_t i = 0; i < num_fields; i++) {
        mirror::ArtField* f = fields->Get(i);
        f->SetMiniTraceType(3);
      }
    }

    // App-specific methods
    for (size_t i = 0, e = klass->NumDirectMethods(); i < e; i++) {
      klass->GetDirectMethod(i)->SetMiniTraceType(3);
    }
    for (size_t i = 0, e = klass->NumVirtualMethods(); i < e; i++) {
      klass->GetVirtualMethod(i)->SetMiniTraceType(3);
    }
  } else {
    // API methods
    if ((strncmp(descriptor, "Ljava/", 6) != 0)
        && (strncmp(descriptor, "Llibcore/", 9) != 0)
        && (strncmp(descriptor, "Landroid/system/", 16) != 0)
        && (strncmp(descriptor, "Landroid/os/StrictMode", 22) != 0)
        && (strncmp(descriptor, "Ldalvik/system/", 15) != 0)
        && (strncmp(descriptor, "Lcom/android/dex/", 17) != 0)
        && (strncmp(descriptor, "Lcom/android/internal/util/", 27) != 0)
        && (strncmp(descriptor, "Lorg/apache/harmony/", 20) != 0)) {
      // Non-basic API methods are type 1
      for (size_t i = 0, e = klass->NumDirectMethods(); i < e; i++) {
        klass->GetDirectMethod(i)->SetMiniTraceType(1);
      }
      for (size_t i = 0, e = klass->NumVirtualMethods(); i < e; i++) {
        klass->GetVirtualMethod(i)->SetMiniTraceType(1);
      }
    }
    // Basic methods among API methods are type 0
  }

  // Mark queueIdle method of Landroid/os/MessageQueue$IdleHandler
  int32_t iftable_count = klass->GetIfTableCount();
  mirror::IfTable* iftable = klass->GetIfTable();
  for (int32_t i = 0; i < iftable_count; ++i) {
    mirror::Class *interface = iftable->GetInterface(i);
    if (interface == idleHandlerClass) {
      mirror::ArtMethod *method = klass->FindDeclaredVirtualMethod("queueIdle", "()Z");
      CHECK(method != NULL);
      method->SetMiniTraceType(2);
      break;
    }
  }
}

/* Register new thread and returns true if the thread is on our interest
 * otherwise returns false
 */
ringbuf_worker_t *MiniTrace::GetRingBufWorker() {
  Thread *self = Thread::Current();

  MiniTraceThreadFlag flag = self->GetMiniTraceFlag();
  if (flag == kMiniTraceFirstSeen) {
    pthread_t pself = pthread_self();
    if (pself == consumer_thread_
        || (idlecheck_thread_ != 0 && pself == idlecheck_thread_)
        || (pinging_thread_ != 0 && pself == pinging_thread_)) {
      self->SetMiniTraceFlag(kMiniTraceExclude);
      return NULL;
    }
    std::string name;
    self->GetThreadName(name);
    for (size_t i=0; i<THREAD_TO_EXCLUDE_CNT; i++) {
      if (name.compare(threadnames_to_exclude[i]) == 0) {
        self->SetMiniTraceFlag(kMiniTraceExclude);
        return NULL;
      }
    }

    // Find available worker slot
    ringbuf_worker_t *ringbuf_worker = NULL;
    {
      MutexLock mu(self, *wids_registered_lock_);
      for (size_t i=0; i<MAX_THREAD_COUNT; i++) {
        if (wids_registered_[i] == false) {
          ringbuf_worker = ringbuf_register(ringbuf_, i);
          wids_registered_[i] = true;
          break;
        }
      }
    }
    if (ringbuf_worker == NULL) {
      // No avilable worker slot
      LOG(ERROR) << "MiniTrace: There are too many active threads";
      self->SetMiniTraceFlag(kMiniTraceExclude);
      return NULL;
    }
    {
      MutexLock mu(self, *traced_thread_lock_);
      threads_not_stored_.emplace_back(self->GetTid(), name);
    }

    self->SetMiniTraceFlag(kMiniTraceMarked);
    self->SetRingBufWorker(ringbuf_worker);
    return ringbuf_worker;
  }
  if (flag == kMiniTraceMarked) {
    return self->GetRingBufWorker();
  }
  return NULL;
}

void MiniTrace::UnregisterThread(Thread *thread) {
  CHECK_EQ(thread, Thread::Current());

  size_t wid;
  ringbuf_worker_t *ringbuf_worker;
  if (thread->GetMiniTraceFlag() == kMiniTraceMarked) {
    ringbuf_worker = thread->GetRingBufWorker();
    wid = ringbuf_w2i(ringbuf_, ringbuf_worker);
    {
      MutexLock mu(thread, *wids_registered_lock_);
      wids_registered_[wid] = false;
    }
    ringbuf_unregister(ringbuf_, ringbuf_worker);
    thread->SetMiniTraceFlag(kMiniTraceExclude);
  }
}

}  // namespace art
