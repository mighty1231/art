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

#ifdef HAVE_ANDROID_OS
#include <utils/Looper.h>
#endif

namespace art {

/**
 * [ MiniTrace Version 2 ]
 *
 * *.bin file format:
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
 * Idle event - length 10 (no action, identify this among events with tid=0)
 *   u2 tid=0;
 *   u8 timestamp_in_ms;
 *
 * Pinging event - length 10 (no action, identify this among events with tid=1)
 *   u2 tid=1;
 *   u8 timestamp_in_ms;
 *
 * Thread terminated event - length 6 (no action, identify this among events with tid=2)
 *   u2 tid=2;
 *   s4 tid_terminated;
 *
 * Target met alarm - length 10 (Enter/Exit/Unroll)
 *   u2 mode=(3|4|5);
 *   u4 tid;
 *   u4 target_id;
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
static const uint16_t kMiniTraceVersion          = 3;
static const uint32_t kMiniTraceMagic            = 0x7254694D;  // MiTr
void *MiniTrace::nativePollOnce_originalEntry = NULL;
int MiniTrace::MessageDetail::cur_id_ = 0;
std::map<Thread *, std::vector<MiniTrace::MessageDetail*>> MiniTrace::MessageDetail::thread_to_msgstack_;
std::map<mirror::Object *, MiniTrace::MessageDetail *> MiniTrace::MessageDetail::last_messages_;
mirror::ArtMethod *MiniTrace::method_msgq_next_ = NULL;
mirror::ArtMethod *MiniTrace::method_msgq_enqueueMessage_ = NULL;
mirror::ArtMethod *MiniTrace::method_msgq_nativePollOnce_ = NULL;
mirror::ArtMethod *MiniTrace::method_Message_recycleUnchecked_ = NULL;
mirror::ArtMethod *MiniTrace::method_Message_toString_ = NULL;
mirror::ArtMethod *MiniTrace::method_Binder_execTransact_ = NULL;
mirror::ArtField *MiniTrace::field_Binder_mDescriptor_ = NULL;
mirror::ArtMethod *MiniTrace::method_BinderProxy_transact_ = NULL;
mirror::ArtMethod *MiniTrace::method_BinderProxy_getInterfaceDescriptor_ = NULL;
mirror::ArtMethod *MiniTrace::method_InputEventReceiver_dispatchInputEvent_ = NULL;
mirror::ArtMethod *MiniTrace::method_InputEventReceiver_finishInputEvent_ = NULL;

const int MiniTrace::kApeHandShake         = 0x0abeabe0;
const int MiniTrace::kApeHandShakeNoGuide  = 0x1abeabe1;
const int MiniTrace::kApeTargetEntered     = 0xabeabe01;
const int MiniTrace::kApeTargetExited      = 0xabeabe02;
const int MiniTrace::kApeTargetUnwind      = 0xabeabe03;
const int MiniTrace::kApeIdle              = 0xabe0de04;

std::vector<MiniTrace::MessageDetail *> MiniTrace::MessageDetail::messages_;
Mutex *MiniTrace::MessageDetail::lock = NULL;


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
  *reinterpret_cast<uint16_t *>(buf) = val;
}

static void Append4LE(char* buf, uint32_t val) {
  *reinterpret_cast<uint32_t *>(buf) = val;
}

static void Append8LE(char* buf, uint64_t val) {
  *reinterpret_cast<uint64_t *>(buf) = val;
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

void StringAppendArgumentValues(std::string *string_p, mirror::ArtMethod *method, ShadowFrame *shadow_frame) {
  CHECK(!method->IsAbstract());
  const DexFile::CodeItem* code_item = method->GetCodeItem();
  uint16_t num_regs;
  uint16_t num_ins;
  if (code_item != NULL) {
    num_regs =  code_item->registers_size_;
    num_ins = code_item->ins_size_;
  } else {
    DCHECK(method->IsNative());
    num_regs = num_ins = mirror::ArtMethod::NumArgRegisters(method->GetShorty());
    if (!method->IsStatic()) {
      num_regs++;
      num_ins++;
    }
  }

  size_t cur_reg = num_regs - num_ins;
  if (!method->IsStatic()) {
    mirror::Object *receiver = shadow_frame->GetVRegReference(cur_reg);
    StringAppendF(string_p, " this:%p", receiver);
    ++cur_reg;
  }
  uint32_t shorty_len = 0;
  const char* shorty = method->GetShorty(&shorty_len);
  for (size_t shorty_pos = 0, arg_pos = 0; cur_reg < num_regs; ++shorty_pos, ++arg_pos, cur_reg++) {
    DCHECK_LT(shorty_pos + 1, shorty_len);
    switch (shorty[shorty_pos + 1]) {
      case 'L': {
        StringAppendF(string_p, " %c:%p",
            shorty[shorty_pos+1],
            shadow_frame->GetVRegReference(cur_reg));
        break;
      }
      case 'J': case 'D': {
        StringAppendF(string_p, " %c:%" PRId64,
            shorty[shorty_pos+1],
            shadow_frame->GetVRegLong(cur_reg));
        cur_reg++;
        arg_pos++;
        break;
      }
      default:
        StringAppendF(string_p, " %c:%d",
            shorty[shorty_pos+1],
            shadow_frame->GetVReg(cur_reg));
        break;
    }
  }
}

static int read_with_timeout(int socket_fd, void *buf, int size, int timeout_sec = 1) {
  int total_written = 0;
  int written;
  if (timeout_sec <= 0 || timeout_sec > 10) {
    return 0;
  }
  uint32_t run_until = (uint32_t) time(NULL) + timeout_sec;
  int attempt = 0;
  while (total_written < size) {
    written = read(socket_fd, reinterpret_cast<char *>(buf) + total_written, size - total_written);
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

  if (connect(socket_fd, reinterpret_cast<sockaddr *>(&server_addr), addrlen) < 0) {
    if (errno != 111)
      PLOG(ERROR) << "MiniTrace: connect " << errno;
    close(socket_fd);
    return -1;
  }
  LOG(INFO) << "MiniTrace: connect success!";

  uid_t targetuid;
  int32_t prefix_length;
  int written = read_with_timeout(socket_fd, &targetuid, sizeof(uid_t), 3);
  if (written == sizeof(uid_t)) {
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
    PLOG(ERROR) << "MiniTrace::ConnectAPE - socket " << errno;
    return -1;
  }

  memset(&server_addr, 0, sizeof server_addr);
  server_addr.sun_family = AF_UNIX;
  strcpy(&server_addr.sun_path[1], "/dev/mt/ape");
  int addrlen = sizeof server_addr.sun_family + strlen(&server_addr.sun_path[1]) + 1;

  if (connect(socket_fd, reinterpret_cast<sockaddr *>(&server_addr), addrlen) < 0) {
    PLOG(ERROR) << "MiniTrace::ConnectAPE - connect " << errno;
    close(socket_fd);
    return -1;
  }
  LOG(INFO) << "MiniTrace::ConnectAPE - connect success!";
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
  JNIEnvExt *env = self->GetJniEnv();
  MiniTrace *the_trace;
  uint32_t log_flag, listener_flag;
  std::map<mirror::ArtMethod*, std::pair<int, int>> *mtd_targets = NULL;
  std::vector<lazy_target> *lazy_targets = NULL;
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_trace_ != NULL)  // Already started
      return;

    int socket_fd = CreateSocketAndCheckUIDAndPrefix(prefix, uid, &log_flag);
    listener_flag = log_flag;
    if (socket_fd == -1)
      return;
    LOG(INFO) << "MiniTrace: connection success, received prefix="
        << prefix << " log_flag=" << log_flag;

    CHECK(!(log_flag & ~kFlagAll));
    CHECK(!(log_flag & (kDoMethodEntered | kDoMethodExited | kDoMethodUnwind))
      || (log_flag & kLogMethodTypeFlags));
    CHECK(!(log_flag & (kDoFieldRead | kDoFieldWritten))
      || (log_flag & kLogFieldTypeFlags));

    // Currently UNUSED flags
    CHECK(!(log_flag & kLogFieldType1));
    CHECK(!(log_flag & kLogFieldType2));

    // To turn on kConnectAPE, kLogMessage should be turn on.
    CHECK(!(log_flag & kConnectAPE && !(log_flag & kLogMessage)));
    int ape_socket_fd = -1;
    if (log_flag & kConnectAPE) {
      ape_socket_fd = CreateSocketAndCheckAPE();
      CHECK_NE(ape_socket_fd, -1);

      // read targeting methods
      int32_t hsval, num_funcs, string_length, flag;
      char *clsname = new char[128];
      char *methodname = new char[128];
      char *signature = new char[512];
      int written;
      CHECK((written = write(ape_socket_fd, &kApeHandShake, 4)) == 4)
            << StringPrintf("MiniTrace: ConnectAPE - write handshake %d %s", written, strerror(errno));
      CHECK((written = read_with_timeout(ape_socket_fd, &hsval, 4)) == 4)
            << StringPrintf("MiniTrace: ConnectAPE - read handshake %d %s", written, strerror(errno));
      CHECK(hsval == kApeHandShake || hsval == kApeHandShakeNoGuide)
            << StringPrintf("Connect with APE: handshaking value %d", hsval);

      // send main thread id
      static_assert(sizeof(pid_t) == 4, "pid_t must have size 4");
      pid_t tid = self->GetTid();
      CHECK((written = write(ape_socket_fd, &tid, 4)) == 4);

      // send prefix
      string_length = strlen(prefix);
      CHECK((written = write(ape_socket_fd, &string_length, 4)) == 4);
      CHECK((written = write(ape_socket_fd, prefix, string_length)) == string_length);

      // receive marked functions
      CHECK((written = read_with_timeout(ape_socket_fd, &num_funcs, 4) == 4))
            << StringPrintf("MiniTrace: ConnectAPE - read num_funcs %d %s", written, strerror(errno));
      ScopedObjectAccess soa(env);
      int32_t target_mask = kDoMethodEntered | kDoMethodExited | kDoMethodUnwind;
      mtd_targets = new std::map<mirror::ArtMethod*, std::pair<int, int>>();

      int before_refcnt0 = env->locals.Capacity();
      for (int func_id = 0; func_id < num_funcs; func_id++) {
        LOG(INFO) << "MiniTrace: func_id " << func_id;
        // read class name
        CHECK((written = read_with_timeout(ape_socket_fd, &string_length, 4)) == 4)
              << StringPrintf("MiniTrace: ConnectAPE - read string_length %d %s", written, strerror(errno));
        CHECK(0 < string_length && string_length <= 127)
              << StringPrintf("MiniTrace: ConnectAPE - string_length %d", string_length);
        CHECK((written = read_with_timeout(ape_socket_fd, clsname, string_length)) == string_length)
              << StringPrintf("MiniTrace: ConnectAPE - read clsname %d %s", written, strerror(errno));
        clsname[string_length] = 0;
        LOG(INFO) << "MiniTrace: clsname " << clsname;

        // read function name
        CHECK((written = read_with_timeout(ape_socket_fd, &string_length, 4)) == 4)
              << StringPrintf("MiniTrace: ConnectAPE - read string_length %d %s", written, strerror(errno));
        CHECK(0 < string_length && string_length <= 127)
              << StringPrintf("MiniTrace: ConnectAPE - string_length %d", string_length);
        CHECK((written = read_with_timeout(ape_socket_fd, methodname, string_length)) == string_length)
              << StringPrintf("MiniTrace: ConnectAPE - read methodname %d %s", written, strerror(errno));
        methodname[string_length] = 0;
        LOG(INFO) << "MiniTrace: methodname " << methodname;

        // read signature
        CHECK((written = read_with_timeout(ape_socket_fd, &string_length, 4)) == 4)
              << StringPrintf("MiniTrace: ConnectAPE - read string_length %d %s", written, strerror(errno));
        CHECK(0 < string_length && string_length <= 511)
              << StringPrintf("MiniTrace: ConnectAPE - string_length %d", string_length);
        CHECK((written = read_with_timeout(ape_socket_fd, signature, string_length)) == string_length)
              << StringPrintf("MiniTrace: ConnectAPE - read signature %d %s", written, strerror(errno));
        signature[string_length] = 0;
        LOG(INFO) << "MiniTrace: signature " << signature;

        // read flag
        // 1: enter, 2: exit, 4:unwind
        CHECK((written = read_with_timeout(ape_socket_fd, &flag, 4)) == 4)
              << StringPrintf("MiniTrace: ConnectAPE - read flag %d %s", written, strerror(errno));
        CHECK(!(flag & ~(target_mask))); listener_flag |= flag;
        LOG(INFO) << "MiniTrace: flag " << flag;

        jclass target_cls = env->FindClass(clsname);
        if (target_cls == NULL) {
          // lazy
          jthrowable exception = env->ExceptionOccurred();
          CHECK(exception != 0);
          env->DeleteLocalRef(exception);
          env->ExceptionClear();
          if (lazy_targets == NULL) {
            lazy_targets = new std::vector<lazy_target>();
          }
          lazy_targets->emplace_back(func_id, clsname, methodname, signature, flag);
          LOG(INFO) << StringPrintf("MiniTrace: TargetMethod %s:%s[%s] lazy",
              clsname, methodname, signature);
        } else {
          mirror::Class* clsp = soa.Decode<mirror::Class*>(target_cls);
          mirror::ArtMethod* method = nullptr;
          method = clsp->FindVirtualMethod(methodname, signature);
          if (method == nullptr) {
            // No virtual method matching the signature.  Search declared
            // private methods and constructors.
            method = clsp->FindDeclaredDirectMethod(methodname, signature);
            if (method == nullptr) {
              // static
              method = clsp->FindDirectMethod(methodname, signature);
            }
          }
          env->DeleteLocalRef(target_cls);
          CHECK(method != 0) << StringPrintf("MiniTrace: TargetMethod %s:%s[%s] not found",
              clsname, methodname, signature);
          method->SetMiniTraceTarget();
          mtd_targets->emplace(method, std::make_pair(func_id, flag));
          LOG(INFO) << StringPrintf("MiniTrace: TargetMethod %s:%s[%s] registered",
              clsname, methodname, signature);
        }
      }

      // remove ape_socket_fd
      if (hsval == kApeHandShakeNoGuide) {
        ape_socket_fd = -1;
      }

      int after_refcnt0 = env->locals.Capacity();
      CHECK(before_refcnt0 == after_refcnt0) << StringPrintf(
          "MiniTrace: refcnt0 %d -> %d", before_refcnt0, after_refcnt0);
      delete signature;
      delete methodname;
      delete clsname;
    }

    // RedirectnativePollOnce
    if (log_flag & kLogMessage) {
      ScopedObjectAccess soa(env);
      ScopedLocalRef<jclass> queueClass(env, env->FindClass("android/os/MessageQueue"));
      mirror::Class* mirror_queueClass = soa.Decode<mirror::Class*>(queueClass.get());
      mirror::ArtMethod *method_nativePollOnce = mirror_queueClass->FindDirectMethod("nativePollOnce", "(JI)V");
      CHECK(method_msgq_nativePollOnce_ == method_nativePollOnce);
      CHECK(method_nativePollOnce);
      nativePollOnce_originalEntry = method_nativePollOnce->GetEntryPointFromJni();
      method_nativePollOnce->SetEntryPointFromJni(reinterpret_cast<void *>(&new_android_os_MessageQueue_nativePollOnce));
      MessageDetail::lock = new Mutex("MiniTrace MessageDetail lock");
    }
    if (log_flag & (kLogMessage | kConnectAPE))
      listener_flag |= (kDoMethodEntered | kDoMethodExited);
    listener_flag |= kDoExceptionCaught;
    listener_flag &= kInstListener;
    timeval now;
    gettimeofday(&now, NULL);
    the_trace = the_trace_ = new MiniTrace(socket_fd, prefix, log_flag, listener_flag,
      3 * 1024 * 1024, ape_socket_fd, now.tv_sec * 1000LL + now.tv_usec / 1000,
      mtd_targets, lazy_targets);
  }

  Runtime* runtime = Runtime::Current();
  runtime->GetThreadList()->SuspendAll();
  CHECK_PTHREAD_CALL(pthread_create, (&the_trace->consumer_thread_, NULL, &ConsumerTask,
                                      the_trace),
                                      "Consumer thread");
  if (log_flag & kLogOneSecPing) {
    CHECK_PTHREAD_CALL(pthread_create, (&the_trace->pinging_thread_, NULL, &PingingTask,
                                        the_trace),
                                        "Pinging thread");
  }
  runtime->GetInstrumentation()->AddListener(the_trace, listener_flag);
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
    if (the_trace_ == NULL) {
      return;
    } else {
      the_trace = the_trace_;
      the_trace_ = NULL;
    }
  }
  if (the_trace != NULL) {
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
    runtime->GetInstrumentation()->RemoveListener(the_trace, the_trace->listener_flag_);

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
  if (the_trace == NULL) {
    Start();
  } else {
    LOG(INFO) << "MiniTrace: Checkout called";
    the_trace->data_bin_index_++;
  }
}

void *MiniTrace::ConsumerTask(void *arg) {
  MiniTrace *the_trace = reinterpret_cast<MiniTrace *>(arg);
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
    Append8LE(header + 12, the_trace->start_timestamp_);
  }

  // Create empty file to log data
  int last_bin_index = the_trace->data_bin_index_;
  std::string trace_data_filename(StringPrintf("%sdata_%d.bin",
      the_trace->prefix_, last_bin_index));
  std::string trace_method_info_filename(StringPrintf("%sinfo_m.log", the_trace->prefix_));
  std::string trace_field_info_filename(StringPrintf("%sinfo_f.log", the_trace->prefix_));
  std::string trace_thread_info_filename(StringPrintf("%sinfo_t.log", the_trace->prefix_));
  std::string trace_execution_filename(StringPrintf("%sexec.txt", the_trace->prefix_));

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

  File *trace_execution_file_ = OS::CreateEmptyFile(trace_execution_filename.c_str());
  CHECK(trace_execution_file_ != NULL);

  char *databuf = new char[the_trace->buffer_size_];

  // Cache for execution data
  std::map<mirror::ArtMethod*, char*> *execution_data = new std::map<mirror::ArtMethod*, char*>();
  std::vector<mirror::ArtMethod*> *changed_methods = new std::vector<mirror::ArtMethod*>();

  size_t len, woff;
  std::string buffer;
  while (the_trace->consumer_runs_) {
    // Dump Buffer
    len = ringbuf_consume(the_trace->ringbuf_, &woff);
    if (len > 0) {
      // If data_bin_index_ is modified, flush previous data and create a new file
      if (last_bin_index != the_trace->data_bin_index_) {
        // release and send its filename to socket
        CHECK(!trace_data_file_->Flush());
        CHECK(!trace_data_file_->Close());
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

    changed_methods->clear();
    {
      // fetch only the difference
      MutexLock mu(self, *the_trace->traced_execution_lock_);
      for (auto &new_item: the_trace->execution_data_) {
        mirror::ArtMethod *method = new_item.first;
        char *new_data = new_item.second;
        std::map<mirror::ArtMethod*, char*>::iterator it = execution_data->find(method);
        if (it == execution_data->end()) {
          char *data = new char[strlen(new_data)];
          strcpy(data, new_data);
          execution_data->emplace(method, data);
          changed_methods->push_back(method);
        } else {
          if (strcmp(it->second, new_data) != 0) {
            strcpy(it->second, new_data); 
            changed_methods->push_back(method);
          }
        }
      }
    }

    if (!changed_methods->empty()) {
      std::string string;
      for (auto &method: *changed_methods) {
        string.append(StringPrintf("%p\t%s\n", method, (*execution_data)[method]));
      }
      if (!trace_execution_file_->WriteFully(string.c_str(), string.length())) {
        std::string detail(StringPrintf("MiniTrace: Trace execution data write failed: %s", strerror(errno)));
        PLOG(ERROR) << detail;
        {
          Locks::mutator_lock_->ExclusiveLock(self);
          ThrowRuntimeException("%s", detail.c_str());
          Locks::mutator_lock_->ExclusiveUnlock(self);
        }
      }
    }

    the_trace->consumer_cycle_cnt_++;
    usleep(100 * 1000); // 100 ms
  }

  delete databuf;
  delete header;
  CHECK(!trace_data_file_->Flush());
  CHECK(!trace_data_file_->Close());
  CHECK(!trace_method_info_file_->Flush());
  CHECK(!trace_method_info_file_->Close());
  CHECK(!trace_field_info_file_->Flush());
  CHECK(!trace_field_info_file_->Close());
  CHECK(!trace_thread_info_file_->Flush());
  CHECK(!trace_thread_info_file_->Close());
  CHECK(!trace_execution_file_->Flush());
  CHECK(!trace_execution_file_->Close());

  write(the_trace->socket_fd_, trace_method_info_filename.c_str(),
      trace_method_info_filename.length() + 1);
  write(the_trace->socket_fd_, trace_field_info_filename.c_str(),
      trace_field_info_filename.length() + 1);
  write(the_trace->socket_fd_, trace_thread_info_filename.c_str(),
      trace_thread_info_filename.length() + 1);
  write(the_trace->socket_fd_, trace_data_filename.c_str(),
      trace_data_filename.length() + 1);
  write(the_trace->socket_fd_, trace_execution_filename.c_str(),
      trace_execution_filename.length() + 1);
  runtime->DetachCurrentThread();
  return NULL;
}

void *MiniTrace::PingingTask(void *arg) {
  MiniTrace *the_trace = reinterpret_cast<MiniTrace *>(arg);
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
    for (size_t i = 0; i < MAX_THREAD_COUNT; i++) {
      if (the_trace->wids_registered_[i] == false) {
        ringbuf_worker = ringbuf_register(the_trace->ringbuf_, i);
        the_trace->wids_registered_[i] = true;
        break;
      }
    }
  }
  CHECK(ringbuf_worker != NULL);

  char buf[10];
  Append2LE(buf, 1);  // tid = 1

  timeval now;
  uint64_t timestamp;
  while (true) {
    gettimeofday(&now, NULL);
    timestamp = now.tv_sec * 1000LL + now.tv_usec / 1000;
    Append8LE(buf + 2, timestamp);
    the_trace->WriteRingBuffer(ringbuf_worker, buf, 10);

    usleep(1 * 1000 * 1000);  // 1 second
    LOG(INFO) << "MiniTrace: 1 sec ping!";
  }
  runtime->DetachCurrentThread();

  return NULL;
}

typedef void (fntype)(JNIEnv*, jclass, jlong, jint);
void MiniTrace::new_android_os_MessageQueue_nativePollOnce(JNIEnv* env, jclass clazz,
        jlong ptr, jint timeoutMillis) {
  static MiniTrace *the_trace = NULL;
  static int64_t main_ptr = 0;
  // static timeval now;
  // static char buf[10] = {0,};
  if (main_ptr == 0) {
    Thread *self = Thread::Current();
    {
      MutexLock mu(self, *Locks::trace_lock_);
      the_trace = the_trace_;
    }
    main_ptr = ptr;
  }
  if (main_ptr == ptr) {  // if main MessageQueue,
    the_trace->ForwardMessageStatus(kMessageTransitionNativePollOnceEntered);
  }
  fntype* const fn = reinterpret_cast<fntype*>(MiniTrace::nativePollOnce_originalEntry);
  fn(env, clazz, ptr, timeoutMillis);
  if (main_ptr == ptr) {
    // the_trace->msg_enqueued_cnt_ = 0;
    the_trace->ForwardMessageStatus(kMessageTransitionNativePollOnceExited);
  }
}

MiniTrace::MiniTrace(int socket_fd, const char *prefix, uint32_t log_flag,
        uint32_t listener_flag, uint32_t buffer_size, int ape_socket_fd, uint64_t start_timestamp,
        std::map<mirror::ArtMethod*, std::pair<int, int>> *mtd_targets,
        std::vector<lazy_target> *lazy_targets)
    : socket_fd_(socket_fd), data_bin_index_(0),
      buf_(new uint8_t[buffer_size]()),
      wids_registered_lock_(new Mutex("Ringbuf worker lock")),
      consumer_runs_(true), consumer_tid_(0),
      log_flag_(log_flag), listener_flag_(listener_flag),
      do_coverage_((log_flag & kDoCoverage) != 0),
      buffer_size_(buffer_size), start_timestamp_(start_timestamp),
      consumer_cycle_cnt_(0),
      traced_method_lock_(new Mutex("MiniTrace method lock")),
      traced_field_lock_(new Mutex("MiniTrace field lock")),
      traced_thread_lock_(new Mutex("MiniTrace thread lock")),
      traced_execution_lock_(new Mutex("MiniTrace execution lock")),
      main_thread_(Thread::Current()),
      message_status_(kMessageInitial),
      message_status_lock_(new Mutex("MiniTrace message state lock")),
      main_msgq_(NULL),
      ape_socket_fd_(ape_socket_fd),
      ape_lock_(new Mutex("MiniTrace ape lock")), m_idler_(NULL),
      pinging_thread_(0), mtd_targets_(mtd_targets), lazy_targets_(lazy_targets) {

  // Set prefix
  strcpy(prefix_, prefix);

  // Initialize MPSC ring buffer
  size_t ringbuf_obj_size;
  ringbuf_get_sizes(MAX_THREAD_COUNT, &ringbuf_obj_size, NULL);

  ringbuf_ = reinterpret_cast<ringbuf_t *>(malloc(ringbuf_obj_size));
  ringbuf_setup(ringbuf_, MAX_THREAD_COUNT, buffer_size);

  for (size_t i = 0; i < MAX_THREAD_COUNT; i++) {
    wids_registered_[i] = false;
  }

  main_thread_ = Thread::Current();
  if (log_flag & (kLogMessage | kConnectAPE)) {
    CHECK(method_msgq_next_);
    CHECK(method_msgq_enqueueMessage_);
    CHECK(method_msgq_nativePollOnce_);
    CHECK(method_Message_recycleUnchecked_);
    CHECK(method_Message_toString_);
    CHECK(method_Binder_execTransact_);
    CHECK(field_Binder_mDescriptor_);
    CHECK(method_BinderProxy_transact_);
    CHECK(method_BinderProxy_getInterfaceDescriptor_);
    CHECK(method_InputEventReceiver_dispatchInputEvent_);
    CHECK(method_InputEventReceiver_finishInputEvent_);
  }

  for (auto &mtd_target: *mtd_targets) {
    LogNewMethod(mtd_target.first);
  }
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
  if (UNLIKELY(method_msgq_enqueueMessage_ == method && main_msgq_ == NULL)) {
    main_msgq_ = this_object;
  }

  if (log_flag_ & kLogMessage) {
    if (UNLIKELY(this_object == main_msgq_)) {
      if (UNLIKELY(method == method_msgq_enqueueMessage_)) {
        mirror::Object *message = thread->GetManagedStack()->GetTopShadowFrame()->GetVRegReference(9);
        MessageDetail::cb_enqueueMessage(message);
        ForwardMessageStatus(kMessageTransitionEnqueued);
      }
    }

    if (UNLIKELY(method->GetMiniTraceMarked() == 2 && thread == main_thread_)) {
      /**
       * someHandler.DispatchMessage(Message msg)
       * DispatchMessage(Message msg) uses v2 as msg,
       * Analyzed bytecode with LogMethodInByteCode
       */
      mirror::Object *message = thread->GetManagedStack()->GetTopShadowFrame()->GetVRegReference(2);
      MessageDetail *detail = MessageDetail::cb_dispatchMessage_enter(message);
      LogMessage(thread, detail);
    }

    if (UNLIKELY(method == method_Message_recycleUnchecked_)) {
      MessageDetail::cb_Message_recycleUnchecked(this_object);
    }

    // if (UNLIKELY(method == method_Binder_execTransact_)) {
    //   JNIEnvExt *env = thread->GetJniEnv();
    //   ScopedObjectAccessUnchecked soa(env);
    //   jstring jstr_descriptor = soa.AddLocalReference<jstring>(field_Binder_mDescriptor_->GetObject(this_object));
    //   const char *descriptor = env->GetStringUTFChars(jstr_descriptor, 0);
    //   std::string result = ArgumentsOnCurrentFrame(method);
    //   LOG(INFO) << result << " desc:" << std::string(descriptor);
    //   env->ReleaseStringUTFChars(jstr_descriptor, descriptor);
    // }
  }

  // if (UNLIKELY(method == method_BinderProxy_transact_)) {
  //   JNIEnvExt *env = thread->GetJniEnv();
  //   ScopedObjectAccessUnchecked soa(env);
  //   ScopedLocalRef<jobject> binderProxy(env, env->NewLocalRef(this_object));
  //   ScopedLocalRef<jobject> interfaceDescriptor_(env,
  //       env->CallObjectMethod(binderProxy.get(), soa.EncodeMethod(method_BinderProxy_getInterfaceDescriptor_)));
  //   const char* descriptor = env->GetStringUTFChars((jstring) interfaceDescriptor_.get(), 0);
  //   std::string result = ArgumentsOnCurrentFrame(method);
  //   LOG(INFO) << result << " desc:" << std::string(descriptor);
  //   env->ReleaseStringUTFChars((jstring) interfaceDescriptor_.get(), descriptor);
  // }
  // if (UNLIKELY(method == method_InputEventReceiver_dispatchInputEvent_)) {
  //   LOG(INFO) << ArgumentsOnCurrentFrame(method);
  // }
  // if (UNLIKELY(method == method_InputEventReceiver_finishInputEvent_)) {
  //   LOG(INFO) << ArgumentsOnCurrentFrame(method);
  // }

  // send APE when specific methods are met
  // if (method == method_InputEventReceiver_dispatchInputEvent_ && thread == main_thread_ && ape_socket_fd_ != -1) {
  //   MutexLock mu(thread, *Locks::trace_lock_);
  //   if (lazy_targets_ != NULL) {
  //     LOG(ERROR) << "MiniTrace: targets are not found until next() is entered";
  //     for (auto& target : *lazy_targets_) {
  //       LOG(ERROR) << StringPrintf("MiniTrace:  - %s:%s[%s]",
  //                                     target.clsname.c_str(),
  //                                     target.mtdname.c_str(),
  //                                     target.signature.c_str());
  //     }
  //     CHECK(lazy_targets_ == NULL);
  //   }
  // }

  if (method->IsMiniTraceTarget()) {
    auto it = mtd_targets_->find(method);
    CHECK(it != mtd_targets_->end());
    if (it->second.second & kDoMethodEntered) {
      pid_t tid = thread->GetTid();
      int *func_id = &it->second.first;
      if (ape_socket_fd_ != -1) {
        uint64_t timestamp;
        {
          timeval now;
          gettimeofday(&now, NULL);
          timestamp = now.tv_sec * 1000LL + now.tv_usec / 1000;
        }
        MutexLock mu(thread, *ape_lock_);
        CHECK(write(ape_socket_fd_, &kApeTargetEntered, 4) == 4);
        CHECK(write(ape_socket_fd_, &tid, 4) == 4);
        CHECK(write(ape_socket_fd_, func_id, 4) == 4);
        CHECK(write(ape_socket_fd_, &timestamp, 8) == 8);
      }

      // write into buffer
      char buf[10];
      ringbuf_worker_t *ringbuf_worker = thread->GetRingBufWorker();
      if (ringbuf_worker != NULL) {
        /* Log target met on thread */
        Append2LE(buf, 3);
        Append4LE(buf + 2, tid);
        Append4LE(buf + 6, *func_id);
        WriteRingBuffer(ringbuf_worker, buf, 10);
      }
    }
  }
}

void MiniTrace::MethodExited(Thread* thread, mirror::Object* this_object,
                         mirror::ArtMethod* method, uint32_t dex_pc,
                         const JValue& return_value) {
  if (log_flag_ & kDoMethodExited)
    LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodExited);

  if (log_flag_ & kLogMessage) {
    if (UNLIKELY(method->GetMiniTraceMarked() == 2 && thread == main_thread_)) {
      // someHandler.DispatchMessage(Message msg)
      MessageDetail::cb_dispatchMessage_exit();
    }

    /* Check every queueIdle */
    if (UNLIKELY(thread == main_thread_
                 && method->GetMiniTraceMarked() == 1
                 && this_object == m_idler_)) {
      ForwardMessageStatus(kMessageTransitionQueueIdleExited);
    }
  }

  // send APE when specific methods are met
  if (method->IsMiniTraceTarget()) {
    auto it = mtd_targets_->find(method);
    CHECK(it != mtd_targets_->end());
    if (it->second.second & kDoMethodExited) {
      pid_t tid = thread->GetTid();
      int *func_id = &it->second.first;
      if (ape_socket_fd_ != -1) {
        uint64_t timestamp;
        {
          timeval now;
          gettimeofday(&now, NULL);
          timestamp = now.tv_sec * 1000LL + now.tv_usec / 1000;
        }
        MutexLock mu(thread, *ape_lock_);
        CHECK(write(ape_socket_fd_, &kApeTargetExited, 4) == 4);
        CHECK(write(ape_socket_fd_, &tid, 4) == 4);
        CHECK(write(ape_socket_fd_, func_id, 4) == 4);
        CHECK(write(ape_socket_fd_, &timestamp, 8) == 8);
      }

      // write into buffer
      char buf[10];
      ringbuf_worker_t *ringbuf_worker = thread->GetRingBufWorker();
      if (ringbuf_worker != NULL) {
        /* Log target met on thread */
        Append2LE(buf, 4);
        Append4LE(buf + 2, tid);
        Append4LE(buf + 6, *func_id);
        WriteRingBuffer(ringbuf_worker, buf, 10);
      }
    }
  }
}

void MiniTrace::MethodUnwind(Thread* thread, mirror::Object* this_object,
                         mirror::ArtMethod* method, uint32_t dex_pc) {
  if (log_flag_ & kDoMethodUnwind)
    LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodUnwind);

  // send APE when specific methods are met
  if (method->IsMiniTraceTarget()) {
    auto it = mtd_targets_->find(method);
    CHECK(it != mtd_targets_->end());
    if (it->second.second & kDoMethodUnwind) {
      pid_t tid = thread->GetTid();
      int *func_id = &it->second.first;
      if (ape_socket_fd_ != -1) {
        uint64_t timestamp;
        {
          timeval now;
          gettimeofday(&now, NULL);
          timestamp = now.tv_sec * 1000LL + now.tv_usec / 1000;
        }
        MutexLock mu(thread, *ape_lock_);
        CHECK(write(ape_socket_fd_, &kApeTargetUnwind, 4) == 4);
        CHECK(write(ape_socket_fd_, &tid, 4) == 4);
        CHECK(write(ape_socket_fd_, func_id, 4) == 4);
        CHECK(write(ape_socket_fd_, &timestamp, 8) == 8);
      }

      // write into buffer
      char buf[10];
      ringbuf_worker_t *ringbuf_worker = thread->GetRingBufWorker();
      if (ringbuf_worker != NULL) {
        /* Log target met on thread */
        Append2LE(buf, 5);
        Append4LE(buf + 2, tid);
        Append4LE(buf + 6, *func_id);
        WriteRingBuffer(ringbuf_worker, buf, 10);
      }
    }
  }
}

void MiniTrace::ExceptionCaught(Thread* thread, const ThrowLocation& throw_location,
                            mirror::ArtMethod* catch_method, uint32_t catch_dex_pc,
                            mirror::Throwable* exception_object) {
  if (log_flag_ & kDoExceptionCaught) {
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
  // Wait for a cycle on consumer
  // @TODO use condition variable..?
  int cycleid = consumer_cycle_cnt_;
  while (consumer_cycle_cnt_ - cycleid <= 2) {}
}

void MiniTrace::LogMessage(Thread* thread, MessageDetail *msg_detail) {
  if (msg_detail == NULL)
    return;
  ringbuf_worker_t *ringbuf_worker = GetRingBufWorker();
  if (ringbuf_worker == NULL)
    return;

  // Record detail information for message
  std::string dumped = msg_detail->Dump();
  int32_t record_size = dumped.length() + 2 + 4 + 1;
  char *buf = new char[record_size]();
  Append2LE(buf, thread->GetTid());
  Append4LE(buf + 2, (record_size << 3) | kMiniTraceMessageEvent);
  strcpy(buf + 6, dumped.c_str());
  WriteRingBuffer(ringbuf_worker, buf, record_size);
  delete buf;
}

void MiniTrace::ForwardMessageStatus(MessageStatusTransition transition) {
#ifdef HAVE_ANDROID_OS
  class MiniMessageHandler : public android::MessageHandler {
  public:
      virtual void handleMessage(const android::Message& message) {}
  };
  static mirror::Object *main_MessageQueue;
  static jmethodID method_addIdleHandler;
  static android::sp<MiniMessageHandler> nativeLooperMessageHandler;
  static char buf[10];

  Thread *self = Thread::Current();
  JNIEnvExt *env = self->GetJniEnv();
  MutexLock mu(self, *message_status_lock_);
  {
    if (m_idler_ == NULL) {
      /* First time initialize objects */
      MiniTraceThreadFlag orig_flag = self->GetMiniTraceFlag();
      self->SetMiniTraceFlag(kMiniTraceExclude);
      ScopedLocalRef<jclass> looperClass(env, env->FindClass("android/os/Looper"));
      ScopedLocalRef<jclass> msgqClass(env, env->FindClass("android/os/MessageQueue"));
      ScopedLocalRef<jclass> idlerClass(env, env->FindClass("android/app/Instrumentation$Idler"));
      jmethodID getMainLooper = env->GetStaticMethodID(looperClass.get(),
          "getMainLooper", "()Landroid/os/Looper;");
      jmethodID getQueue = env->GetMethodID(looperClass.get(),
          "getQueue", "()Landroid/os/MessageQueue;");
      jmethodID idlerInit = env->GetMethodID(idlerClass.get(),
          "<init>", "(Ljava/lang/Runnable;)V");
      method_addIdleHandler = env->GetMethodID(msgqClass.get(),
          "addIdleHandler", "(Landroid/os/MessageQueue$IdleHandler;)V");
      ScopedLocalRef<jobject> mainLooper(env, env->CallStaticObjectMethod(looperClass.get(), getMainLooper));
      jobject j_idler = env->NewGlobalRef(env->NewObject(idlerClass.get(), idlerInit, 0));
      jobject j_main_msgq = env->NewGlobalRef(env->CallObjectMethod(mainLooper.get(), getQueue));
      m_idler_ = self->DecodeJObject(j_idler);
      main_MessageQueue = self->DecodeJObject(j_main_msgq);
      self->SetMiniTraceFlag(orig_flag);

      Append2LE(buf, 0);  // tid = 0
    }
  }
  switch (message_status_) {
    case kMessageInitial:
      if (transition == kMessageTransitionEnqueued) {
        goto run_add_idle;
      }
      break;
    case kMessageEnqueued:
      if (transition == kMessageTransitionQueueIdleExited) {
        message_status_ = kMessageIdled;
      }
      break;
    case kMessageIdled:
      if (transition == kMessageTransitionNativePollOnceEntered) {
        if (MessageDetail::HasNoMoreMessage()) {
          // Looper::sendMessage
          message_status_ = kMessageLooperMessageSent;
          if (nativeLooperMessageHandler == NULL)
            nativeLooperMessageHandler = new MiniMessageHandler();
          android::Message msg(0);
          android::Looper::getForThread()->sendMessage(nativeLooperMessageHandler, msg);
        } else {
          goto run_add_idle;
        }
      }
      break;
    case kMessageLooperMessageSent:
      if (transition == kMessageTransitionNativePollOnceExited) {
        if (MessageDetail::HasNoMoreMessageThenFlushOut()) {
          message_status_ = kMessageInitial;
          uint64_t timestamp;
          {
            timeval now;
            gettimeofday(&now, NULL);
            timestamp = now.tv_sec * 1000LL + now.tv_usec / 1000;
          }
          Append8LE(buf+2, timestamp);
          ringbuf_worker_t *ringbuf_worker = GetRingBufWorker();
          CHECK(ringbuf_worker);
          WriteRingBuffer(ringbuf_worker, buf, 10);
          LOG(INFO) << "MessageStatus: Idle Timestamp " << timestamp;

          // Send current timestamp to APE
          if (ape_socket_fd_ != -1) {
            MutexLock mu(self, *ape_lock_);
            CHECK(write(ape_socket_fd_, &kApeIdle, 4) == 4);
            CHECK(write(ape_socket_fd_, &timestamp, 8) == 8);
          }
        } else {
          goto run_add_idle;
        }
      }
      break;
  }
  if (false) {
   run_add_idle:
    message_status_ = kMessageEnqueued;

    MiniTraceThreadFlag orig_flag = self->GetMiniTraceFlag();
    self->SetMiniTraceFlag(kMiniTraceExclude);

    ScopedObjectAccessUnchecked soa(env);
    {
      ScopedLocalRef<jobject> j_idler(env, soa.AddLocalReference<jobject>(m_idler_));
      ScopedLocalRef<jobject> j_main_msgq(env, soa.AddLocalReference<jobject>(main_MessageQueue));
      env->CallVoidMethod(j_main_msgq.get(), method_addIdleHandler, j_idler.get());
    }

    self->SetMiniTraceFlag(orig_flag);
  }
#endif
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
  for (auto& it : methods_not_stored_) {
    (&it)->Dump(string);
  }
  methods_not_stored_.clear();
}

void MiniTrace::DumpField(std::string &string) {
  Thread *self = Thread::Current();
  traced_field_lock_->AssertHeld(self);
  string.assign("");
  for (auto it : fields_not_stored_) {
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
  const ArtFieldDetail *fieldDetail = &(*(it.first));
  if (it.second) {
    fields_not_stored_.push_back(fieldDetail);
    return 0;
  } else {
    return fieldDetail->FindIdx(field);
  }
}

char* MiniTrace::GetExecutionData(Thread* self, mirror::ArtMethod* method) {
  if (method->IsRuntimeMethod() || method->IsProxyMethod()) {  // No profile for execution data
    return NULL;
  }

  {
    DCHECK_EQ(self, Thread::Current());
    MiniTrace* the_trace = NULL;
    {
      MutexLock mu(Thread::Current(), *Locks::trace_lock_);
      the_trace = the_trace_;
      if (the_trace == NULL) {
        return NULL;
      }
    }

    if (!the_trace->do_coverage_) {
      return NULL;
    }

    uint32_t minitrace_type = method->GetMiniTraceType();
    if (((minitrace_type == 0 && !(the_trace->log_flag_ & kLogMethodType0))
         || (minitrace_type == 1 && !(the_trace->log_flag_ & kLogMethodType1))
         || (minitrace_type == 2 && !(the_trace->log_flag_ & kLogMethodType2))
         || (minitrace_type == 3 && !(the_trace->log_flag_ & kLogMethodType3)))
        && !method->IsMiniTraceTarget())
      return NULL;

    std::map<mirror::ArtMethod*, char*>::iterator it = the_trace->execution_data_.find(method);
    if (it == the_trace->execution_data_.end()) {
      const DexFile::CodeItem *code_item = method->GetCodeItem();
      uint16_t insns_size = code_item->insns_size_in_code_units_;
      if (insns_size == 0) {
        return NULL;
      }

      char *execution_data = new char[insns_size+1];
      memset(execution_data, '0', insns_size * sizeof(char));
      execution_data[insns_size] = '\0';
      {
        MutexLock mu(self, *the_trace->traced_execution_lock_);
        the_trace->execution_data_[method] = execution_data;
      }
      return execution_data;
    }
    return it->second;
  }
}

void MiniTrace::PostClassPrepare(mirror::Class* klass, const char *descriptor) {
  static mirror::Class *idleHandlerClass = NULL;
  static mirror::Class *handlerClass = NULL;
  static mirror::Class *inputEventReceiverClass = NULL;
  if (idleHandlerClass == NULL && strcmp(descriptor, "Landroid/os/MessageQueue$IdleHandler;") == 0) {
    idleHandlerClass = klass;
  }
  if (inputEventReceiverClass == NULL && strcmp(descriptor, "Landroid/view/InputEventReceiver;") == 0) {
    inputEventReceiverClass = klass;
    method_InputEventReceiver_dispatchInputEvent_ = klass->FindDeclaredDirectMethod("dispatchInputEvent", "(ILandroid/view/InputEvent;)V");
    CHECK(method_InputEventReceiver_dispatchInputEvent_);

    method_InputEventReceiver_finishInputEvent_ = klass->FindDeclaredVirtualMethod("finishInputEvent", "(Landroid/view/InputEvent;Z)V");
    CHECK(method_InputEventReceiver_finishInputEvent_);
  }
  if (klass->IsArrayClass() || klass->IsInterface() || klass->IsPrimitive()) {
    return;
  }

  // static const DexFile *apkDexFile = NULL;
  const DexFile& dxFile = klass->GetDexFile();
  // if (apkDexFile == NULL && (dxFile.GetLocation().rfind("/data/app/", 0) == 0))
  //   apkDexFile = &dxFile;
  // CHECK((apkDexFile == NULL) || (dxFile.GetLocation().rfind("/data/app/", 0) != 0) || apkDexFile == &dxFile)
  //       << StringPrintf("apkDexFile %s dxFile %s", apkDexFile->GetLocation().c_str(), dxFile.GetLocation().c_str());

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

  // if (&dxFile == apkDexFile) {
  if (dxFile.GetLocation().rfind("/data/app/", 0) == 0) {
    // register lazy target
    {
      MutexLock mu(Thread::Current(), *Locks::trace_lock_);
      if (the_trace_ != NULL && the_trace_->lazy_targets_ != NULL) {
        auto targets = the_trace_->lazy_targets_;
        for (auto it = targets->begin(); it != targets->end();) {
          lazy_target &target = (*it);
          if (target.clsname.compare(descriptor) == 0) {
            mirror::ArtMethod* method = nullptr;
            method = klass->FindVirtualMethod(
                  target.mtdname.c_str(), target.signature.c_str());
            if (method == nullptr) {
              // No virtual method matching the signature.  Search declared
              // private methods and constructors.
              method = klass->FindDeclaredDirectMethod(
                    target.mtdname.c_str(), target.signature.c_str());
              if (method == nullptr) {
                // static
                method = klass->FindDirectMethod(
                      target.mtdname.c_str(), target.signature.c_str());
              }
            }

            CHECK(method != nullptr)
                << StringPrintf("MiniTrace: TargetMethod %s:%s[%s] not found",
                                target.clsname.c_str(),
                                target.mtdname.c_str(),
                                target.signature.c_str());
            method->SetMiniTraceTarget();
            the_trace_->LogNewMethod(method);
            the_trace_->mtd_targets_->emplace(method,
                                             std::make_pair(target.id, target.flag));
            LOG(INFO) << StringPrintf("MiniTrace: TargetMethod %s:%s[%s] registered lazily",
                                      target.clsname.c_str(),
                                      target.mtdname.c_str(),
                                      target.signature.c_str());
            targets->erase(it);
          } else {
            it++;
          }
        }
        if (the_trace_->lazy_targets_->empty()) {
          delete the_trace_->lazy_targets_;
          the_trace_->lazy_targets_ = NULL;
        }
      }
    }
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
    if (handlerClass == NULL && strcmp(descriptor, "Landroid/os/Handler;") == 0) {
      handlerClass = klass;
      mirror::ArtMethod *method = handlerClass->FindDeclaredVirtualMethod("dispatchMessage", "(Landroid/os/Message;)V");
      CHECK(method != NULL);
      method->SetMiniTraceMarked(2);
    }
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
      mirror::ArtMethod *method = klass->FindVirtualMethod("queueIdle", "()Z");
      CHECK(method != NULL);
      method->SetMiniTraceMarked(1);
      break;
    }
  }

  // Mark dispatchMessage method of Landroid/os/Handler
  if (handlerClass != NULL && klass->IsSubClass(handlerClass)) {
    mirror::ArtMethod *method = klass->FindVirtualMethod("dispatchMessage", "(Landroid/os/Message;)V");
    CHECK(method != NULL);
    method->SetMiniTraceMarked(2);
  }

  // Find methods to used on message loggings
  if (method_msgq_next_ == NULL && strcmp(descriptor, "Landroid/os/MessageQueue;") == 0) {
    method_msgq_next_ = klass->FindDeclaredVirtualMethod("next", "()Landroid/os/Message;");
    method_msgq_enqueueMessage_ = klass->FindDeclaredVirtualMethod("enqueueMessage", "(Landroid/os/Message;J)Z");
    method_msgq_nativePollOnce_ = klass->FindDeclaredDirectMethod("nativePollOnce", "(JI)V");
    CHECK(method_msgq_next_);
    CHECK(method_msgq_enqueueMessage_);
    CHECK(method_msgq_nativePollOnce_);
  }

  if (method_Message_recycleUnchecked_ == NULL && strcmp(descriptor, "Landroid/os/Message;") == 0) {
    method_Message_toString_ = klass->FindDeclaredVirtualMethod("toString", "()Ljava/lang/String;");
    method_Message_recycleUnchecked_ = klass->FindDeclaredVirtualMethod("recycleUnchecked", "()V");
    CHECK(method_Message_toString_);
    CHECK(method_Message_recycleUnchecked_);
  }

  if (method_Binder_execTransact_ == NULL && strcmp(descriptor, "Landroid/os/Binder;") == 0) {
    method_Binder_execTransact_ = klass->FindDeclaredDirectMethod("execTransact", "(IJJI)Z");
    field_Binder_mDescriptor_ = klass->FindDeclaredInstanceField("mDescriptor", "Ljava/lang/String;");
    CHECK(method_Binder_execTransact_);
    CHECK(field_Binder_mDescriptor_);
  }

  if (method_BinderProxy_transact_ == NULL && strcmp(descriptor, "Landroid/os/BinderProxy;") == 0) {
    method_BinderProxy_transact_ = klass->FindDeclaredVirtualMethod("transact", "(ILandroid/os/Parcel;Landroid/os/Parcel;I)Z");
    method_BinderProxy_getInterfaceDescriptor_ = klass->FindDeclaredVirtualMethod("getInterfaceDescriptor", "()Ljava/lang/String;");

    CHECK(method_BinderProxy_transact_);
    CHECK(method_BinderProxy_getInterfaceDescriptor_);
  }

  /**
   * Debug to find method with following code
   * for (size_t i = 0, e = klass->NumDirectMethods(); i < e; i++) {
   *   LOG(INFO) << "Direct" << i  << "/" << PrettyMethod(klass->GetDirectMethod(i));
   * }
   * for (size_t i = 0, e = klass->NumVirtualMethods(); i < e; i++) {
   *   LOG(INFO) << "Virtual" << i  << "/" << PrettyMethod(klass->GetVirtualMethod(i));
   * }
   */
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
        || (pinging_thread_ != 0 && pself == pinging_thread_)) {
      self->SetMiniTraceFlag(kMiniTraceExclude);
      return NULL;
    }
    std::string name;
    self->GetThreadName(name);
    for (size_t i = 0; i < THREAD_TO_EXCLUDE_CNT; i++) {
      if (name.compare(threadnames_to_exclude[i]) == 0) {
        self->SetMiniTraceFlag(kMiniTraceExclude);
        return NULL;
      }
    }

    // Find available worker slot
    ringbuf_worker_t *ringbuf_worker = NULL;
    {
      MutexLock mu(self, *wids_registered_lock_);
      for (size_t i = 0; i < MAX_THREAD_COUNT; i++) {
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
    char buf[6];
    ringbuf_worker = thread->GetRingBufWorker();

    /* Log termination of thread */
    Append2LE(buf, 2);  // tid = 2
    Append4LE(buf + 2, thread->GetTid());
    WriteRingBuffer(ringbuf_worker, buf, 6);

    /* Unregister ringbuf */
    wid = ringbuf_w2i(ringbuf_, ringbuf_worker);
    {
      MutexLock mu(thread, *wids_registered_lock_);
      wids_registered_[wid] = false;
    }
    ringbuf_unregister(ringbuf_, ringbuf_worker);
    thread->SetMiniTraceFlag(kMiniTraceFirstSeen);
  }
}

}  // namespace art
