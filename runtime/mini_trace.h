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

#ifndef ART_RUNTIME_MINI_TRACE_H_
#define ART_RUNTIME_MINI_TRACE_H_

#include <memory>
#include <ostream>
#include <set>
#include <string>
#include <vector>
#include <queue>
#include <unordered_map>
#include <pthread.h>
#include <sys/time.h>

#include "atomic.h"
#include "base/macros.h"
#include "base/stringpiece.h"
#include "globals.h"
#include "dex_file-inl.h"
#include "instrumentation.h"
#include "mirror/art_method-inl.h"
#include "mirror/class-inl.h"
#include "mirror/dex_cache.h"
#include "trace.h"
#include "os.h"
#include "safe_map.h"
#include "ringbuf.h"
#include "base/mutex.h"

// MAX_THREAD_COUNT may not be enough
#define MAX_THREAD_COUNT 256
namespace art {

namespace mirror {
  class Class;
  class ArtField;
  class ArtMethod;
}  // namespace mirror

class Thread;

class MiniTrace : public instrumentation::InstrumentationListener {
 public:
  enum MiniTraceFlag {
    /* Flags used with instrumentation::Instrumentation */
    kDoMethodEntered     = 0x00000001,
    kDoMethodExited      = 0x00000002,
    kDoMethodUnwind      = 0x00000004,
    kDoDexPcMoved        = 0x00000008,
    kDoFieldRead         = 0x00000010,
    kDoFieldWritten      = 0x00000020,
    kDoExceptionCaught   = 0x00000040,
    kInstListener        = 0x00000077, /* Currently, DexPcMoved is not used */

    /* Flags used only for MiniTrace */
    kDoCoverage          = 0x00000080,
    kLogMessage          = 0x00000100, // log all messages on main looper

    /* Flags used for communicate with ape */
    kConnectAPE          = 0x00010000, // If set, communicates with APE

    /* Ping flag */
    kLogOneSecPing       = 0x00020000, // If set, push simple log for every 1 second

    /* Flags used for filtering objects */
    kLogFieldTypeFlags   = 0x0F000000,
    kLogFieldType0       = 0x01000000, // All the other fields
    kLogFieldType1       = 0x02000000, // UNUSED
    kLogFieldType2       = 0x04000000, // UNUSED
    kLogFieldType3       = 0x08000000, // fields defined on app
    kLogMethodTypeFlags  = 0xF0000000,
    kLogMethodType0      = 0x10000000, // Basic API methods
    kLogMethodType1      = 0x20000000, // Non-basic API methods
    kLogMethodType2      = 0x40000000, // UNUSED
    kLogMethodType3      = 0x80000000, // methods defined on app
    kFlagAll             = 0xFF0301FF
  };

  static void Start()
      LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::thread_suspend_count_lock_,
                     Locks::trace_lock_);

  static void Shutdown()
      LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::trace_lock_);

  static void Checkout() LOCKS_EXCLUDED(Locks::trace_lock_);

  static bool* GetExecutionData(Thread* self, mirror::ArtMethod* method)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_)
      LOCKS_EXCLUDED(Locks::trace_lock_);

  static void PostClassPrepare(mirror::Class* klass)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  // InstrumentationListener implementation.
  void MethodEntered(Thread* thread, mirror::Object* this_object,
                     mirror::ArtMethod* method, uint32_t dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void MethodExited(Thread* thread, mirror::Object* this_object,
                    mirror::ArtMethod* method, uint32_t dex_pc,
                    const JValue& return_value)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void MethodUnwind(Thread* thread, mirror::Object* this_object,
                    mirror::ArtMethod* method, uint32_t dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void DexPcMoved(Thread* thread, mirror::Object* this_object,
                  mirror::ArtMethod* method, uint32_t new_dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void FieldRead(Thread* thread, mirror::Object* this_object,
                 mirror::ArtMethod* method, uint32_t dex_pc, mirror::ArtField* field)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void FieldWritten(Thread* thread, mirror::Object* this_object,
                    mirror::ArtMethod* method, uint32_t dex_pc, mirror::ArtField* field,
                    const JValue& field_value)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;
  void ExceptionCaught(Thread* thread, const ThrowLocation& throw_location,
                       mirror::ArtMethod* catch_method, uint32_t catch_dex_pc,
                       mirror::Throwable* exception_object)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) OVERRIDE;

  static void StoreExitingThreadInfo(Thread* thread);

  static void *ConsumerTask(void *mt_object) LOCKS_EXCLUDED(Locks::trace_lock_);
  static void *IdleCheckTask(void *mt_object);
  static void *PingingTask(void *mt_object);

  class ArtMethodDetail {
  public:
    ArtMethodDetail(mirror::ArtMethod* method) : method_(method) {
      // @TODO Is this detail enough? consider argument type & return type
      const char *descriptor = method->GetDeclaringClassDescriptor();
      if (descriptor == NULL)
        classDescriptor_.assign("NoDescriptor");
      else
        classDescriptor_.assign(descriptor);
      name_.assign(method->GetName());
      signature_.assign(method->GetSignature().ToString()); // It never fails, "<no signature>" in dexfile.cc:994
      const char *declaringClassSourceFile = method->GetDeclaringClassSourceFile();
      if (declaringClassSourceFile == NULL)
        declaringClassSourceFile_.assign("NoClassSourceFile");
      else
        declaringClassSourceFile_.assign(method->GetDeclaringClassSourceFile());
    }
    bool operator< (const ArtMethodDetail & other) const {
      return this->method_ < other.method_;
    }
    void Dump(std::string &string) {
      string.append(StringPrintf("%p\t%s\t%s\t%s\t%s\n", method_,
        classDescriptor_.c_str(),
        name_.c_str(),
        signature_.c_str(),
        declaringClassSourceFile_.c_str()
      ));
    }
  private:
    mirror::ArtMethod* method_;
    std::string classDescriptor_;
    std::string name_;
    std::string signature_;
    std::string declaringClassSourceFile_;
  };

  class ArtFieldDetail {
  public:
    ArtFieldDetail(mirror::ArtField *field) : field_(field),
        typeDesc_(field->GetTypeDescriptor()), next_(NULL) {
      Thread *self = Thread::Current();
      Locks::mutator_lock_->SharedLock(self);
      name_.assign(field->GetName());
      Locks::mutator_lock_->SharedUnlock(self);
      const DexFile* dex_file = field->GetDexFile();
      const DexFile::FieldId& field_id = dex_file->GetFieldId(field->GetDexFieldIndex());
      classDescriptor_.assign(PrettyDescriptor(dex_file->GetFieldDeclaringClassDescriptor(field_id)));
    }
    bool operator< (const ArtFieldDetail & other) const {
      return this->field_ < other.field_;
    }
    void Dump(std::string &string) const {
      uint16_t idx = 0;
      const ArtFieldDetail *cur = this;
      while (cur != NULL) {
        string.append(StringPrintf("%p\t%d\t%s\t%s\t%s\n", field_, idx,
          cur->classDescriptor_.c_str(), cur->name_.c_str(), cur->typeDesc_.c_str()));
        ++idx;
        cur = cur->next_;
      }
    }
    /**
     * Problem: pointer value is same but actually different
     * use field->GetName */
    uint16_t FindIdx(mirror::ArtField *field) const {
      Thread *self = Thread::Current();
      Locks::mutator_lock_->SharedLock(self);
      std::string new_name = field->GetName();
      Locks::mutator_lock_->SharedUnlock(self);
      const ArtFieldDetail *cur = NULL;
      const ArtFieldDetail *next = this;
      uint16_t idx = 0;
      while (next != NULL) {
        cur = next;
        if (new_name.compare(cur->name_) == 0) {
          return idx;
        }
        ++idx;
        next = cur->next_;
      }

      // New field
      cur->next_ = new ArtFieldDetail(field);
      return idx;
    }
  private:
    mirror::ArtField* field_;
    std::string classDescriptor_;
    std::string name_;
    std::string typeDesc_;
    mutable ArtFieldDetail *next_;
  };

  class ThreadDetail {
  public:
    ThreadDetail(pid_t pid, std::string name): pid_(pid), name_(name) {}
    bool operator< (const ThreadDetail *other) const {
      if (this->pid_ == other->pid_)
        return this->name_.compare(other->name_);
      else
        return this->pid_ < other->pid_;
    }
    void Dump(std::string &string) {
      string.append(StringPrintf("%d\t%s\n", pid_, name_.c_str()));
    }
  private:
    pid_t pid_;
    std::string name_;
  };

 private:
  explicit MiniTrace(int socket_fd, const char *prefix, uint32_t log_flag,
                     uint32_t buffer_size, int ape_socket_fd);

  void LogMethodTraceEvent(Thread* thread, mirror::ArtMethod* method, uint32_t dex_pc,
                           instrumentation::Instrumentation::InstrumentationEvent event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogFieldTraceEvent(Thread* thread, mirror::Object* this_object, mirror::ArtField* field,
                           uint32_t dex_pc, bool read_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogMonitorTraceEvent(Thread* thread, mirror::Object* lock_object, uint32_t dex_pc,
                           bool enter_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogMessage(Thread* thread, const JValue& msg) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void DumpMethod(std::string &buffer);
  void DumpField(std::string &buffer);
  void DumpThread(std::string &buffer);

  void LogNewMethod(mirror::ArtMethod *method);
  uint16_t LogNewField(mirror::ArtField *field);
  void LogNewThread(Thread *thread);

  void ReadBuffer(char *dest, size_t offset, size_t len);
  void WriteRingBuffer(ringbuf_worker_t *worker, const char *src, size_t len);

  // Singleton instance of the Trace or NULL when no method tracing is active.
  static MiniTrace* volatile the_trace_ GUARDED_BY(Locks::trace_lock_);

  // Socket fd connect with mtserver
  // The consumer thread should close it
  int socket_fd_;

  // File index on binary file for logs
  volatile int data_bin_index_;

  // Prefix for log info and data
  char prefix_[100];

  // Buffer to store trace data.
  uint8_t *buf_;

  // manages buf, as ring buffer
  ringbuf_t *ringbuf_;

  // // Manages all threads and ringbuf workers
  Mutex *wids_registered_lock_;
  bool wids_registered_[MAX_THREAD_COUNT];

  // Threads to avoid log
  static constexpr const int THREAD_TO_EXCLUDE_CNT = 5;
  static constexpr const char *THREAD_FinalizerDaemon = "FinalizerDaemon";
  static constexpr const char *THREAD_ReferenceQueueDaemon = "ReferenceQueueDaemon";
  static constexpr const char *THREAD_GCDaemon = "GCDaemon";
  static constexpr const char *THREAD_FinalizerWatchdogDaemon = "FinalizerWatchdogDaemon";
  static constexpr const char *THREAD_HeapTrimmerDaemon = "HeapTrimmerDaemon";

  static const char *threadnames_to_exclude[THREAD_TO_EXCLUDE_CNT];

  // Used for consumer - MiniTrace synchronization
  pthread_t consumer_thread_;
  volatile bool consumer_runs_;
  pid_t consumer_tid_;

  ringbuf_worker_t *GetRingBufWorker();
  void UnregisterThread(Thread *thread);

  // Buffer to store trace method data.
  std::list<ArtMethodDetail> methods_not_stored_;

  // Visited methods
  std::set<mirror::ArtMethod*> visited_methods_;

  // Buffer to store trace field data.
  std::list<const ArtFieldDetail *> fields_not_stored_;

  // Visited fields
  std::set<ArtFieldDetail> visited_fields_;

  // Buffer to store thread data
  // Stored threads are accessible with registered_threads_
  std::list<ThreadDetail> threads_not_stored_;

  // Events, default open every available events.
  const uint32_t log_flag_;

  // Log execution data
  bool do_coverage_;

  const uint32_t buffer_size_;

  // Time trace was created.
  const uint64_t start_time_;

  // Method Execution Data
  SafeMap<mirror::ArtMethod*, bool*> execution_data_;

  Mutex *traced_method_lock_;

  Mutex *traced_field_lock_;

  Mutex *traced_thread_lock_;

  JNIEnvExt *env_;
  mirror::ArtMethod *method_msgq_next_;
  mirror::Object *main_msgq_;
  volatile bool msg_taken_;

  int ape_socket_fd_;
  pthread_t idlecheck_thread_;

  // Push simple log for every 1 second
  pthread_t pinging_thread_;

  DISALLOW_COPY_AND_ASSIGN(MiniTrace);
};

}  // namespace art

#endif  // ART_RUNTIME_MINI_TRACE_H_
