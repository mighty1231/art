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
    kDoMethodEntered =    0x00000001,
    kDoMethodExited =     0x00000002,
    kDoMethodUnwind =     0x00000004,
    kDoDexPcMoved =       0x00000008,
    kDoFieldRead =        0x00000010,
    kDoFieldWritten =     0x00000020,
    kDoExceptionCaught =  0x00000040,
    kInstListener =       0x00000077, /* Currently, DexPcMoved is not used */
    /* Above flags are used on instrumentation::Instrumentation */

    /* Following flags are used for MiniTrace */
    kDoCoverage =         0x00000080,
    kDoFilter =           0x00000100,
    kFlagAll =            0x000001FF
  };
  static void Start()
      LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::thread_suspend_count_lock_,
                     Locks::trace_lock_);
  static void Stop()
      LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::trace_lock_);
  static void Shutdown() LOCKS_EXCLUDED(Locks::trace_lock_);

  static void Checkout() LOCKS_EXCLUDED(Locks::trace_lock_);

  static TracingMode GetMethodTracingMode() LOCKS_EXCLUDED(Locks::trace_lock_);

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

  static void *ConsumerFunction(void *mt_object) LOCKS_EXCLUDED(Locks::trace_lock_);
  static void *IdleChecker(void *mt_object);

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
    bool operator< (const ArtMethodDetail *other) const {
      return this->method_ < other->method_;
    }
    void Dump(std::string &string) {
      string.append(StringPrintf("%p\t%s\t%s\t%s\t%s\n", method_,
        classDescriptor_.c_str(),
        name_.c_str(),
        signature_.c_str(),
        declaringClassSourceFile_.c_str()));
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
        name_(field->GetName()), typeDesc_(field->GetTypeDescriptor()) {
      const DexFile* dex_file = field->GetDexFile();
      const DexFile::FieldId& field_id = dex_file->GetFieldId(field->GetDexFieldIndex());
      classDescriptor_.assign(PrettyDescriptor(dex_file->GetFieldDeclaringClassDescriptor(field_id)));
    }
    bool operator< (const ArtFieldDetail *other) const {
      return this->field_ < other->field_;
    }
    void Dump(std::string &string) {
      string.append(StringPrintf("%p\t%s\t%s\t%s\n", field_,
        classDescriptor_.c_str(), name_.c_str(), typeDesc_.c_str()));
    }
  private:
    mirror::ArtField* field_;
    std::string classDescriptor_;
    std::string name_;
    std::string typeDesc_;
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
  explicit MiniTrace(int socket_fd, const char *prefix, uint32_t log_flag, uint32_t buffer_size);

  void LogMethodTraceEvent(Thread* thread, mirror::ArtMethod* method, uint32_t dex_pc,
                           instrumentation::Instrumentation::InstrumentationEvent event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogFieldTraceEvent(Thread* thread, mirror::Object* this_object, mirror::ArtField* field,
                           uint32_t dex_pc, bool read_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogMonitorTraceEvent(Thread* thread, mirror::Object* lock_object, uint32_t dex_pc,
                           bool enter_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void DumpMethod(std::string &buffer); // SHARED_LOCKS_REQUIRED(this->traced_method_lock_)
  void DumpField(std::string &buffer); // SHARED_LOCKS_REQUIRED(this->traced_field_lock_)
  void DumpThread(std::string &buffer); // SHARED_LOCKS_REQUIRED(this->traced_thread_lock_)

  void LogNewMethod(mirror::ArtMethod *method) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  void LogNewField(mirror::ArtField *field);
  void LogNewThread(Thread *thread);

  void ReadBuffer(char *dest, size_t offset, size_t len);
  void WriteBuffer(const char *src, size_t offset, size_t len);

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
  std::list<ArtFieldDetail> fields_not_stored_;

  // Visited fields
  std::set<mirror::ArtField*> visited_fields_;

  // Buffer to store thread data
  // Stored threads are accessible with registered_threads_
  std::list<ThreadDetail> threads_not_stored_;

  // Events, default open every available events.
  const uint32_t log_flag_;

  // Log execution data
  bool do_coverage_;

  // Filter library code
  bool do_filter_;

  const uint32_t buffer_size_;

  // Time trace was created.
  const uint64_t start_time_;

  // Method Execution Data
  SafeMap<mirror::ArtMethod*, bool*> execution_data_;

  Mutex *traced_method_lock_;

  Mutex *traced_field_lock_;

  Mutex *traced_thread_lock_;

  JNIEnvExt *env_;
  const JValue *main_looper_;

  // idle checking loop
  mirror::ArtMethod *method_message_next_;
  mirror::Object *main_message_;
  pthread_t idlechecker_thread_;
  volatile bool msg_taken_;
  volatile bool instrumentation_taken_;

  DISALLOW_COPY_AND_ASSIGN(MiniTrace);
};

}  // namespace art

#endif  // ART_RUNTIME_MINI_TRACE_H_
