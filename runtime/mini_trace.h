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

#include "atomic.h"
#include "base/macros.h"
#include "base/stringpiece.h"
#include "globals.h"
#include "instrumentation.h"
#include "trace.h"
#include "os.h"
#include "safe_map.h"

namespace art {

namespace mirror {
  class Class;
  class ArtField;
  class ArtMethod;
}  // namespace mirror

class Thread;

class MiniTrace : public instrumentation::InstrumentationListener {

  enum MiniTraceFlag {
    kDoMethodEntered =    1 << 0,
    kDoMethodExited =     1 << 1,
    kDoMethodUnwind =     1 << 2,
    kDoDexPcMoved =       1 << 3,
    kDoFieldRead =        1 << 4,
    kDoFieldWritten =     1 << 5,
    kDoExceptionCaught =  1 << 6,
    kDoMonitorEntered =   1 << 7,
    kDoMonitorExited =    1 << 8,
    kDoCoverage =         1 << 9,
    kDoFilter =           1 << 10,
  };

 public:
  static void Start(bool force_start=false)
      LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::thread_suspend_count_lock_,
                     Locks::trace_lock_);
  static void Stop()
      LOCKS_EXCLUDED(Locks::mutator_lock_,
                     Locks::thread_list_lock_,
                     Locks::trace_lock_);
  static void Shutdown() LOCKS_EXCLUDED(Locks::trace_lock_);

  static void Toggle() LOCKS_EXCLUDED(Locks::trace_lock_);

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

  // ExtInstrumentationListener implementation.
  void MonitorEntered(Thread* thread, mirror::Object* lock_object,
                     uint32_t dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  void MonitorExited(Thread* thread, mirror::Object* lock_object,
                    uint32_t dex_pc)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  static void StoreExitingThreadInfo(Thread* thread);

 private:
  explicit MiniTrace(File* trace_info_file, File* trace_data_file, uint32_t events, int buffer_size);

  void FinishTracing() SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogMethodTraceEvent(Thread* thread, mirror::ArtMethod* method, uint32_t dex_pc,
                           instrumentation::Instrumentation::InstrumentationEvent event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogFieldTraceEvent(Thread* thread, mirror::Object* this_object, mirror::ArtField* field,
                           uint32_t dex_pc, bool read_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogMonitorTraceEvent(Thread* thread, mirror::Object* lock_object, uint32_t dex_pc,
                           bool enter_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  bool HandleOverflow() LOCKS_EXCLUDED(Locks::trace_lock_);

  bool FlushBuffer();

  void DumpMethodList(std::ostream& os) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  void DumpFieldList(std::ostream& os) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  void DumpExecutionData(std::ostream& os) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
  void DumpThreadList(std::ostream& os) LOCKS_EXCLUDED(Locks::thread_list_lock_);

  // Singleton instance of the Trace or NULL when no method tracing is active.
  static MiniTrace* volatile the_trace_ GUARDED_BY(Locks::trace_lock_);

  // File to write method info and field info out to.
  std::unique_ptr<File> trace_info_file_;

  // File to write trace data out to.
  std::unique_ptr<File> trace_data_file_;

  // Buffer to store trace data.
  std::unique_ptr<uint8_t> buf_;

  // Events, default open every available events.
  uint32_t events_;

  // Log execution data
  bool do_coverage_;

  // Filter library code
  bool do_filter_;

  // Size of buf_.
  const int buffer_size_;

  // Time trace was created.
  const uint64_t start_time_;

  // Offset into buf_.
  AtomicInteger cur_offset_;

  // Overflow counter
  int buffer_overflow_count_;

  // Visited methods
  std::set<mirror::ArtMethod*> visited_methods_;

  // Visited fields
  std::set<mirror::ArtField*> visited_fields_;

  // Map of thread ids and names that have already exited.
  SafeMap<pid_t, std::string> exited_threads_;

  // Method Execution Data
  SafeMap<mirror::ArtMethod*, bool*> execution_data_;

  // Fuzzing

  DISALLOW_COPY_AND_ASSIGN(MiniTrace);
};

class MethodAction {

public:
  MethodAction(std::string data);
  ~MethodAction();

  // One sleep action and all exception actions
  int GetActionCount() {
    return exceptions_.size() + 1;
  }

  bool PerformAction(Thread* thread, int count)
       SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  long GetSleepTime() {
    return sleep_time_;
  }

  StringPiece& GetClass() {
    return declaring_class_;
  }

  StringPiece& GetName() {
    return name_;
  }

  StringPiece& GetSignature() {
    return signature_;
  }

  char* GetData() {
    return data_;
  }

private:
  void Parse(char* data);

  StringPiece declaring_class_;
  StringPiece name_;
  StringPiece signature_;

  std::vector<int>         exception_flags_;
  std::vector<StringPiece> exceptions_;

  long sleep_time_;

  char* data_;

};

class Fuzzing : public instrumentation::InstrumentationListener {
public:

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

  static void Toggle() LOCKS_EXCLUDED(Locks::trace_lock_);

  explicit Fuzzing(const char* config_file_name);
  ~Fuzzing();

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

  void ResolveMethodActions(mirror::Class* klass)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  static void PostClassPrepare(mirror::Class* klass)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void FinishFuzzing() SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

private:

  void PerformMethodAction(Thread* thread, mirror::ArtMethod* method, bool is_entry)
                       LOCKS_EXCLUDED(Locks::trace_lock_)
                       SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void AddMethodAction(std::string data);

  static Fuzzing* volatile the_fuzzing_ GUARDED_BY(Locks::trace_lock_);

  int current_point_;
  // parsed from configuration file
  std::queue<int> action_points_;
  int verbose_;
  std::unordered_map<std::string, std::vector<MethodAction*>> class_to_method_actions_;

  // resolved during post class prepare
  std::unordered_map<mirror::ArtMethod*, MethodAction*> resolved_method_actions_ GUARDED_BY(Locks::mutator_lock_);

  DISALLOW_COPY_AND_ASSIGN(Fuzzing);
};

}  // namespace art

#endif  // ART_RUNTIME_MINI_TRACE_H_
