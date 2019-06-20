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
#include "dex_file-inl.h"
#include "instrumentation.h"
#include "mirror/art_method-inl.h"
#include "mirror/class-inl.h"
#include "mirror/dex_cache.h"
#include "mirror/object_array-inl.h"
#include "mirror/object-inl.h"
#include "os.h"
#include "scoped_thread_state_change.h"
#include "ScopedLocalRef.h"
#include "thread.h"
#include "thread_list.h"
#if !defined(ART_USE_PORTABLE_COMPILER)
#include "entrypoints/quick/quick_entrypoints.h"
#endif

namespace art {

enum MiniTraceAction {
    kMiniTraceMethodEnter = 0x00,       // method entry
    kMiniTraceMethodExit = 0x01,        // method exit
    kMiniTraceUnroll = 0x02,            // method exited by exception unrolling
    kMiniTraceFieldRead = 0x03,         // field read
    kMiniTraceFieldWrite = 0x04,        // field write
    kMiniTraceMonitorEnter = 0x05,      // monitor enter
    kMiniTraceMonitorExit = 0x06,       // monitor exit
    kMiniTraceActionMask = 0x07,        // three bits
};

enum MiniTraceEventLength {
  kMiniTraceMethodEventLength = 6,
  kMiniTraceFieldEventLength = 14,
  kMiniTraceMonitorEventLength = 10,
  kMiniTraceLargestEventLength = kMiniTraceFieldEventLength,
};

static const char     kMiniTraceTokenChar             = '*';

MiniTrace* volatile MiniTrace::the_trace_ = NULL;

static uint16_t GetRecordSize(MiniTraceAction action) {
  switch (action) {
    case kMiniTraceMethodEnter:
    case kMiniTraceMethodExit:
    case kMiniTraceUnroll:
      return 6;
    case kMiniTraceFieldRead:
    case kMiniTraceFieldWrite:
      return 14;
    case kMiniTraceMonitorEnter:
    case kMiniTraceMonitorExit:
      return 10;
    default:
      UNIMPLEMENTED(FATAL) << "Unexpected action: " << action;
  }
  return 0;
}

static mirror::ArtMethod* DecodeMiniTraceMethodId(uint32_t tmid) {
  return reinterpret_cast<mirror::ArtMethod*>(tmid & ~kMiniTraceActionMask);
}

static mirror::ArtField* DecodeMiniTraceFieldId(uint32_t tfid) {
  return reinterpret_cast<mirror::ArtField*>(tfid & ~kMiniTraceActionMask);
}

static MiniTraceAction DecodeMiniTraceAction(uint32_t tmid) {
  return static_cast<MiniTraceAction>(tmid & kMiniTraceActionMask);
}

static uint32_t EncodeMiniTraceMethodAndAction(mirror::ArtMethod* method,
                                           MiniTraceAction action) {
  uint32_t tmid = PointerToLowMemUInt32(method) | action;
  DCHECK_EQ(method, DecodeMiniTraceMethodId(tmid));
  return tmid;
}

static uint32_t EncodeMiniTraceFieldAndAction(mirror::ArtField* field,
                                           MiniTraceAction action) {
  uint32_t tfid = PointerToLowMemUInt32(field) | action;
  return tfid;
}

static uint32_t EncodeMiniTraceObjectAndAction(mirror::Object* object,
                                           MiniTraceAction action) {
  uint32_t toid = PointerToLowMemUInt32(object) | action;
  return toid;
}

static uint32_t EncodeMiniTraceObject(mirror::Object* object) {
  return PointerToLowMemUInt32(object);
}

// TODO: put this somewhere with the big-endian equivalent used by JDWP.
static void Append2LE(uint8_t* buf, uint16_t val) {
  *buf++ = static_cast<uint8_t>(val);
  *buf++ = static_cast<uint8_t>(val >> 8);
}

// TODO: put this somewhere with the big-endian equivalent used by JDWP.
static void Append4LE(uint8_t* buf, uint32_t val) {
  *buf++ = static_cast<uint8_t>(val);
  *buf++ = static_cast<uint8_t>(val >> 8);
  *buf++ = static_cast<uint8_t>(val >> 16);
  *buf++ = static_cast<uint8_t>(val >> 24);
}

bool SDCARDEnabled() {
  const gid_t SDCARD_RW = 1015;  // See system/core/include/private/android_filesystem_config.h
  int size = getgroups(0, NULL);

  if (size == -1) {
    LOG(ERROR) << "MiniTrace: getgroups failed: " << strerror(errno);
    return false;
  }

  std::unique_ptr<gid_t[]> gids;
  gids.reset(new gid_t[size]);

  size = getgroups(size, gids.get());
  if (size == -1) {
    LOG(ERROR) << "MiniTrace: getgroups failed: " << strerror(errno);
    return false;
  }

  for (int i = 0; i < size; i++) {
    if (gids[i] == SDCARD_RW) {
      return true;
    }
  }

  return false;
}

void MiniTrace::Start(bool force_start) {
  Thread* self = Thread::Current();
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_trace_ != NULL) {
      LOG(ERROR) << "Trace already in progress, ignoring this request";
      return;
    }
  }

  const char* trace_base_filename = "/data/mini_trace_";
  bool sdcard_enabeld = SDCARDEnabled();
  if (sdcard_enabeld) {
    trace_base_filename = "/sdcard/mini_trace_";
  }

  uint32_t events = 0;
  int buffer_size = 1 * 1024 * 1024;
  {
    std::ostringstream os;
    os << trace_base_filename << getuid()  << "_config.in";
    std::string trace_config_filename(os.str());

    if (OS::FileExists(trace_config_filename.c_str())) {
      std::ifstream in(trace_config_filename.c_str());
      if (!in) {
        LOG(INFO) << "MiniTrace: config file " << trace_config_filename << " exists but can't be opened";
        return;
      }
      // The first line contains on or off.
      std::string line;

      while (!in.eof()) {
        std::getline(in, line);
        if (in.eof()) {
          break;
        }
        if (line.compare("off") == 0) {
          LOG(INFO) << "MiniTrace has been turned off in the config file " << trace_config_filename;
          return;
        } else if (line.compare("DoCoverage") == 0) {
          LOG(INFO) << "MiniTrace: enable DoCoverage in file " << trace_config_filename;
          events |= kDoCoverage;
        } else if (line.compare("DoFilter") == 0) {
          LOG(INFO) << "MiniTrace: enable DoFilter in file " << trace_config_filename;
          events |= kDoFilter;
        } else if (line.compare("MethodEvent") == 0) {
          LOG(INFO) << "MiniTrace: enable MethodEvent in file " << trace_config_filename;
          events |= kDoMethodEntered | kDoMethodExited | kDoMethodUnwind;
        } else if (line.compare("FieldEvent") == 0) {
          LOG(INFO) << "MiniTrace: enable FieldEvent in file " << trace_config_filename;
          events |= kDoFieldRead | kDoFieldWritten;
        } else if (line.compare("MonitorEvent") == 0) {
          LOG(INFO) << "MiniTrace: enable MonitorEvent in file " << trace_config_filename;
          events |= kDoMonitorEntered | kDoMonitorExited;
        } else {
          LOG(INFO) << "MiniTrace: ignore unknown option " << line << " in file " << trace_config_filename;
        }
      }
      LOG(INFO) << StringPrintf("MiniTrace: final events: 0x%08x", events);
    } else if (!force_start) {
      LOG(INFO) << "MiniTrace: config file " << trace_config_filename << " does not exist";
      return;
    }
  }

  std::unique_ptr<File> trace_info_file;
  {
    std::ostringstream os;
    os << trace_base_filename << getuid()  << "_info.log";
    std::string trace_info_filename(os.str());
    trace_info_file.reset(OS::CreateEmptyFile(trace_info_filename.c_str()));
    if (trace_info_file.get() == NULL) {
      LOG(INFO) << "MiniTrace: Unable to open trace info file '" << trace_info_filename << "'";
      return;
    }
  }

  std::unique_ptr<File> trace_data_file;
  {
    std::ostringstream os;
    os << trace_base_filename << getuid()  << "_data.bin";
    std::string trace_data_filename(os.str());
    trace_data_file.reset(OS::CreateEmptyFile(trace_data_filename.c_str()));
    if (trace_data_file.get() == NULL) {
      LOG(INFO) << "MiniTrace: Unable to open trace data file '" << trace_data_filename << "'";
      return;
    }
  }

  Runtime* runtime = Runtime::Current();

  runtime->GetThreadList()->SuspendAll();

  // Create Trace object.
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_trace_ != NULL) {
      LOG(ERROR) << "Trace already in progress, ignoring this request";
    } else {
      if (events == 0) {  // Do everything we can if there is no events
        events = instrumentation::Instrumentation::kMethodEntered |
                 instrumentation::Instrumentation::kMethodExited |
                 instrumentation::Instrumentation::kMethodUnwind |
                 instrumentation::Instrumentation::kFieldRead |
                 instrumentation::Instrumentation::kFieldWritten |
                 kDoCoverage;
      }

      the_trace_ = new MiniTrace(trace_info_file.release(),
                                 trace_data_file.release(),
                                 events,
                                 buffer_size);

      runtime->GetInstrumentation()->AddListener(the_trace_, events);
      runtime->GetInstrumentation()->EnableMethodTracing();
    }
  }

  runtime->GetThreadList()->ResumeAll();
}

void MiniTrace::Stop() {
  Runtime* runtime = Runtime::Current();
  runtime->GetThreadList()->SuspendAll();
  MiniTrace* the_trace = NULL;
  {
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    if (the_trace_ == NULL) {
      LOG(ERROR) << "Trace stop requested, but no trace currently running";
    } else {
      the_trace = the_trace_;
      the_trace_ = NULL;
    }
  }
  if (the_trace != NULL) {
    the_trace->FinishTracing();

    /* uint32_t events = instrumentation::Instrumentation::kMethodEntered |
                      instrumentation::Instrumentation::kMethodExited |
                      instrumentation::Instrumentation::kMethodUnwind |
                      instrumentation::Instrumentation::kFieldRead |
                      instrumentation::Instrumentation::kFieldWritten;*/

    runtime->GetInstrumentation()->DisableMethodTracing();
    runtime->GetInstrumentation()->RemoveListener(the_trace, the_trace->events_);

    if (the_trace->trace_info_file_.get() != nullptr) {
      // Do not try to erase, so flush and close explicitly.
      if (the_trace->trace_info_file_->Flush() != 0) {
        PLOG(ERROR) << "Could not flush trace info file.";
      }
      if (the_trace->trace_info_file_->Close() != 0) {
        PLOG(ERROR) << "Could not close trace info file.";
      }
    }
    if (the_trace->trace_data_file_.get() != nullptr) {
      // Do not try to erase, so flush and close explicitly.
      if (the_trace->trace_data_file_->Flush() != 0) {
        PLOG(ERROR) << "Could not flush trace data file.";
      }
      if (the_trace->trace_data_file_->Close() != 0) {
        PLOG(ERROR) << "Could not close trace data file.";
      }
    }
    delete the_trace;
  }
  runtime->GetThreadList()->ResumeAll();
}

void MiniTrace::Shutdown() {
  if (GetMethodTracingMode() != kTracingInactive) {
    Stop();
  }
}

void MiniTrace::Toggle() {
  if (GetMethodTracingMode() == kTracingInactive) {
    LOG(INFO) << "MiniTrace: toggle on";
    Start(true);
  } else {
    LOG(INFO) << "MiniTrace: toggle off";
    Stop();
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

MiniTrace::MiniTrace(File* trace_info_file, File* trace_data_file,
      uint32_t events, int buffer_size)
    : trace_info_file_(trace_info_file), trace_data_file_(trace_data_file),
      buf_(new uint8_t[buffer_size]()), events_(events), do_coverage_((events & kDoCoverage) != 0),
      do_filter_((events & kDoFilter) != 0), buffer_size_(buffer_size), start_time_(MicroTime()),
      cur_offset_(0), buffer_overflow_count_(0) {
}

void MiniTrace::FinishTracing() {
  FlushBuffer();

  std::ostringstream os;

  os << StringPrintf("%cthreads\n", kMiniTraceTokenChar);
  DumpThreadList(os);
  os << StringPrintf("%cmethods\n", kMiniTraceTokenChar);
  DumpMethodList(os);
  os << StringPrintf("%cfields\n", kMiniTraceTokenChar);
  DumpFieldList(os);
  os << StringPrintf("%ccoverage\n", kMiniTraceTokenChar);
  DumpExecutionData(os);
  os << StringPrintf("%cend\n", kMiniTraceTokenChar);

  std::string header(os.str());
  if (!trace_info_file_->WriteFully(header.c_str(), header.length())) {
    std::string detail(StringPrintf("Trace info write failed: %s", strerror(errno)));
    PLOG(ERROR) << detail;
    ThrowRuntimeException("%s", detail.c_str());
  }
}

void MiniTrace::DexPcMoved(Thread* thread, mirror::Object* this_object,
                       mirror::ArtMethod* method, uint32_t new_dex_pc) {
  // We're not recorded to listen to this kind of event, so complain.
  LOG(ERROR) << "Unexpected dex PC event in tracing " << PrettyMethod(method) << " " << new_dex_pc;
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
}

void MiniTrace::MethodUnwind(Thread* thread, mirror::Object* this_object,
                         mirror::ArtMethod* method, uint32_t dex_pc) {
  LogMethodTraceEvent(thread, method, dex_pc, instrumentation::Instrumentation::kMethodUnwind);
}

void MiniTrace::ExceptionCaught(Thread* thread, const ThrowLocation& throw_location,
                            mirror::ArtMethod* catch_method, uint32_t catch_dex_pc,
                            mirror::Throwable* exception_object)
    SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
  LOG(ERROR) << "Unexpected exception caught event in tracing";
}

bool MiniTrace::HandleOverflow() {
  const uint16_t largest_record_size = kMiniTraceLargestEventLength;
  Thread* self = Thread::Current();

  {
    MutexLock mu(self, *Locks::trace_lock_);

    if (buffer_overflow_count_ > 1024) {  // 1024 * 1 MB = 1 GB
      return false;
    }

    int32_t old_offset = cur_offset_.LoadRelaxed();
    int32_t new_offset = old_offset + largest_record_size;
    if (new_offset <= buffer_size_) {  // already handled
      return true;
    }

    buffer_overflow_count_ ++;

    return FlushBuffer();
  }
}

bool MiniTrace::FlushBuffer() {

  int32_t cur_offset = cur_offset_.LoadRelaxed();

  if (!trace_data_file_->WriteFully(buf_.get(), cur_offset)) {
    std::string detail(StringPrintf("Trace data write failed: %s", strerror(errno)));
    PLOG(ERROR) << detail;
    return false;
  }


  uint8_t* ptr = buf_.get();
  uint8_t* end = buf_.get() + cur_offset;

  while (ptr < end) {
    uint32_t aid = ptr[2] | (ptr[3] << 8) | (ptr[4] << 16) | (ptr[5] << 24);
    MiniTraceAction action = DecodeMiniTraceAction(aid);
    uint32_t length = 0;
    switch (action) {
      case kMiniTraceMethodEnter:
      case kMiniTraceMethodExit:
      case kMiniTraceUnroll:
        length = 6;
        visited_methods_.insert(DecodeMiniTraceMethodId(aid));
        break;
      case kMiniTraceFieldRead:
      case kMiniTraceFieldWrite:
        length = 14;
        visited_fields_.insert(DecodeMiniTraceFieldId(aid));
        break;
      case kMiniTraceMonitorEnter:
      case kMiniTraceMonitorExit:
        length = 10;
        break;
      default:
        UNIMPLEMENTED(FATAL) << "Unexpected action: " << action;
    }
    ptr += length;
  }

  cur_offset_.StoreRelease(0);
  return true;
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
      UNIMPLEMENTED(FATAL) << "Unexpected event: " << event;
  }

  // Advance cur_offset_ atomically.
  int32_t new_offset;
  int32_t old_offset;
  int32_t overflow_check;
  do {
    old_offset = cur_offset_.LoadRelaxed();
    new_offset = old_offset + GetRecordSize(action);
    overflow_check = old_offset + kMiniTraceLargestEventLength;
    if (overflow_check > buffer_size_) {
      if (HandleOverflow()) {
        continue;
      }
      return;
    }
  } while (!cur_offset_.CompareExchangeWeakSequentiallyConsistent(old_offset, new_offset));


  uint32_t method_value = EncodeMiniTraceMethodAndAction(method, action);

  // Write data
  uint8_t* ptr = buf_.get() + old_offset;
  Append2LE(ptr, thread->GetTid());
  Append4LE(ptr + 2, method_value);
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

  // Advance cur_offset_ atomically.
  int32_t new_offset;
  int32_t old_offset;
  int32_t overflow_check;
  do {
    old_offset = cur_offset_.LoadRelaxed();
    new_offset = old_offset + GetRecordSize(action);
    overflow_check = old_offset + kMiniTraceLargestEventLength;
    if (overflow_check > buffer_size_) {
      if (HandleOverflow()) {
        continue;
      }
      return;
    }
  } while (!cur_offset_.CompareExchangeWeakSequentiallyConsistent(old_offset, new_offset));

  uint32_t field_value = EncodeMiniTraceFieldAndAction(field, action);

  // Write data
  uint8_t* ptr = buf_.get() + old_offset;
  Append2LE(ptr, thread->GetTid());
  Append4LE(ptr + 2, field_value);
  ptr += 6;

  uint32_t object_value = EncodeMiniTraceObject(this_object);
  Append4LE(ptr, object_value);
  Append4LE(ptr + 4, dex_pc);
}

void MiniTrace::LogMonitorTraceEvent(Thread* thread, mirror::Object* lock_object,
    uint32_t dex_pc, bool enter_event) {
  MiniTraceAction action;
  if (enter_event) {
    action = kMiniTraceMonitorEnter;
  } else {
    action = kMiniTraceMonitorExit;
  }

  // Advance cur_offset_ atomically.
  int32_t new_offset;
  int32_t old_offset;
  int32_t overflow_check;
  do {
    old_offset = cur_offset_.LoadRelaxed();
    new_offset = old_offset + GetRecordSize(action);
    overflow_check = old_offset + kMiniTraceLargestEventLength;
    if (overflow_check > buffer_size_) {
      if (HandleOverflow()) {
        continue;
      }
      return;
    }
  } while (!cur_offset_.CompareExchangeWeakSequentiallyConsistent(old_offset, new_offset));

  uint32_t object_value = EncodeMiniTraceObjectAndAction(lock_object, action);

  // Write data
  uint8_t* ptr = buf_.get() + old_offset;
  Append2LE(ptr, thread->GetTid());
  Append4LE(ptr + 2, object_value);
  ptr += 6;

  Append4LE(ptr, dex_pc);
}

void MiniTrace::DumpMethodList(std::ostream& os) {
  for (const auto& method : visited_methods_) {
    os << StringPrintf("%p\t%s\t%s\t%s\t%s\n", method,
        PrettyDescriptor(method->GetDeclaringClassDescriptor()).c_str(), method->GetName(),
        method->GetSignature().ToString().c_str(), method->GetDeclaringClassSourceFile());
  }
}

void MiniTrace::DumpFieldList(std::ostream& os) {
  for (const auto& field : visited_fields_) {
    // TODO we may use FieldHelper to help print a field.
    const DexFile* dex_file = field->GetDexFile();
    const DexFile::FieldId& field_id = dex_file->GetFieldId(field->GetDexFieldIndex());
    os << StringPrintf("%p\t%s\t%s\t%s\n", field,
        PrettyDescriptor(dex_file->GetFieldDeclaringClassDescriptor(field_id)).c_str(), field->GetName(),
        field->GetTypeDescriptor());
  }
}

static void DumpThread(Thread* t, void* arg) {
  std::ostream& os = *reinterpret_cast<std::ostream*>(arg);
  std::string name;
  t->GetThreadName(name);
  os << t->GetTid() << "\t" << name << "\n";
}

void MiniTrace::DumpExecutionData(std::ostream& os) {
  for (auto it : execution_data_) {
    mirror::ArtMethod* method = it.first;
    bool* execution_data = it.second;
    const DexFile::CodeItem* code_item = method->GetCodeItem();
    uint16_t insns_size = code_item->insns_size_in_code_units_;

    os << StringPrintf("%p\t%d\t", method, insns_size);

    for (int i = 0; i < insns_size; i++) {
      if (execution_data[i]) {
        os << 1;
      } else {
        os << 0;
      }
    }
    os << '\n';
    delete[] execution_data;
    it.second = NULL;
  }
}

void MiniTrace::DumpThreadList(std::ostream& os) {
  Thread* self = Thread::Current();
  for (auto it : exited_threads_) {
    os << it.first << "\t" << it.second << "\n";
  }
  Locks::thread_list_lock_->AssertNotHeld(self);
  MutexLock mu(self, *Locks::thread_list_lock_);
  Runtime::Current()->GetThreadList()->ForEach(DumpThread, &os);
}

void MiniTrace::StoreExitingThreadInfo(Thread* thread) {
  MutexLock mu(thread, *Locks::trace_lock_);
  if (the_trace_ != nullptr) {
    std::string name;
    thread->GetThreadName(name);
    the_trace_->exited_threads_.Put(thread->GetTid(), name);
  }
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

      the_trace->visited_methods_.insert(method);
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


MethodAction::MethodAction(std::string data) {
  data_ = new char[data.size() + 1];
  std::copy(data.begin(), data.end(), data_);
  data_[data.size()] = '\0';
  Parse(data_);
}

MethodAction::~MethodAction() {
  delete [] data_;
}

char* next_token(char* &p) {
  for (;;p++) {
    if (*p == '\0') {
      return NULL; // stop iteration
    }
    if (*p == ' ') {
      //*p = '\0'; // do split
      return p;
    }
  }
}

void MethodAction::Parse(char* data) {
  char* begin = data;
  char* end = data;

  if (next_token(end)) {
    declaring_class_.set(begin, (end - begin) / sizeof(char));
    begin = ++ end;
  } else {
    return;
  }

  if (next_token(end)) {
    name_.set(begin, (end - begin) / sizeof(char));
    begin = ++ end;
  } else {
    return;
  }

  if (next_token(end)) {
    signature_.set(begin, (end - begin) / sizeof(char));
    begin = ++ end;
  } else {
    return;
  }

  if (next_token(end)) {
    std::stringstream ss;
    ss << begin;
    ss >> sleep_time_;
    begin = ++ end;
  } else {
    return;
  }

  while(true) {
    StringPiece exception;
    int flag;

    if (next_token(end)) {
      exception.set(begin, (end - begin) / sizeof(char));
      begin = ++ end;
    } else {
      return;
    }

    // parse flags
    if (next_token(end)) {
      std::stringstream ss;
      ss << begin;
      ss >> flag;
      begin = ++ end;
    } else {
      return;
    }

    exceptions_.push_back(exception);
    exception_flags_.push_back(flag);
  }
}

bool MethodAction::PerformAction(Thread* thread, int count) {

  if (count == 0) {
    LOG(INFO) << "Fuzzing: performing action " << count << " that sleeps for " << sleep_time_ << " for " << data_;
    usleep(sleep_time_);
    return true;
  }

  count--;
  int size = exceptions_.size();
  if (count >= 0 && count < size) {
    std::string temp;
    exceptions_[count].CopyToString(&temp);
    const char* exception_class_name = static_cast<const char*>(temp.c_str());

    JNIEnv* jni = thread->GetJniEnv();

    jclass exception_type = jni->FindClass(exception_class_name);
    if (exception_type == NULL) {
      LOG(INFO) << "Fuzzing: cannot find class [" << exception_class_name << "]";
      return false;
    }

    LOG(INFO) << "Fuzzing: performing action " << (count+1) << " that throws an exception of " << exception_class_name << " for " << data_;
    jni->ThrowNew(exception_type, "throwing a phantom exception for fuzzing!");
    return true;
  }

  LOG(FATAL) << "There are " << exceptions_.size() << " exceptions, but we are requesting " << count;
  return false;
}


Fuzzing* volatile Fuzzing::the_fuzzing_ = NULL;


static bool ResolveMethodActionsClassVisitor(mirror::Class* klass, void* arg)
    SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
  Fuzzing* fuzzing = reinterpret_cast<Fuzzing*>(arg);
  fuzzing->ResolveMethodActions(klass);
  return true;
}

void Fuzzing::Start() {
  Thread* self = Thread::Current();
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_fuzzing_ != NULL) {
      LOG(ERROR) << "Fuzzing already in progress, ignoring this request";
      return;
    }
  }

  const char* trace_base_filename = "/data/mini_trace_";
  // if (SDCARDEnabled()) {
  //   trace_base_filename = "/sdcard/mini_trace_";
  // }

  std::ostringstream os;
  os << trace_base_filename << getuid()  << "_fuzzing.in";
  std::string config_filename(os.str());

  if (!OS::FileExists(config_filename.c_str())) {
    LOG(INFO) << "Fuzzing config file " << config_filename << " does not exist!";
    return;
  }

  Runtime* runtime = Runtime::Current();

  runtime->GetThreadList()->SuspendAll();

  // Create Trace object.
  {
    MutexLock mu(self, *Locks::trace_lock_);
    if (the_fuzzing_ != NULL) {
      LOG(ERROR) << "Fuzzing already in progress, ignoring this request";
    } else {
      the_fuzzing_ = new Fuzzing(config_filename.c_str());

      runtime->GetInstrumentation()->AddListener(the_fuzzing_,
              instrumentation::Instrumentation::kMethodEntered |
              instrumentation::Instrumentation::kMethodExited);
      runtime->GetInstrumentation()->EnableMethodTracing();

      runtime->GetClassLinker()->VisitClasses(ResolveMethodActionsClassVisitor, the_fuzzing_);
    }
  }

  runtime->GetThreadList()->ResumeAll();
}

void Fuzzing::Stop() {
  Runtime* runtime = Runtime::Current();
  runtime->GetThreadList()->SuspendAll();
  Fuzzing * the_fuzzing = NULL;
  {
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    if (the_fuzzing_ == NULL) {
      LOG(ERROR) << "Fuzzing stop requested, but no trace currently running";
    } else {
      the_fuzzing = the_fuzzing_;
      the_fuzzing_ = NULL;
    }
  }
  if (the_fuzzing != NULL) {
    the_fuzzing->FinishFuzzing();

    runtime->GetInstrumentation()->DisableMethodTracing();
    runtime->GetInstrumentation()->RemoveListener(the_fuzzing,
                      instrumentation::Instrumentation::kMethodEntered |
                      instrumentation::Instrumentation::kMethodExited);

    delete the_fuzzing;
  }
  runtime->GetThreadList()->ResumeAll();
}

void Fuzzing::Shutdown() {
  {
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    if (the_fuzzing_ == NULL) {
      return;
    }
  }
  Stop();
}

void Fuzzing::Toggle() {
  bool started = false;

  {
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    if (the_fuzzing_ != NULL) {
      started = true;
    }
  }

  if (started) {
    LOG(INFO) << "Fuzzing: toggle off";
    Stop();
  } else {
    LOG(INFO) << "Fuzzing: toggle on";
    Start();
  }
}

Fuzzing::Fuzzing(const char* config_file_name)
  : current_point_(0), verbose_(0) {
  if (OS::FileExists(config_file_name)) {
    std::ifstream in(config_file_name);
    if (!in) {
      LOG(INFO) << "Fuzzing: config file " << config_file_name << " exists but can't be opened";
      return;
    }
    std::string line;
    std::getline(in, line);

    if (line.compare(0, 7, "verbose") == 0) {
      verbose_ = atoi(line.c_str() + 7);
      std::getline(in, line);
    } else {
      LOG(INFO) << "Fuzzing: no verbose line but " << line;
    }

    if (line.compare(0, 7, "action ") == 0) {
      char* begin = const_cast<char*>(line.c_str() + 7); // one more for the space
      char* end = begin;
      while (next_token(end)) {
        int p = atoi(begin);
        if (verbose_ > 0) {
          LOG(INFO) << "Fuzzing: add an action point " << p;
        }
        action_points_.push(p);
        begin = ++end;
      }
    }  else {
      LOG(INFO) << "Fuzzing: no action line but " << line;
      AddMethodAction(line);
    }

    while (!in.eof()) {
      std::getline(in, line);
      if (in.eof()) {
        break;
      }
      AddMethodAction(line);
    }

  } else {
    LOG(INFO) << "Fuzzing: config file " << config_file_name << " does not exist";
    return;
  }
}

void Fuzzing::FinishFuzzing() {
  LOG(INFO) << "Fuzzing: current point is " << current_point_;
}

void Fuzzing::AddMethodAction(std::string data) {
  MethodAction* action = new MethodAction(data);

  std::string descriptor;
  action->GetClass().CopyToString(&descriptor);

  std::vector<MethodAction*> &actions = class_to_method_actions_[descriptor];
  actions.push_back(action);
}

Fuzzing::~Fuzzing() {
  resolved_method_actions_.clear();

  for (auto &e : class_to_method_actions_) {
    std::vector<MethodAction*> &actions = e.second;
    for (auto &a : actions) {
      delete a;
    }
  }
  class_to_method_actions_.clear();
}

void Fuzzing::DexPcMoved(Thread* thread, mirror::Object* this_object,
                       mirror::ArtMethod* method, uint32_t new_dex_pc) {
  // We're not recorded to listen to this kind of event, so complain.
  LOG(ERROR) << "Unexpected dex PC event in fuzzing " << PrettyMethod(method) << " " << new_dex_pc;
};

void Fuzzing::FieldRead(Thread* thread, mirror::Object* this_object,
                       mirror::ArtMethod* method, uint32_t dex_pc, mirror::ArtField* field) {
  LOG(ERROR) << "Unexpected FieldRead event in fuzzing " << PrettyMethod(method) << " " << dex_pc;
}

void Fuzzing::FieldWritten(Thread* thread, mirror::Object* this_object,
                          mirror::ArtMethod* method, uint32_t dex_pc, mirror::ArtField* field,
                          const JValue& field_value) {
  LOG(ERROR) << "Unexpected FieldWritten event in fuzzing " << PrettyMethod(method) << " " << dex_pc;
}

void Fuzzing::MethodEntered(Thread* thread, mirror::Object* this_object,
                          mirror::ArtMethod* method, uint32_t dex_pc) {
  PerformMethodAction(thread, method, true);
}

void Fuzzing::MethodExited(Thread* thread, mirror::Object* this_object,
                         mirror::ArtMethod* method, uint32_t dex_pc,
                         const JValue& return_value) {
  PerformMethodAction(thread, method, false);
}

void Fuzzing::MethodUnwind(Thread* thread, mirror::Object* this_object,
                         mirror::ArtMethod* method, uint32_t dex_pc) {
  LOG(ERROR) << "Unexpected method unwind event in fuzzing";
}

void Fuzzing::ExceptionCaught(Thread* thread, const ThrowLocation& throw_location,
                            mirror::ArtMethod* catch_method, uint32_t catch_dex_pc,
                            mirror::Throwable* exception_object)
    SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
  LOG(ERROR) << "Unexpected exception caught event in fuzzing";
}


struct MethodTraceEventMark {

public:
  MethodTraceEventMark(Thread* thread) : thread_(thread) {
    thread_->BeginMethodTraceEvent();
  }

  ~MethodTraceEventMark() {
    thread_->EndMethodTraceEvent();
  }

private:
  Thread* thread_;
};

void Fuzzing::PerformMethodAction(Thread* thread, mirror::ArtMethod* method, bool is_entry) {
  if (thread != Thread::Current()) {
    return;
  }

  if (thread->HandlingMethodTraceEvent()) {
    return;
  }

  MethodTraceEventMark mtem(thread);

  MethodAction* action = resolved_method_actions_[method];

  if (action == NULL) {
    return;
  }

  {
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    int current_point = current_point_;
    int next_point = current_point_ + action->GetActionCount();

    if (verbose_ > 0) {
      LOG(INFO) << "Fuzzing: try to retrieve an action point in [" << current_point << "," << next_point << ") for method " 
        << (is_entry ? "entry of " : "exit of ")
        << PrettyMethod(method);
    }

    int action_point = -1;
    if (!action_points_.empty()) {

      do {
        action_point = action_points_.front();
        if (action_point < current_point) {
          LOG(INFO) << "Fuzzing: ignore action point " << action_point << " cause it's less than current point " << current_point;
          action_points_.pop();
        } else if (action_point < next_point) {
          action_points_.pop();
          break;
        } else {
          break;
        }
      } while (!action_points_.empty());
    }
    if (action_point >= current_point && action_point < next_point) {
      int the_point = action_point - current_point;
      LOG(INFO) << "Fuzzing: perform action at " << action_point;
      action->PerformAction(thread, the_point);
    } else { // use random
      // TODO
    }

    current_point_ = next_point;
  }
  return;
}


void Fuzzing::ResolveMethodActions(mirror::Class* klass) {
  if (klass->IsArrayClass() || klass->IsInterface() || klass->IsPrimitive()) {
    return;
  }

  std::string temp;
  const char* descriptor = klass->GetDescriptor(&temp);

  if (verbose_ > 0) {
    LOG(INFO) << "Fuzzing: resolving " << descriptor;
  }

  auto it = class_to_method_actions_.find(std::string(descriptor));
  if (it == class_to_method_actions_.end()) {
    return;
  }

  std::vector<MethodAction*> &actions = it->second;

  for (auto &ma:actions) {
    StringPiece &name = ma->GetName();
    StringPiece &signature = ma->GetSignature();
    mirror::ArtMethod* method = klass->FindDeclaredDirectMethod(name, signature);
    if (method == nullptr) {
      method = klass->FindDeclaredVirtualMethod(name, signature);
    }

    if (method == nullptr) {
      LOG(INFO) << "Fuzzing: cannot find method " << name << signature;
      continue;
    }
    LOG(INFO) << "Fuzzing: resolve method action for " << ma->GetData();
    resolved_method_actions_.emplace(method, ma);
  }
}

void Fuzzing::PostClassPrepare(mirror::Class* klass) {
  if (klass->IsArrayClass() || klass->IsInterface() || klass->IsPrimitive()) {
    return;
  }

  {
    MutexLock mu(Thread::Current(), *Locks::trace_lock_);
    Fuzzing* the_fuzzing = the_fuzzing_;
    if (the_fuzzing == NULL) {
      return;
    }

    the_fuzzing->ResolveMethodActions(klass);
  }
}


}  // namespace art
