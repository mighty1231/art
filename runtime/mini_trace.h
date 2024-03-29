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
#include "ScopedLocalRef.h"
#include <utils/Timers.h>

// MAX_THREAD_COUNT may not be enough
#define MAX_THREAD_COUNT 256
namespace art {

namespace mirror {
  class Class;
  class ArtField;
  class ArtMethod;
}  // namespace mirror

class Thread;

void StringAppendArgumentValues(std::string *string_p, mirror::ArtMethod *method, ShadowFrame *shadow_frame)
    SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

class lazy_target {
public:
  int id;
  std::string clsname;
  std::string mtdname;
  std::string signature;
  int flag;
  lazy_target(int id_, char *clsname_, char *mtdname_, char *signature_, int flag_) :
      id(id_), clsname(clsname_), mtdname(mtdname_), signature(signature_), flag(flag_) {
    // android/os/MessageQueue -> Landroid/os/MessageQueue;
    clsname.insert(0, 1, 'L');
    clsname.insert(clsname.end(), 1, ';');
  }
};

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
    kInstListener        = 0x00000077,  /* Currently, DexPcMoved is not used */

    /* Flags used only for MiniTrace */
    kDoCoverage          = 0x00000080,
    kLogMessage          = 0x00000100,  // log all messages on main looper

    /* Flags used for communicate with ape */
    kConnectAPE          = 0x00010000,  // If set, communicates with APE

    /* Ping flag */
    kLogOneSecPing       = 0x00020000,  // If set, push simple log for every 1 second

    /* Flags used for filtering objects */
    kLogFieldTypeFlags   = 0x0F000000,
    kLogFieldType0       = 0x01000000,  // All the other fields
    kLogFieldType1       = 0x02000000,  // UNUSED
    kLogFieldType2       = 0x04000000,  // UNUSED
    kLogFieldType3       = 0x08000000,  // fields defined on app
    kLogMethodTypeFlags  = 0xF0000000,
    kLogMethodType0      = 0x10000000,  // Basic API methods
    kLogMethodType1      = 0x20000000,  // Non-basic API methods
    kLogMethodType2      = 0x40000000,  // IdleHandler$queueIdle
    kLogMethodType3      = 0x80000000,  // methods defined on app
    kFlagAll             = 0xFF0301FF
  };

  static const int kApeHandShake;
  static const int kApeHandShakeNoGuide;
  static const int kApeTargetEntered;
  static const int kApeTargetExited;
  static const int kApeTargetUnwind;
  static const int kApeIdle;

  enum MessageStatus {
    kMessageInitial,
    kMessageEnqueued,
    kMessageIdled,
    kMessageLooperMessageSent
  };

  enum MessageStatusTransition {
    kMessageTransitionEnqueued,
    kMessageTransitionQueueIdleExited,
    kMessageTransitionNativePollOnceEntered,
    kMessageTransitionNativePollOnceExited
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

  static char* GetExecutionData(Thread* self, mirror::ArtMethod* method)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_)
      LOCKS_EXCLUDED(Locks::trace_lock_);

  static void PostClassPrepare(mirror::Class* klass, const char *descriptor)
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

  static void *ConsumerTask(void *mt_object);
  static void *PingingTask(void *mt_object);

  class ArtMethodDetail {
   public:
    explicit ArtMethodDetail(mirror::ArtMethod* method) : method_(method) {
      // @TODO Is this detail enough? consider argument type & return type
      const char *descriptor = method->GetDeclaringClassDescriptor();
      if (descriptor == NULL)
        classDescriptor_.assign("NoDescriptor");
      else
        classDescriptor_.assign(descriptor);
      name_.assign(method->GetName());
      signature_.assign(method->GetSignature().ToString());  // It never fails, "<no signature>" in dexfile.cc:994
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
    explicit ArtFieldDetail(mirror::ArtField *field) : field_(field),
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
    ThreadDetail(pid_t tid, std::string name): tid_(tid), name_(name) {}
    bool operator< (const ThreadDetail *other) const {
      if (this->tid_ == other->tid_)
        return this->name_.compare(other->name_);
      else
        return this->tid_ < other->tid_;
    }
    void Dump(std::string &string) {
      string.append(StringPrintf("%d\t%s\n", tid_, name_.c_str()));
    }
   private:
    pid_t tid_;
    std::string name_;
  };

  /* Wrapper for android/os/Message */
  class MessageDetail {
   public:
    /**
     * Logged if MessageQueue is the main MessageQueue
     * Note: Every message enqueued do not need to be dispatched.
     *       Some messages are not dispatched by calling removeMessages.
     */
    static void cb_enqueueMessage(mirror::Object *message)
        SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
      Thread *self = Thread::Current();      
      /**
       * enqueueMessage uses elapsed time after booting
       * $ long uptimeMillis = SystemClock.uptimeMillis();
       * It returns different value with System.currentTimeMillis();
       */
      int64_t uptimeMillis = systemTime(SYSTEM_TIME_MONOTONIC) / 1000000LL;
      int64_t when = self->GetManagedStack()->GetTopShadowFrame()->GetVRegLong(10);
      int dispatch_timediff_millis = when - uptimeMillis;
      {
        MutexLock mu(self, *lock);

        // Find message
        std::map<mirror::Object*, MessageDetail*>::iterator lm = last_messages_.find(message);
        CHECK(lm == last_messages_.end() || lm->second == NULL)
            << "Same message enqueued during dispatching it, message = " << message;
        // New message
        MessageDetail *new_msg_detail;
        auto cause_stack = thread_to_msgstack_.find(self);
        if (cause_stack != thread_to_msgstack_.end()) {
          // cause exists
          std::vector<MessageDetail*> vec = cause_stack->second;
          if (!vec.empty()) {
            new_msg_detail = new MessageDetail(message, dispatch_timediff_millis, vec.back());
          } else {
            new_msg_detail = new MessageDetail(message, dispatch_timediff_millis, self);
          }
        } else {
          // cause does not exist
          new_msg_detail = new MessageDetail(message, dispatch_timediff_millis, self);
        }
        messages_.push_back(new_msg_detail);
        last_messages_[message] = messages_.back();
        cur_id_++;
        if (new_msg_detail->cause_unknown_) {
          LOG(INFO) << "Unknown sourced message " << new_msg_detail->Dump();
          MethodStackVisitor visitor(self);
          visitor.WalkStack(true);
        }
      }
    }
    /* cause is logged for anytime */
    static MessageDetail *cb_dispatchMessage_enter(mirror::Object *message) {
      Thread *self = Thread::Current();
      MutexLock mu(self, *lock);
      auto lm = last_messages_.find(message);
      if (lm == last_messages_.end()) {
        /* Maybe the app is dying now */
        LOG(INFO) << "Dispatching never-seen message " << message
            << "\n" << MessageDetail::DumpAll(false);
        return NULL;
      }
      MessageDetail *last_message = lm->second;
      if (thread_to_msgstack_.find(self) != thread_to_msgstack_.end()) {
        // already stack is constructed
        thread_to_msgstack_[self].push_back(lm->second);
        CHECK(thread_to_msgstack_[self].size() < 2);
      } else {
        // otherwise, make a new stack
        std::vector<MessageDetail*> vec;
        vec.push_back(last_message);
        thread_to_msgstack_[self] = vec;
      }
      return last_message;
    }
    static void cb_dispatchMessage_exit() {
      Thread *self = Thread::Current();
      MutexLock mu(self, *lock);
      thread_to_msgstack_[self].pop_back();
    }

    static void cb_Message_recycleUnchecked(mirror::Object *message) {
      Thread *self = Thread::Current();
      MutexLock mu(self, *lock);
      auto lm = last_messages_.find(message);
      if (lm != last_messages_.end()) {
        if (lm->second) {
          MessageDetail *detail = lm->second;
          detail->recycled_ = true;  // make true to delete later on FlushOut
        }
        lm->second = NULL;
      } else {
        // The message may be enqueued with MessageQueue.enqueueSyncBarrier
        // LOG(INFO) << << "Recycling message have been never seen??" << MessageDetail::DumpAll(false);
      }
    }

    MessageDetail(mirror::Object *message, int dispatch_timediff_millis, Thread *self):
        message_(message), id_(cur_id_),
        dispatch_timediff_millis_(dispatch_timediff_millis),
        recycled_(false) {
      info_.assign(message_toString(message, dispatch_timediff_millis));
      MessageCauseFinder visitor(self, &cause_);
      visitor.WalkStack(true);
      cause_unknown_ = visitor.unknown_;
    }

    MessageDetail(mirror::Object *message, int dispatch_timediff_millis, MessageDetail *cause_object):
        message_(message), id_(cur_id_),
        dispatch_timediff_millis_(dispatch_timediff_millis),
        recycled_(false), cause_(StringPrintf("[Message id %d]", cause_object->id_)),
        cause_unknown_(false) {
      info_.assign(message_toString(message, dispatch_timediff_millis));
    }

    virtual ~MessageDetail() {};

    static bool HasNoMoreMessage() {
      MutexLock mu(Thread::Current(), *lock);
      for (auto const& it : last_messages_) {
        MessageDetail *detail = it.second;
        if (detail != NULL && !detail->IsQueuedLater()) {
          return false;
        }
      }
      return true;
    }

    static bool HasNoMoreMessageThenFlushOut() {
      MutexLock mu(Thread::Current(), *lock);
      for (auto const& it : last_messages_) {
        MessageDetail *detail = it.second;
        if (detail != NULL && !detail->IsQueuedLater()) {
          return false;
        }
      }
      /* Print threads to Message Stack */
      // int cnt = 0;
      // for (auto it = thread_to_msgstack_.begin(); it != thread_to_msgstack_.end(); it++) {
      //   if (!(it->second).empty()) {
      //     LOG(INFO) << "Thread not empty: " << it->first;
      //     for (auto it2 = it->second.begin(); it2 != it->second.end(); it2++) {
      //       MessageDetail *detail = *it2;
      //       LOG(INFO) << detail->Dump();
      //       cnt++;
      //     }
      //   }
      // }
      // CHECK(cnt == 0);

      /* Flush out */
      for (auto iter = messages_.begin(); iter != messages_.end();) {
        MessageDetail *detail = (*iter);
        if (detail->IsQueuedLater() && detail->recycled_ == false) {
          ++iter;
        } else {
          delete detail;
          messages_.erase(iter);
        }
      }
      return true;
    }

    static std::string DumpAll(bool use_lock) {
      std::string ret;
      if (use_lock) {
        MutexLock mu(Thread::Current(), *lock);
        for (auto it = messages_.begin(); it < messages_.end(); it++) {
          MessageDetail *detail = (*it);
          ret.append(StringPrintf("%p %s\n", detail, detail->Dump().c_str()));
        }
      } else {
        for (auto it = messages_.begin(); it < messages_.end(); it++) {
          MessageDetail *detail = (*it);
          ret.append(StringPrintf("%p %s\n", detail, detail->Dump().c_str()));
        }
      }
      return ret;
    }

    bool IsQueuedLater() {
      return dispatch_timediff_millis_ > 10;
    }

    std::string Dump() const {
      return StringPrintf("[id %d] %p %s /r %s",
        id_, message_, info_.c_str(), cause_.c_str());
    }

    static Mutex *lock;

   private:
    struct MethodStackVisitor : public StackVisitor {
      explicit MethodStackVisitor(Thread* thread)
          : StackVisitor(thread, NULL), tid(thread->GetTid()) {
        thread->GetThreadName(tname);
      }

      bool VisitFrame() OVERRIDE SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
        LOG(INFO) << "["<< tname << "(" << tid << ")] "
            "St#" << GetFrameId() << " " << DescribeLocation();
        return true;
      }
      pid_t tid;
      std::string tname;
    };
    struct MessageCauseFinder : public StackVisitor {
      explicit MessageCauseFinder(Thread* thread, std::string *cause_ptr)
          : StackVisitor(thread, NULL), tid_(thread->GetTid()), cause_p(cause_ptr),
            unknown_(true), last_method_(NULL), last_shadow_frame_(NULL) {
        thread->GetThreadName(tname_);
        cause_ptr->assign(StringPrintf("[Thread %s(%d)]", tname_.c_str(), tid_));
      }

      bool VisitFrame() OVERRIDE SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
        mirror::ArtMethod *method = GetMethod();
        if (method == NULL)
          return true;
        if (method == method_Binder_execTransact_) {
          JNIEnvExt *env = Thread::Current()->GetJniEnv();
          mirror::Object *binder_obj = GetThisObject();
          ScopedObjectAccessUnchecked soa(env);
          {
            jstring jstr_descriptor = soa.AddLocalReference<jstring>(
                field_Binder_mDescriptor_->GetObject(binder_obj));
            const char *descriptor = env->GetStringUTFChars(jstr_descriptor, 0);
            cause_p->assign(StringPrintf("[Thread %s(%d) - execTransact(%s)",
                tname_.c_str(), tid_, descriptor));
            env->ReleaseStringUTFChars(jstr_descriptor, descriptor);
            env->DeleteLocalRef(jstr_descriptor);
            RecordArgumentValues();
            cause_p->append("]");
            unknown_ = false;
          }
          return false;
        } else if (method == method_InputEventReceiver_dispatchInputEvent_) {
          cause_p->assign(StringPrintf("[Thread %s(%d) - dispatchInputEvent",
              tname_.c_str(), tid_));
          RecordArgumentValues();
          cause_p->append("]");
          unknown_ = false;
          return false;
        } else if (method == method_msgq_nativePollOnce_) {
          cause_p->assign(StringPrintf("[Thread %s(%d) - nativePollOnce/%s",
              tname_.c_str(), tid_, last_method_->GetName()));
          StringAppendArgumentValues(cause_p, last_method_, last_shadow_frame_);
          cause_p->append("]");
          unknown_ = false;
          return false;
        }
        // For nativePollOnce, store the last method
        if (LIKELY(method->GetInterfaceMethodIfProxy()->GetDexMethodIndex() != DexFile::kDexNoIndex)) {
          last_method_ = method;
          last_shadow_frame_ = GetCurrentShadowFrame();
        }
        return true;
      }

      void RecordArgumentValues()
          SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
        StringAppendArgumentValues(cause_p, GetMethod(), GetCurrentShadowFrame());
      }

      pid_t tid_;
      std::string tname_;
      std::string *cause_p;  // output value for VisitFrame
      bool unknown_;

      /* For nativePollOnce-caused messages */
      mirror::ArtMethod *last_method_;
      ShadowFrame *last_shadow_frame_;
    };
    static std::string message_toString(mirror::Object *message, int timediff_ms)
        SHARED_LOCKS_REQUIRED(Locks::mutator_lock_) {
      Thread *thread = Thread::Current();
      JNIEnvExt *env = thread->GetJniEnv();
      std::string ret;
      MiniTraceThreadFlag orig_flag = thread->GetMiniTraceFlag();
      thread->SetMiniTraceFlag(kMiniTraceExclude);
      ScopedObjectAccessUnchecked soa(thread);
      {
        ScopedLocalRef<jobject> jmessage(env, env->NewLocalRef(message));
        ScopedLocalRef<jobject> message_string(env,
            env->CallObjectMethod(jmessage.get(), soa.EncodeMethod(method_Message_toString_)));
        const char* message_cstring = env->GetStringUTFChars((jstring) message_string.get(), 0);
        ret.assign(message_cstring);
        env->ReleaseStringUTFChars((jstring) message_string.get(), message_cstring);
      }
      thread->SetMiniTraceFlag(orig_flag);

      // remove "when" part
      // IN  "{ when=-14s685ms callback=... }"
      //        ^^^^^^^^^^^^^^
      // OUT "{ callback=... }"
      size_t found = ret.find(' ', 2);
      ret.erase(2, found - 1);

      // Append timediff information
      if (timediff_ms > 10)
        StringAppendF(&ret, " (queued %dms)", timediff_ms);
      return ret;
    }
    static std::vector<MessageDetail *> messages_;
    static int cur_id_;
    static std::map<mirror::Object *, MessageDetail *> last_messages_;
    static std::map<Thread *, std::vector<MessageDetail *>> thread_to_msgstack_;
    mirror::Object *message_;
    int id_;
    std::string info_;
    int dispatch_timediff_millis_;
    bool recycled_;

    /* Messages are defined from dispatchMessage or just thread */
    std::string cause_;
    bool cause_unknown_;
  };

 private:
  explicit MiniTrace(int socket_fd, const char *prefix, uint32_t log_flag,
                     uint32_t listener_flag, uint32_t buffer_size,
                     int ape_socket_fd, uint64_t start_timestamp,
                     std::map<mirror::ArtMethod*, std::pair<int, int>> *mtd_targets,
                     std::vector<lazy_target> *lazy_targets);

  void LogMethodTraceEvent(Thread* thread, mirror::ArtMethod* method, uint32_t dex_pc,
                           instrumentation::Instrumentation::InstrumentationEvent event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogFieldTraceEvent(Thread* thread, mirror::Object* this_object, mirror::ArtField* field,
                           uint32_t dex_pc, bool read_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogMonitorTraceEvent(Thread* thread, mirror::Object* lock_object, uint32_t dex_pc,
                           bool enter_event)
      SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void LogMessage(Thread* thread, MessageDetail *message) SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);

  void DumpMethod(std::string &buffer);
  void DumpField(std::string &buffer);
  void DumpThread(std::string &buffer);

  void LogNewMethod(mirror::ArtMethod *method);
  uint16_t LogNewField(mirror::ArtField *field);
  void LogNewThread(Thread *thread);

  void ReadBuffer(char *dest, size_t offset, size_t len);
  void WriteRingBuffer(ringbuf_worker_t *worker, const char *src, size_t len);

  void ForwardMessageStatus(MessageStatusTransition transition);

  static void new_android_os_MessageQueue_nativePollOnce(JNIEnv* env, jclass clazz,
        jlong ptr, jint timeoutMillis);
  static void *nativePollOnce_originalEntry;
  // static void (MiniTrace::*nativePollOnceEntry)(JNIEnv*, jclass, jlong, jint);

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

  // Similar to log_flag, used for removelistener
  const uint32_t listener_flag_;

  // Log execution data
  bool do_coverage_;

  const uint32_t buffer_size_;

  // Time trace was created.
  const uint64_t start_timestamp_;

  // To sync on exception synchronization
  volatile int consumer_cycle_cnt_;

  // save execution data
  volatile bool save_execution_data_;

  // Method Execution Data
  std::map<mirror::ArtMethod*, char*> execution_data_;

  Mutex *traced_method_lock_;
  Mutex *traced_field_lock_;
  Mutex *traced_thread_lock_;
  Mutex *traced_execution_lock_;

  /* Used for logging messages / idlecheck task */
  Thread *main_thread_;
  MessageStatus message_status_;
  Mutex *message_status_lock_;

  /* Used for logging messages */
  static mirror::ArtMethod *method_msgq_next_;
  static mirror::ArtMethod *method_msgq_enqueueMessage_;
  static mirror::ArtMethod *method_msgq_nativePollOnce_;
  static mirror::ArtMethod *method_Looper_loop_;
  static mirror::ArtMethod *method_Message_recycleUnchecked_;
  static mirror::ArtMethod *method_Message_toString_;
  static mirror::ArtMethod *method_Binder_execTransact_;
  static mirror::ArtField *field_Binder_mDescriptor_;
  static mirror::ArtMethod *method_BinderProxy_transact_;
  static mirror::ArtMethod *method_BinderProxy_getInterfaceDescriptor_;
  static mirror::ArtMethod *method_InputEventReceiver_dispatchInputEvent_;
  static mirror::ArtMethod *method_InputEventReceiver_finishInputEvent_;

  /* uses enqueueMessage and logging messages */
  mirror::Object *main_msgq_;

  /* Used for communicate with ape */
  int ape_socket_fd_;
  Mutex *ape_lock_;
  mirror::Object *m_idler_;

  // Push simple log for every 1 second
  pthread_t pinging_thread_;

  // method targeting
  std::map<mirror::ArtMethod*, std::pair<int, int>> *mtd_targets_;

  // class, methodname, signature, flag
  std::vector<lazy_target> *lazy_targets_;

  DISALLOW_COPY_AND_ASSIGN(MiniTrace);
};

}  // namespace art

#endif  // ART_RUNTIME_MINI_TRACE_H_
