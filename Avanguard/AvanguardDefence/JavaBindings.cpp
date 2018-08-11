#include "stdafx.h"

#include "AvnDefinitions.h"

#ifdef JAVA_BINDINGS

#pragma comment(lib, "jvm.lib")

#include "HWIDsUtils.h"
#include "ThreatTypes.h"
#include "ThreatElimination.h"
#include "t1ha.h"

#include "JavaBindings.h"

static BOOL _IsJavaBinded = FALSE;

extern BOOL AvnStartDefence();
extern VOID AvnStopDefence();
extern BOOL IsAvnStarted;
extern BOOL IsAvnStaticLoaded;

static JavaVM* _vm = NULL;
static JNIEnv* _env = NULL;
static jclass _klass = NULL;
static jmethodID _notifier = NULL;

jboolean JNICALL avnStartDefence(JNIEnv* env, jclass klass) {
    return (jboolean)AvnStartDefence();
}

void JNICALL avnStopDefence(JNIEnv* env, jclass klass) {
    AvnStopDefence();
}

jboolean JNICALL avnIsStarted(JNIEnv* env, jclass klass) {
    return (jboolean)IsAvnStarted;
}

jboolean JNICALL avnIsStaticLoaded(JNIEnv* env, jclass klass) {
    return (jboolean)IsAvnStaticLoaded;
}

void JNICALL avnEliminateThreat(JNIEnv* env, jclass klass, jint threat) {
    EliminateThreat((AVN_THREAT)threat, NULL, etTerminate);
}

jlong JNICALL avnGetCpuid(JNIEnv* env, jclass klass) {
    return (jlong)HWIDs::GetCpuid();
}

jlong JNICALL avnGetSmbiosId(JNIEnv* env, jclass klass) {
    return (jlong)HWIDs::GetSmbiosId();
}

jlong JNICALL avnGetMacId(JNIEnv* env, jclass klass) {
    return (jlong)HWIDs::GetMacId();
}

jlong JNICALL avnGetHddId(JNIEnv* env, jclass klass) {
    return (jlong)HWIDs::GetHddId();
}

jlong JNICALL avnGetHash(JNIEnv* env, jclass klass, jbyteArray data) {
    jsize length = env->GetArrayLength(data);
    jbyte* buffer = (jbyte*)new jbyte[length];
    env->GetByteArrayRegion(data, 0, length, buffer);
    jlong hash = (jlong)t1ha(buffer, length, 0x1EE7C0DEC0FFEE);
    delete[] buffer;
    return hash;
}

void JNICALL avnRegisterNotifier(JNIEnv* env, jclass klass, jobject callback) {
    if (callback == NULL) {
        _klass = NULL;
        _notifier = NULL;
        return;
    }
    _klass = env->GetObjectClass(callback);
    _notifier = env->GetMethodID(_klass, "call", "(I)Z");
}

#ifdef TIMERED_CHECKINGS
void JNICALL setCheckTime(JNIEnv* env, jclass klass, jint timeCheck) {
    setTstTime((int)timeCheck);
}

jint JNICALL getCheckTime(JNIEnv* env, jclass klass) {
    return (jint)getTstTime();
}
#endif

jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    jint status;

    status = vm->GetEnv((void**)&env, JNI_VERSION_1_8);
    if (status != JNI_OK)
        if (status == JNI_EDETACHED) 
            status = vm->AttachCurrentThread((void**)&env, NULL);
        else
            return JNI_ERR;

    if (status != JNI_OK) return JNI_ERR;

    jclass binding = env->FindClass("ru/zaxar163/GuardBind");
    const JNINativeMethod methods[] = {
        { "avnStartDefence"     , "()Z"     , (void*)avnStartDefence },
        { "avnStopDefence"      , "()V"     , (void*)avnStopDefence },
        { "avnIsStarted"        , "()Z"     , (void*)avnIsStarted },
        { "avnIsStaticLoaded"   , "()Z"     , (void*)avnIsStaticLoaded },
        { "avnEliminateThreat"  , "(I)V"    , (void*)avnEliminateThreat },
        { "avnGetCpuid"         , "()J"     , (void*)avnGetCpuid },
        { "avnGetSmbiosId"      , "()J"     , (void*)avnGetSmbiosId },
        { "avnGetMacId"         , "()J"     , (void*)avnGetMacId },
        { "avnGetHddId"         , "()J"     , (void*)avnGetHddId },
        { "avnGetHash"          , "([B)J"   , (void*)avnGetHash },
#ifdef TIMERED_CHECKINGS
        { "setCheckTime"          , "(I)V"   , (void*)setCheckTime },
        { "getCheckTime"          , "()I"   , (void*)getCheckTime },
#endif
        { "avnRegisterThreatNotifier", "(Lru/zaxar163/GuardBind$ThreatNotifier;)V", (void*)avnRegisterNotifier }
    };
    
    status = env->RegisterNatives(binding, methods, sizeof(methods) / sizeof(methods[0]));
    if (status != JNI_OK) return JNI_ERR;

    _vm = vm;
    _env = env;
    _IsJavaBinded = TRUE;
    return JNI_VERSION_1_8;
}

BOOL IsJavaBinded() {
    return _IsJavaBinded;
}

AVN_ET_ACTION CallJavaNotifier(AVN_THREAT Threat) {
    if (_vm == NULL || _env == NULL || _klass == NULL || _notifier == NULL) return etNotSpecified;

    jint status = _vm->AttachCurrentThread((void**)&_env, NULL);
    if (status != JNI_OK) return etNotSpecified;

    return _env->CallBooleanMethod(_klass, _notifier, (int)Threat)
        ? etContinue
        : etTerminate;
}

#endif