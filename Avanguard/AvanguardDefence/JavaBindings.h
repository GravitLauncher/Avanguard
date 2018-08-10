#pragma once

#include "AvnDefinitions.h"

#ifdef JAVA_BINDINGS

#include "jni.h"
#include "ThreatElimination.h"
#include "ThreatTypes.h"

JNIEXPORT 
jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved);

BOOL IsJavaBinded();
AVN_ET_ACTION CallJavaNotifier(AVN_THREAT Threat);

#endif