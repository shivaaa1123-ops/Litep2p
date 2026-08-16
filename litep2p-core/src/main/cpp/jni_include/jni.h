/* JNI Headers - Minimal Implementation for Testing */
#ifndef _JNI_H_
#define _JNI_H_

#include <jni_md.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned char jboolean;
typedef signed char jbyte;
typedef unsigned short jchar;
typedef short jshort;
typedef long jint;
typedef long long jlong;
typedef float jfloat;
typedef double jdouble;
typedef jint jsize;

typedef void* jobject;
typedef jobject jclass;
typedef jobject jthrowable;
typedef jobject jstring;
typedef jobject jarray;
typedef jarray jobjectArray;
typedef jarray jbooleanArray;
typedef jarray jbyteArray;
typedef jarray jcharArray;
typedef jarray jshortArray;
typedef jarray jintArray;
typedef jarray jlongArray;
typedef jarray jfloatArray;
typedef jarray jdoubleArray;

typedef jobject jweak;

/* Primitive type arrays */

struct JNINativeInterface_;

typedef const struct JNINativeInterface_* JNIEnv;

typedef const struct JNIInvokeInterface_* JavaVM;

struct JNIEnv_ {
    const struct JNINativeInterface_* functions;
};

struct JNINativeInterface_ {
    void* reserved0;
    void* reserved1;
    void* reserved2;
    void* reserved3;
    /* ... rest of function pointers ... */
};

#ifdef __cplusplus
}
#endif

#endif /* _JNI_H_ */
