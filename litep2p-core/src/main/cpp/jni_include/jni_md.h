/* JNI Machine Dependent - Platform specific definitions */
#ifndef _JNI_MD_H_
#define _JNI_MD_H_

#ifdef __cplusplus
extern "C" {
#endif

#define JNIEXPORT
#define JNIIMPORT
#define JNICALL

typedef long jint;
typedef long long jlong;
typedef signed char jbyte;

#ifdef __cplusplus
}
#endif

#endif /* _JNI_MD_H_ */
