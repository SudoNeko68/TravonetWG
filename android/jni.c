/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

#include <jni.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct go_string {
    const char *str;
    long n;
};

extern int wgTurnOn(struct go_string ifname, int tun_fd, struct go_string settings);
extern void wgTurnOff(int handle);
extern int wgGetSocketV4(int handle);
extern int wgGetSocketV6(int handle);
extern char *wgGetConfig(int handle);
extern char *wgVersion();

extern int wgStartSocks5(struct go_string listen_addr, struct go_string settings);
extern void wgStopSocks5(int handle);
extern int wgGetSocks5SocketV4(int handle);
extern int wgGetSocks5SocketV6(int handle);
extern void wgNotifySocketProtected(int handle);

/* =========================================================================
 * VpnService protection bridge
 * ========================================================================= */

static JavaVM *global_vm = NULL;
static jobject global_vpn_service = NULL;
static jmethodID global_protect_mid = NULL;
static pthread_mutex_t vpn_mutex = PTHREAD_MUTEX_INITIALIZER;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    (void)reserved;
    global_vm = vm;
    return JNI_VERSION_1_6;
}

/*
 * c_set_vpn_service stores a global reference to the embedding VpnService and
 * caches its boolean protect(int) method. Passing NULL clears the reference.
 */
void c_set_vpn_service(JNIEnv *env, jobject vpn_service)
{
    if (env == NULL)
        return;

    jmethodID mid = NULL;
    jobject new_ref = NULL;

    if (vpn_service != NULL) {
        jclass cls = (*env)->GetObjectClass(env, vpn_service);
        if (cls == NULL) {
            (*env)->ExceptionClear(env);
            return;
        }
        mid = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
        (*env)->DeleteLocalRef(env, cls);
        if (mid == NULL) {
            (*env)->ExceptionClear(env);
            return;
        }
        new_ref = (*env)->NewGlobalRef(env, vpn_service);
        if (new_ref == NULL) {
            (*env)->ExceptionClear(env);
            return;
        }
    }

    pthread_mutex_lock(&vpn_mutex);
    if (global_vpn_service != NULL)
        (*env)->DeleteGlobalRef(env, global_vpn_service);
    global_vpn_service = new_ref;
    global_protect_mid = mid;
    pthread_mutex_unlock(&vpn_mutex);
}

int c_has_vpn_service(void)
{
    pthread_mutex_lock(&vpn_mutex);
    int present = global_vpn_service != NULL && global_protect_mid != NULL;
    pthread_mutex_unlock(&vpn_mutex);
    return present ? 1 : 0;
}

/*
 * c_protect_socket calls VpnService.protect(fd) synchronously. It attaches the
 * calling native thread to the JVM when needed. Returns 0 on success (also when
 * no VpnService is registered), -1 on error.
 */
int c_protect_socket(int fd)
{
    if (fd < 0)
        return -1;

    pthread_mutex_lock(&vpn_mutex);
    JavaVM *vm = global_vm;
    jobject service = global_vpn_service;
    jmethodID mid = global_protect_mid;
    pthread_mutex_unlock(&vpn_mutex);

    if (vm == NULL || service == NULL || mid == NULL)
        return 0;

    JNIEnv *env = NULL;
    int detach = 0;
    jint get_env_result = (*vm)->GetEnv(vm, (void **)&env, JNI_VERSION_1_6);
    if (get_env_result == JNI_EDETACHED) {
        if ((*vm)->AttachCurrentThread(vm, &env, NULL) != JNI_OK)
            return -1;
        detach = 1;
    } else if (get_env_result != JNI_OK || env == NULL) {
        return -1;
    }

    jboolean result = (*env)->CallBooleanMethod(env, service, mid, (jint)fd);
    int ret = 0;
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        ret = -1;
    } else if (result != JNI_TRUE) {
        ret = -1;
    }

    if (detach)
        (*vm)->DetachCurrentThread(vm);

    return ret;
}

/* Helper static functions */

static jint do_wgTurnOn(JNIEnv *env, jstring ifname, jint tun_fd, jstring settings)
{
    if (!ifname || !settings)
        return -1;

    const char *ifname_str = (*env)->GetStringUTFChars(env, ifname, 0);
    size_t ifname_len = (*env)->GetStringUTFLength(env, ifname);
    const char *settings_str = (*env)->GetStringUTFChars(env, settings, 0);
    size_t settings_len = (*env)->GetStringUTFLength(env, settings);

    int ret = wgTurnOn((struct go_string){
        .str = ifname_str,
        .n = (long)ifname_len
    }, tun_fd, (struct go_string){
        .str = settings_str,
        .n = (long)settings_len
    });

    (*env)->ReleaseStringUTFChars(env, ifname, ifname_str);
    (*env)->ReleaseStringUTFChars(env, settings, settings_str);
    return ret;
}

static jint do_wgTurnOnProtected(JNIEnv *env, jstring ifname, jint tun_fd, jstring settings, jobject vpn_service)
{
    c_set_vpn_service(env, vpn_service);
    return do_wgTurnOn(env, ifname, tun_fd, settings);
}

static void do_wgTurnOff(jint handle)
{
    wgTurnOff(handle);
}

static jint do_wgGetSocketV4(jint handle)
{
    return wgGetSocketV4(handle);
}

static jint do_wgGetSocketV6(jint handle)
{
    return wgGetSocketV6(handle);
}

static jstring do_wgGetConfig(JNIEnv *env, jint handle)
{
    char *config = wgGetConfig(handle);
    if (!config)
        return NULL;
    jstring ret = (*env)->NewStringUTF(env, config);
    free(config);
    return ret;
}

static jstring do_wgVersion(JNIEnv *env)
{
    char *version = wgVersion();
    if (!version)
        return NULL;
    jstring ret = (*env)->NewStringUTF(env, version);
    free(version);
    return ret;
}

static jint do_wgStartSocks5(JNIEnv *env, jstring listen_addr, jstring settings)
{
    if (!settings)
        return -1;

    const char *addr_str = listen_addr ? (*env)->GetStringUTFChars(env, listen_addr, 0) : "";
    size_t addr_len = listen_addr ? (*env)->GetStringUTFLength(env, listen_addr) : 0;
    const char *settings_str = settings ? (*env)->GetStringUTFChars(env, settings, 0) : "";
    size_t settings_len = settings ? (*env)->GetStringUTFLength(env, settings) : 0;

    int ret = wgStartSocks5((struct go_string){
        .str = addr_str,
        .n = (long)addr_len
    }, (struct go_string){
        .str = settings_str,
        .n = (long)settings_len
    });

    if (listen_addr)
        (*env)->ReleaseStringUTFChars(env, listen_addr, addr_str);
    if (settings)
        (*env)->ReleaseStringUTFChars(env, settings, settings_str);
    return ret;
}

static void do_wgStopSocks5(jint handle)
{
    wgStopSocks5(handle);
}

static jint do_wgGetSocks5SocketV4(jint handle)
{
    return wgGetSocks5SocketV4(handle);
}

static jint do_wgGetSocks5SocketV6(jint handle)
{
    return wgGetSocks5SocketV6(handle);
}

static void do_wgSetVpnService(JNIEnv *env, jobject vpn_service)
{
    c_set_vpn_service(env, vpn_service);
}

static void do_wgNotifySocketProtected(jint handle)
{
    wgNotifySocketProtected(handle);
}

/* =========================================================================
 * 1. com.wireguard.android.backend.GoBackend (WireGuard Android drop-in)
 * ========================================================================= */

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgSetVpnService(JNIEnv *env, jclass c, jobject vpn_service)
{
    do_wgSetVpnService(env, vpn_service);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
    return do_wgTurnOn(env, ifname, tun_fd, settings);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOnProtected(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings, jobject vpn_service)
{
    return do_wgTurnOnProtected(env, ifname, tun_fd, settings, vpn_service);
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
    do_wgTurnOff(handle);
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgNotifySocketProtected(JNIEnv *env, jclass c, jint handle)
{
    do_wgNotifySocketProtected(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetConfig(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetConfig(env, handle);
}

JNIEXPORT jstring JNICALL Java_com_wireguard_android_backend_GoBackend_wgVersion(JNIEnv *env, jclass c)
{
    return do_wgVersion(env);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgStartSocks5(JNIEnv *env, jclass c, jstring listen_addr, jstring settings)
{
    return do_wgStartSocks5(env, listen_addr, settings);
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgStopSocks5(JNIEnv *env, jclass c, jint handle)
{
    do_wgStopSocks5(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocks5SocketV4(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocks5SocketV4(handle);
}

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgGetSocks5SocketV6(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocks5SocketV6(handle);
}

/* =========================================================================
 * 2. org.amnezia.vpn.protocol.amneziawg.GoBackend (AmneziaWG drop-in)
 * ========================================================================= */

JNIEXPORT void JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgSetVpnService(JNIEnv *env, jclass c, jobject vpn_service)
{
    do_wgSetVpnService(env, vpn_service);
}

JNIEXPORT jint JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
    return do_wgTurnOn(env, ifname, tun_fd, settings);
}

JNIEXPORT jint JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgTurnOnProtected(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings, jobject vpn_service)
{
    return do_wgTurnOnProtected(env, ifname, tun_fd, settings, vpn_service);
}

JNIEXPORT void JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
    do_wgTurnOff(handle);
}

JNIEXPORT void JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgNotifySocketProtected(JNIEnv *env, jclass c, jint handle)
{
    do_wgNotifySocketProtected(handle);
}

JNIEXPORT jint JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgGetConfig(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetConfig(env, handle);
}

JNIEXPORT jstring JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgVersion(JNIEnv *env, jclass c)
{
    return do_wgVersion(env);
}

JNIEXPORT jint JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgStartSocks5(JNIEnv *env, jclass c, jstring listen_addr, jstring settings)
{
    return do_wgStartSocks5(env, listen_addr, settings);
}

JNIEXPORT void JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgStopSocks5(JNIEnv *env, jclass c, jint handle)
{
    do_wgStopSocks5(handle);
}

JNIEXPORT jint JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgGetSocks5SocketV4(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocks5SocketV4(handle);
}

JNIEXPORT jint JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgGetSocks5SocketV6(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocks5SocketV6(handle);
}

/* =========================================================================
 * 3. org.travonet.backend.GoBackend (TravonetWG Native Android Package)
 * ========================================================================= */

JNIEXPORT void JNICALL Java_org_travonet_backend_GoBackend_wgSetVpnService(JNIEnv *env, jclass c, jobject vpn_service)
{
    do_wgSetVpnService(env, vpn_service);
}

JNIEXPORT jint JNICALL Java_org_travonet_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
    return do_wgTurnOn(env, ifname, tun_fd, settings);
}

JNIEXPORT jint JNICALL Java_org_travonet_backend_GoBackend_wgTurnOnProtected(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings, jobject vpn_service)
{
    return do_wgTurnOnProtected(env, ifname, tun_fd, settings, vpn_service);
}

JNIEXPORT void JNICALL Java_org_travonet_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
    do_wgTurnOff(handle);
}

JNIEXPORT void JNICALL Java_org_travonet_backend_GoBackend_wgNotifySocketProtected(JNIEnv *env, jclass c, jint handle)
{
    do_wgNotifySocketProtected(handle);
}

JNIEXPORT jint JNICALL Java_org_travonet_backend_GoBackend_wgGetSocketV4(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocketV4(handle);
}

JNIEXPORT jint JNICALL Java_org_travonet_backend_GoBackend_wgGetSocketV6(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocketV6(handle);
}

JNIEXPORT jstring JNICALL Java_org_travonet_backend_GoBackend_wgGetConfig(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetConfig(env, handle);
}

JNIEXPORT jstring JNICALL Java_org_travonet_backend_GoBackend_wgVersion(JNIEnv *env, jclass c)
{
    return do_wgVersion(env);
}

JNIEXPORT jint JNICALL Java_org_travonet_backend_GoBackend_wgStartSocks5(JNIEnv *env, jclass c, jstring listen_addr, jstring settings)
{
    return do_wgStartSocks5(env, listen_addr, settings);
}

JNIEXPORT void JNICALL Java_org_travonet_backend_GoBackend_wgStopSocks5(JNIEnv *env, jclass c, jint handle)
{
    do_wgStopSocks5(handle);
}

JNIEXPORT jint JNICALL Java_org_travonet_backend_GoBackend_wgGetSocks5SocketV4(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocks5SocketV4(handle);
}

JNIEXPORT jint JNICALL Java_org_travonet_backend_GoBackend_wgGetSocks5SocketV6(JNIEnv *env, jclass c, jint handle)
{
    return do_wgGetSocks5SocketV6(handle);
}
