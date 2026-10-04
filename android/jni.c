/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

#include <jni.h>
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

/* Helper static functions */

static jint do_wgTurnOn(JNIEnv *env, jstring ifname, jint tun_fd, jstring settings)
{
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

/* =========================================================================
 * 1. com.wireguard.android.backend.GoBackend (WireGuard Android drop-in)
 * ========================================================================= */

JNIEXPORT jint JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
    return do_wgTurnOn(env, ifname, tun_fd, settings);
}

JNIEXPORT void JNICALL Java_com_wireguard_android_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
    do_wgTurnOff(handle);
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

JNIEXPORT jint JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
    return do_wgTurnOn(env, ifname, tun_fd, settings);
}

JNIEXPORT void JNICALL Java_org_amnezia_vpn_protocol_amneziawg_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
    do_wgTurnOff(handle);
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

/* =========================================================================
 * 3. org.travonet.backend.GoBackend (TravonetWG Native Android Package)
 * ========================================================================= */

JNIEXPORT jint JNICALL Java_org_travonet_backend_GoBackend_wgTurnOn(JNIEnv *env, jclass c, jstring ifname, jint tun_fd, jstring settings)
{
    return do_wgTurnOn(env, ifname, tun_fd, settings);
}

JNIEXPORT void JNICALL Java_org_travonet_backend_GoBackend_wgTurnOff(JNIEnv *env, jclass c, jint handle)
{
    do_wgTurnOff(handle);
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
