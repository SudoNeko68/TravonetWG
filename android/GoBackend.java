/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 TravonetWG Contributors.
 */

package org.travonet.backend;

public final class GoBackend {
    static {
        try {
            System.loadLibrary("travonet-wg");
        } catch (UnsatisfiedLinkError e) {
            System.loadLibrary("wg-go");
        }
    }

    private GoBackend() {}

    // VpnService protection bridge (call wgSetVpnService or use wgTurnOnProtected
    // so that UDP sockets are protected before the first handshake is sent).
    public static native void wgSetVpnService(Object vpnService);
    public static native int wgTurnOnProtected(String ifname, int tunFd, String settings, Object vpnService);
    public static native void wgNotifySocketProtected(int handle);

    // WireGuard VPN methods (VpnService TUN mode)
    public static native int wgTurnOn(String ifname, int tunFd, String settings);
    public static native void wgTurnOff(int handle);
    public static native int wgGetSocketV4(int handle);
    public static native int wgGetSocketV6(int handle);
    public static native String wgGetConfig(int handle);
    public static native String wgVersion();

    // SOCKS5 in-memory proxy methods (Pure Userspace mode without VpnService / root)
    public static native int wgStartSocks5(String listenAddr, String settings);
    public static native void wgStopSocks5(int handle);
    public static native int wgGetSocks5SocketV4(int handle);
    public static native int wgGetSocks5SocketV6(int handle);
}
