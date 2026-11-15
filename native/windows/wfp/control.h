#ifndef FLOWBRIDGE_WFP_CONTROL_H
#define FLOWBRIDGE_WFP_CONTROL_H
#include "wire_types.h"
#include "redirect_context.h"
/* Include ntddk.h or Windows.h/winioctl.h first. Access is restricted to
 * SYSTEM/admin and bound to the exclusive owner's OS-authenticated process. */
#define FB_WFP_DEVICE L"\\\\.\\FlowBridgeWfp"
#define FB_WFP_ABI 3u
#define FB_IOCTL_CONFIGURE CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FB_IOCTL_DISABLE CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FB_IOCTL_QUERY CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_READ_DATA)
#define FB_IOCTL_CLAIM CTL_CODE(FILE_DEVICE_NETWORK, 0x804, METHOD_BUFFERED, FILE_WRITE_DATA)
typedef struct FbWfpConfig {
    FbUint32 size;
    FbUint32 version;
    FbUint16 port_v4_be;
    FbUint16 port_v6_be;
    FbUint32 reserved;
} FbWfpConfig;
typedef struct FbWfpStatus {
    FbUint32 size;
    FbUint32 version;
    FbUint32 enabled;
    FbUint32 service_pid;
} FbWfpStatus;
/* Exact v3 redirect context returned from OS WSAIoctl on an accepted socket.
 * Only the original elevated helper's exclusive driver handle may request
 * a terminal AUTH receipt; the kernel checks all origin and endpoint fields.
 * This is a bounded user-to-kernel claim, NOT independent socket attestation.
 */
typedef struct FbWfpClaim {
    FbUint32 size;
    FbUint32 version;
    FbRedirectContext context;
} FbWfpClaim;
static const GUID FB_WFP_PROVIDER = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x01}};
static const GUID FB_WFP_SUBLAYER = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x02}};
static const GUID FB_WFP_CALLOUT4 = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x04}};
static const GUID FB_WFP_CALLOUT6 = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x06}};
static const GUID FB_WFP_AUTH_CALLOUT4 = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x08}};
static const GUID FB_WFP_AUTH_CALLOUT6 = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x09}};
static const GUID FB_WFP_DEVICE_CLASS = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x10}};
#endif
