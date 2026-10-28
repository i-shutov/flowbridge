#ifndef FLOWBRIDGE_WFP_CONTROL_H
#define FLOWBRIDGE_WFP_CONTROL_H
#include <stdint.h>
/* Include ntddk.h or Windows.h/winioctl.h first. Device ACL restricts access to
 * SYSTEM/admin; exclusive owner handle and requestor PID bind configuration. */
#define FB_WFP_DEVICE L"\\\\.\\FlowBridgeWfp"
#define FB_WFP_ABI 2u
#define FB_IOCTL_CONFIGURE CTL_CODE(FILE_DEVICE_NETWORK, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FB_IOCTL_DISABLE CTL_CODE(FILE_DEVICE_NETWORK, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define FB_IOCTL_QUERY CTL_CODE(FILE_DEVICE_NETWORK, 0x803, METHOD_BUFFERED, FILE_READ_DATA)
typedef struct FbWfpConfig {
    uint32_t size;
    uint32_t version;
    uint16_t port_v4_be;
    uint16_t port_v6_be;
    uint32_t reserved;
} FbWfpConfig;
typedef struct FbWfpStatus {
    uint32_t size;
    uint32_t version;
    uint32_t enabled;
    uint32_t service_pid;
} FbWfpStatus;
/* Project-owned GUIDs; never used to enumerate/delete another provider. */
static const GUID FB_WFP_PROVIDER = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x01}};
static const GUID FB_WFP_SUBLAYER = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x02}};
static const GUID FB_WFP_CALLOUT4 = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x04}};
static const GUID FB_WFP_CALLOUT6 = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x06}};
static const GUID FB_WFP_DEVICE_CLASS = {0xb1d849a1,0x40a0,0x4f70,{0x9e,0x91,0xf7,0x32,0x55,0x19,0x20,0x10}};
#endif
