// Headers/constants ONLY. No C or C++ runtime object is linked into the driver.
#include <ntifs.h>
// WFP networking headers require the NDIS6 surface (official WDK types).
#ifndef NDIS630
#define NDIS630 1
#endif
#include <ndis.h>
#include <fwpsk.h>
#include <wdmsec.h>
#include <stddef.h>
enum {
 FB_IRP_BUFFER = offsetof(IRP, AssociatedIrp.SystemBuffer),
 FB_IRP_STACK = offsetof(IRP, Tail.Overlay.CurrentStackLocation),
 FB_IRP_STATUS = offsetof(IRP, IoStatus.Status),
 FB_IRP_INFORMATION = offsetof(IRP, IoStatus.Information),
 FB_STACK_CODE = offsetof(IO_STACK_LOCATION, Parameters.DeviceIoControl.IoControlCode),
 FB_STACK_OUTPUT = offsetof(IO_STACK_LOCATION, Parameters.DeviceIoControl.OutputBufferLength),
 FB_STACK_MAJOR = offsetof(IO_STACK_LOCATION, MajorFunction),
 FB_CREATE_FLAGS = sizeof(SIZE_T),
 FB_VALUE_TYPE = offsetof(FWPS_INCOMING_VALUE0, value.type),
 FB_VALUE_U8 = offsetof(FWPS_INCOMING_VALUE0, value.uint8),
 FB_VALUE_BLOB = offsetof(FWPS_INCOMING_VALUE0, value.byteBlob),
 FB_WITNESS_IOCTL = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_READ_DATA)
};
