#pragma once
/* WDK headers intentionally use anonymous unions. Keep the diagnostic change
 * scoped to system headers; FlowBridge code is still compiled with /W4 /WX.
 * This matches the header boundary used by Microsoft's WFPSampler. */
#pragma warning(push)
#pragma warning(disable:4201)
#include <ntddk.h>
#include <wdmsec.h>
#include <ndis.h>
#include <fwpsk.h>
#include <ws2ipdef.h>
#pragma warning(pop)
