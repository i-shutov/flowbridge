#pragma once
/* WDK headers intentionally use anonymous unions and aligned structures.
 * Scope their diagnostics exactly as Microsoft's WFPSampler does. */
#pragma warning(push)
#pragma warning(disable:4201 4324)
#include <ntifs.h>
#include <wdmsec.h>
#include <ndis.h>
#include <fwpsk.h>
#include <ws2ipdef.h>
#pragma warning(pop)
