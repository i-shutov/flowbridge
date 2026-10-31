#ifndef FLOWBRIDGE_WIRE_TYPES_H
#define FLOWBRIDGE_WIRE_TYPES_H
/* Fixed-width Windows ABI types without importing the user-mode CRT into WDK.
 * Sizes and layout are asserted by both the native reader and kernel producer. */
typedef unsigned char FbUint8;
typedef unsigned short FbUint16;
typedef unsigned int FbUint32;
typedef unsigned long long FbUint64;
#ifdef __cplusplus
static_assert(sizeof(FbUint8) == 1 && sizeof(FbUint16) == 2 && sizeof(FbUint32) == 4 && sizeof(FbUint64) == 8, "Wire integer ABI drift");
#endif
#endif
