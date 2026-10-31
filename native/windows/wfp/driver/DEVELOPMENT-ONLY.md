# Development-only WFP package

This artifact is an unsigned kernel callout build, not an installable consumer release.
It is deliberately excluded from the ordinary FlowBridge desktop installer.

A successful build verifies compilation/linking and the packaging checks performed by
WDK. It does not verify load/unload, actual redirection, coexistence with firewalls/VPNs,
crash recovery, DNS behavior, or Driver Verifier results.

Do not disable Secure Boot or Windows code-integrity checks to use the desktop app.
Production delivery requires the publisher's Microsoft driver-signing process and
isolated VM validation before integration into an elevated, explicitly approved installer.
No driver or service is installed or activated by this CI workflow.

The toolchain is pinned to Microsoft WDK/SDK 10.0.28000.2526, acquired through NuGet.
Toolchain reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/install-the-wdk-using-nuget
