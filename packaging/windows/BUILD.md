# Windows GUI and installer

Build the Rust engine/CLI first. MSVC and MinGW import/static libraries are supported.
The C ABI header is `native/include/flowbridge.h`; nlohmann/json 3.11.3 is vendored
under `third_party/nlohmann` with its official MIT license. No package-manager step
is required for the GUI.

MSVC x64 (from the repository root, in an x64 developer prompt):

```powershell
cargo build --release -p flowbridge-ffi -p flowbridge-cli
cmake -S native/windows -B build/windows -A x64 -DFLOWBRIDGE_FFI_LIBRARY="$PWD/target/release/flowbridge_ffi.dll.lib"
cmake --build build/windows --config Release
```

Linux cross compilation, after installing MinGW-w64, CMake and NSIS:

```sh
cargo build --release --target x86_64-pc-windows-gnu -p flowbridge-ffi -p flowbridge-cli
cmake -S native/windows -B build/windows-gnu \
  -DCMAKE_SYSTEM_NAME=Windows -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++ \
  -DFLOWBRIDGE_FFI_LIBRARY="$PWD/target/x86_64-pc-windows-gnu/release/libflowbridge_ffi.dll.a"
cmake --build build/windows-gnu --parallel
```

For MinGW, the UI links its C++/GCC/thread runtime statically. The Rust import
library links against the separately staged `flowbridge_ffi.dll`. For MSVC a
static FFI `.lib` is also valid; the package definition still includes the engine
DLL so use the DLL import library for ordinary distribution. The WFP source target
is separate and is not linked into the GUI, installed or activated.

Stage a payload directory:

```text
payload/
  FlowBridge.exe                 # CMake GUI output
  flowbridge-cli.exe             # Rust CLI renamed: names are case insensitive on Windows!
  flowbridge_ffi.dll
  LICENSE                        # project license
  README.txt                     # packaging/windows/README.txt
  examples/ssh-socks.json
  examples/chain.json
  examples/direct.json
  licenses/nlohmann-json-LICENSE.MIT
  licenses/THIRD_PARTY_NOTICES.txt
  resources/presets.json
```

`THIRD_PARTY_NOTICES.txt` should include the Rust dependency/license inventory
produced for the release. Stage extra dependency notices inside that file rather
than using unspecified filenames (the uninstaller deliberately enumerates known
files). Do not include original commercial-product files or key generators.

Build the real installer (use `/D` on Windows NSIS, `-D` on Linux):

```sh
makensis -DPAYLOAD_DIR="$PWD/build/payload" \
  -DOUTPUT_FILE="$PWD/build/FlowBridge-0.2.0-windows-x64-setup.exe" \
  packaging/windows/FlowBridge.nsi
```

NSIS must include the `amd64-unicode` stubs and plugins; the script builds a native
64-bit Unicode installer. It uses English/Russian pages, installs per user, creates Start
menu shortcuts and an uninstaller, and retains `%LOCALAPPDATA%/FlowBridge` profile
data. No drivers, autostart, system proxy/DNS changes or engine activation are
performed. It refuses install/uninstall while the GUI's session mutex exists;
close CLI processes separately. It never recursively removes the installation
folder or profile folder. Upgrades reuse the registered installation directory,
including silent installs with a different `/D` argument, so an upgrade cannot
orphan an earlier installation by moving to another directory.

Before release, smoke-test on Windows x64: install as a standard user, start an
external SOCKS5 proxy, Start the UI, route a client via `127.0.0.1:1081`, inspect
connections/events, reload a rule, stop, restart, upgrade with the GUI open
(expected refusal), uninstall, and verify retained profile data. Test RU/EN
installer pages, non-ASCII profile paths and invalid/occupied listener errors.
A Linux cross build alone does not establish native runtime correctness.
