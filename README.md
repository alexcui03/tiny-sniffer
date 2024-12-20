# Tiny Sniffer

Course Project of SJTU NIS3364.

## Build from Source

## Requirements

1. git
2. CMake
3. Qt6
4. Npcap

### Prepare libpcap

Following the instructions on [libpcap README](https://github.com/the-tcpdump-group/libpcap/blob/master/INSTALL.md).

For windows, run `scrips/build-libpcap.ps1` on PowerShell to build libpcap. The compilation output will be in `<workspace>/third-party/libpcap/dist`.

### Build with CMake

Run cmake and for the project. `CMAKE_PREFIX_PATH` should be specified with path to libpcap and Qt6. `CMAKE_LIBRARY_ARCHITECTURE` should be specified for finding libpcap library, depending on your platform.

For example:
```bash
mkdir build
cd build
cmake -DCMAKE_PREFIX_PATH="<workspace>/third-party/libpcap/dist;<path-to-qt>/6.7.0/msvc2019_64" -DCMAKE_LIBRARY_ARCHITECTURE="x64" -A x64 ..
```

Then run cmake with `--build` to build the project.
```bash
cmake --build .
```
