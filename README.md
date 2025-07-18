# ionet

**ionet** is a real-time network traffic monitoring tool based on **eBPF**. It operates in kernel space via eBPF and uses Go in user space to consume and display events.

## Getting Started

> ⚠️ Requires root privileges and eBPF support.

### 1. Build

First, compile the eBPF module:

```bash
cd eBPF_module
make
```
Then, compile the Go userspace application:

```
cd ..
go build
```
📁 Important: After building, move or copy the compiled ioNet.o file from eBPF_module/ into the same directory as the ionet binary.
The userspace program expects the eBPF object file to be in the same folder.
