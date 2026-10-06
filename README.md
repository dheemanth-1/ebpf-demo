ebpf-demo

eBPF programs written in C and loaded from Go with cilium/ebpf. They drop TCP traffic from inside the kernel.

Folder	What it does
procdrop	Drops TCP packets to one port (default 4040). The port can be changed while it runs.
procxdp	Drops packets to every port a given process listens on, except one allowed port (default 4040).
Requirements
Linux with kernel BTF (/sys/kernel/btf/vmlinux exists) and root access
Go, clang, llvm and the libbpf headers
Fedora: sudo dnf install golang clang llvm libbpf-devel
Ubuntu: sudo apt install golang clang llvm libbpf-dev
cgroup v2 (only for procfilter)
Build

Run from the project root:

bash
go generate ./...        # compiles the C code and generates the Go bindings
mkdir -p bin
go build -o bin/procdrop ./procdrop
go build -o bin/procxdp ./procxdp


The generated files are committed, so go generate is only needed after editing a .c file.

Run

All programs need root. Stop with Ctrl+C.

bash
sudo ./bin/procdrop -port 4040
sudo ./bin/procxdp -process python3 -port 4040 [-iface lo]

-port defaults to 4040.
-process is required for procxdp. It is the executable name (max 15 characters).
procdrop also accepts a new port typed into its terminal while it runs.
Try it
bash
python3 tcp_server.py --port 4040  # default is on 8080
nc 127.0.0.1 4040              # for any input, the server responds with PONG
With procdrop -port 4040 running, nc hangs because packets to 4040 are dropped.
With procxdp -process python3 -port 8080 running, the server on 4040 is blocked, because python3 may only listen on 8080. Kernel messages show up in sudo cat /sys/kernel/debug/tracing/trace_pipe.
Notes
procdrop and procxdp both attach XDP to lo, and an interface takes only one XDP program. Run one at a time.
The XDP programs handle IPv4 only, so test with 127.0.0.1 rather than localhost.