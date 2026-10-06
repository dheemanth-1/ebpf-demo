package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// Target name 'bpf', C source file 'bpf/packet_filter.c'
//
// setPort writes the port into slot 0 of the kernel's array map.
// The XDP program reads that slot on every packet, so the change is
// effective immediately, with no reload.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf packet_filter.c -- -I..
func setPort(m *ebpf.Map, port uint16) error {
	return m.Put(uint32(0), port)
}

func main() {
	port := flag.Uint("port", 4040, "initial TCP destination port to drop (0 = drop nothing)")
	flag.Parse()
	if *port > 65535 {
		log.Fatalf("invalid -port %d: must be between 0 and 65535", *port)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects failed: %v", err)
	}
	defer objs.Close()

	// Set the port BEFORE attaching, so the very first packet already sees it.
	if err := setPort(objs.TargetPort, uint16(*port)); err != nil {
		log.Fatalf("Failed to set initial port: %v", err)
	}

	ifaceName := "lo"
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", ifaceName, err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.FilterPackets,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Could not attach XDP program: %v", err)
	}
	defer l.Close()

	fmt.Printf("XDP packet filter attached to '%s', dropping TCP port %d.\n", ifaceName, *port)

	go streamTracePipe()
	go readPortCommands(objs.TargetPort)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

func readPortCommands(m *ebpf.Map) {
	fmt.Println("Type a new port and press Enter to change it (0 = stop dropping, Ctrl+C to quit).")

	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// bitSize 16 makes ParseUint reject anything above 65535.
		p, err := strconv.ParseUint(line, 10, 16)
		if err != nil {
			fmt.Printf("invalid port %q: enter a number between 0 and 65535\n", line)
			continue
		}

		if err := setPort(m, uint16(p)); err != nil {
			fmt.Println("failed to update port:", err)
			continue
		}

		if p == 0 {
			fmt.Println("filter disabled: no packets are being dropped")
		} else {
			fmt.Printf("now dropping TCP port %d\n", p)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Println("stdin error:", err)
	}
}

func streamTracePipe() {
	pipe, err := os.Open("/sys/kernel/debug/tracing/trace_pipe")
	if err != nil {
		log.Printf("Failed to open trace_pipe: %v", err)
		return
	}
	defer pipe.Close()

	scanner := bufio.NewScanner(pipe)
	for scanner.Scan() {
		fmt.Println("[KERNEL TRACE]", scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		fmt.Println("Error with the scanner:", err)
	}
}
