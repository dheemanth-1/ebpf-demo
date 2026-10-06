package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// -I.. points clang at the folder holding vmlinux.h (the project root).
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go procxdp procxdp.c -- -I..

func main() {
	process := flag.String("process", "", "name of the process (comm) to restrict (required)")
	port := flag.Uint("port", 4040, "the only port that process may listen on")
	ifaceName := flag.String("iface", "lo", "network interface to attach the XDP filter to")
	flag.Parse()
	if *process == "" || *port == 0 || *port > 65535 {
		flag.Usage()
		os.Exit(1)
	}
	allowed := uint16(*port)

	name := filepath.Base(*process)
	if len(name) > 15 {
		name = name[:15]
	}
	var key [16]byte
	copy(key[:], name)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	var objs procxdpObjects
	if err := loadProcxdpObjects(&objs, nil); err != nil {
		log.Fatalf("Loading eBPF objects failed: %v", err)
	}
	defer objs.Close()

	if err := objs.AllowedPorts.Put(key, allowed); err != nil {
		log.Fatalf("Failed to set config: %v", err)
	}

	tp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.TrackListen, nil)
	if err != nil {
		log.Fatalf("Could not attach tracepoint: %v", err)
	}
	defer tp.Close()

	if err := seedExisting(name, allowed, objs.BlockedPorts); err != nil {
		log.Fatalf("Scanning existing listeners failed: %v", err)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Failed to find interface %s: %v", *ifaceName, err)
	}
	xl, err := link.AttachXDP(link.XDPOptions{Program: objs.FilterPackets, Interface: iface.Index})
	if err != nil {
		log.Fatalf("Could not attach XDP program: %v", err)
	}
	defer xl.Close()

	log.Printf("%q may only listen on port %d; packets to its other ports are dropped (XDP on %s)", name, allowed, *ifaceName)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
}

func seedExisting(name string, allowed uint16, blocked *ebpf.Map) error {
	listening := map[string]uint16{}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue // e.g. IPv6 disabled
		}

		for _, line := range strings.Split(string(data), "\n")[1:] {
			f := strings.Fields(line)
			// State 0A means LISTEN.
			if len(f) < 10 || f[3] != "0A" {
				continue
			}
			if p, err := strconv.ParseUint(f[1][strings.LastIndexByte(f[1], ':')+1:], 16, 16); err == nil {
				listening[f[9]] = uint16(p)
			}
		}
	}

	comms, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, commFile := range comms {
		comm, err := os.ReadFile(commFile)
		if err != nil || strings.TrimSpace(string(comm)) != name {
			continue
		}
		fds, _ := filepath.Glob(filepath.Dir(commFile) + "/fd/*")
		for _, fd := range fds {
			target, err := os.Readlink(fd) // looks like "socket:[12345]"
			if err != nil {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
			if p, ok := listening[inode]; ok && p != allowed {
				if err := blocked.Put(p, uint8(1)); err != nil {
					return err
				}
				log.Printf("existing listener on port %d will be blocked", p)
			}
		}
	}
	return nil
}
