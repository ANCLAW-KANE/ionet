package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type RawEvent struct {
	Protocol  uint8
	Direction byte
	Saddr     uint32
	Daddr     uint32
	SaddrV6   [16]uint8
	DaddrV6   [16]uint8
	Sport     uint16
	Dport     uint16
	Ifindex   uint32
	Family    uint32
	Pkttype   uint32
	Bytes     uint64
}

type KeyEvent struct {
	Protocol  uint8
	Direction byte
	Saddr     uint32
	Daddr     uint32
	SaddrV6   [16]uint8
	DaddrV6   [16]uint8
	Sport     uint16
	Dport     uint16
	Ifindex   uint32
	Family    uint32
	Pkttype   uint32
}

type Stats struct {
	Bytes uint64
}

type StructEvent struct {
	key       KeyEvent
	val       Stats
	Timestamp uint64
}

const (
	bpfFilePath          = "ioNet.o"
	bpfIngressCgroupProg = "monitor_ingress"
	bpfEgressCgroupProg  = "monitor_egress"
	bpfMapTraffic        = "traffic_ring"
	cgroupPath           = "/sys/fs/cgroup/"
)

func LoadAndAttach() (chan StructEvent, *ebpf.Collection, []link.Link, chan error) {

	var links []link.Link

	spec, err := ebpf.LoadCollectionSpec(bpfFilePath)
	if err != nil {
		log.Fatalf("failed to load spec: %v", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		log.Printf("load collection: %s", err)
	}

	programs := map[string]*ebpf.Program{
		bpfIngressCgroupProg: coll.Programs[bpfIngressCgroupProg],
		bpfEgressCgroupProg:  coll.Programs[bpfEgressCgroupProg],
	}

	ingressLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: programs[bpfIngressCgroupProg],
	})
	if err != nil {
		log.Fatalf("attach ingress: %v", err)
	}
	links = append(links, ingressLink)

	egressLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: programs[bpfEgressCgroupProg],
	})
	if err != nil {
		log.Fatalf("attach egress: %v", err)
	}
	links = append(links, egressLink)

	statsMap := coll.Maps[bpfMapTraffic]
	if statsMap == nil {
		log.Printf("[%s] map not found", bpfMapTraffic)
	}

	rd, err := ringbuf.NewReader(statsMap)
	if err != nil {
		log.Fatal(err)
	}

	events := make(chan StructEvent, 1<<20)
	errChan := make(chan error, 8)

	go func() {
		defer close(events)
		defer rd.Close()
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					log.Println("Ring buffer closed, stopping reader")
					return
				}
				log.Printf("Error reading from ringbuf: %v", err)
				continue
			}

			var bpfEvent RawEvent

			if err := binary.Read(bytes.NewBuffer(record.RawSample),
				binary.LittleEndian, &bpfEvent); err != nil {
				log.Printf("Failed to parse event: %v", err)
				continue
			}

			event := StructEvent{
				key: KeyEvent{

					Protocol:  bpfEvent.Protocol,
					Direction: bpfEvent.Direction,
					Saddr:     bpfEvent.Saddr,
					Daddr:     bpfEvent.Daddr,
					SaddrV6:   bpfEvent.SaddrV6,
					DaddrV6:   bpfEvent.DaddrV6,
					Sport:     bpfEvent.Sport,
					Dport:     bpfEvent.Dport,
					Ifindex:   bpfEvent.Ifindex,
					Family:    bpfEvent.Family,
					Pkttype:   bpfEvent.Pkttype,
				},
				val: Stats{
					Bytes: bpfEvent.Bytes,
				},
				Timestamp: uint64(time.Now().Unix()),
			}
			select {
			case events <- event:

			default:
				errChan <- errors.New(ERR_CHAN)
			}
		}
	}()

	return events, coll, links, errChan
}
