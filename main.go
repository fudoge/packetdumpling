package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var path string
var startTimestamp int64
var startTime string
var wg sync.WaitGroup

func capture(ni string, ctx context.Context) {
	defer wg.Done()
	fileName := fmt.Sprintf("%s_%s_%d.pcap", ni, startTime, startTimestamp)
	fullPath := filepath.Join(path, fileName)
	fmt.Println("Packet capture started: ", fullPath)

	f, err := os.Create(fullPath)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	snapshotlen := int32(65535)
	promiscuous := true
	timeout := pcap.BlockForever
	handle, err := pcap.OpenLive(ni, snapshotlen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	writer := pcapgo.NewWriter(f)
	writer.WriteFileHeader(uint32(snapshotlen), handle.LinkType())

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return

		case packet := <-packetSource.Packets():
			err = writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Println("Error writing Packet: ", err.Error())
			}

		}
	}
}

func main() {
	now := time.Now()
	startTimestamp = now.Unix()
	startTime = now.Format("20060102_150405")
	// 0.
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		cancel()
		return
	}()

	// 1. args 받기
	args := os.Args[1:]

	// 2. 파싱 및 캡처시작
	path = args[0]
	for i := 1; i < len(args); i++ {
		wg.Add(1)
		go capture(args[i], ctx)
	}

	wg.Wait()
	fmt.Printf("\nPacket captured for %dsecs.\n", time.Now().Unix()-startTimestamp)
}
