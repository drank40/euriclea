package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"

	"pcap-go/pkg/fingerprint"
)

func processPacket(nf *nfqueue.Nfqueue) nfqueue.HookFunc {
	return func(a nfqueue.Attribute) int {
		id := *a.PacketID

		packet := gopacket.NewPacket(*a.Payload, layers.LayerTypeIPv4, gopacket.Default)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		if tcpLayer == nil { // skip non-TCP packets
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		fp, err := fingerprint.ExtractFingerprint(packet)
		if err != nil {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		body := tcpLayer.LayerPayload()
		body = body[min(len(body), 100):]
		// replace non-printable characters with .
		for i := 0; i < len(body); i++ {
			if body[i] < 32 || body[i] > 126 {
				body[i] = '.'
			}
		}

		if len(body) != 0 {
			networkFlow := packet.NetworkLayer().NetworkFlow()
			fmt.Printf("[%d]\t%s -> %s (%s): %s\n", id,
				networkFlow.Src().String(), networkFlow.Dst().String(),
				fp, body)
		}

		_ = nf.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}
}

var (
	queueNum = flag.Uint("queue", 0, "nfqueue queue number")
)

func main() {
	flag.Parse()

	config := nfqueue.Config{
		NfQueue:      uint16(*queueNum),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	queue, err := nfqueue.Open(&config)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		os.Exit(1)
	}

	// Avoid receiving ENOBUFS errors.
	if err := queue.SetOption(netlink.NoENOBUFS, true); err != nil {
		fmt.Printf("failed to set netlink option %v: %v\n", netlink.NoENOBUFS, err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	go func() {
		<-ctx.Done()
		cancel()
	}()

	errorFunc := func(e error) int {
		fmt.Println("error:", e)
		return 0
	}

	// Register your function to listen on nflqueue queue 100
	err = queue.RegisterWithErrorFunc(ctx, processPacket(queue), errorFunc)
	if err != nil {
		fmt.Println("could not register processPacket:", err)
		os.Exit(1)
	}

	// Block till the context expires
	<-ctx.Done()

	// Close the nfqueue socket
	err = queue.Close()
	if err != nil {
		fmt.Println("could not close nfqueue socket:", err)
		os.Exit(1)
	}
}
