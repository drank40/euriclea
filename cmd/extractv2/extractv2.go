package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"pcap-go/pkg/fingerprint"
)

var pointsRegex = regexp.MustCompile(`\.+`)

func processPacket(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil { // skip non-TCP packets
		return
	}

	fp, err := fingerprint.ExtractFingerprint(packet)
	if err != nil {
		return
	}

	body := tcpLayer.LayerPayload()

	// count the number of non-printable characters
	// if it is too high, we just show the number of bytes

	nonPrintable := 0
	for i := 0; i < len(body); i++ {
		if body[i] < 32 || body[i] > 126 {
			nonPrintable++
			body[i] = '.'
		}
	}

	if nonPrintable <= len(body)/2 {
		// replace sequences of non-printable characters with ...
		body = pointsRegex.ReplaceAll(body, []byte("..."))
	} else if *displayData {
		body = []byte(fmt.Sprintf("... %d bytes of data ...", len(body)))
	} else {
		body = nil
	}

	if len(body) != 0 {
		networkFlow := packet.NetworkLayer().NetworkFlow()
		fmt.Printf("\t%15s -> %-15s %15s:\t%s\n",
			networkFlow.Src().String(),
			networkFlow.Dst().String(),
			fmt.Sprintf("(%s)", fp),
			body)
	}

}

var (
	displayData = flag.Bool("data", false, "display data")
)

func main() {
	flag.Parse()

	if len(flag.Args()) != 1 {
		fmt.Println("Usage: nfqueue <pcap file> or nfqueue - for stdin")
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	go func() {
		<-ctx.Done()
		cancel()
	}()

	var reader *os.File
	var err error
	if flag.Arg(0) == "-" {
		reader = os.Stdin
	} else {
		reader, err = os.Open(flag.Arg(0))
		if err != nil {
			fmt.Println("extract: ", "failed to open file", flag.Arg(0), ":", err)
			os.Exit(1)
		}
	}

	source, err := pcap.OpenOfflineFile(reader)
	if err != nil {
		fmt.Println("extract: ", "failed to open pcap file:", err)
		os.Exit(1)
	}

	handle := gopacket.NewPacketSource(source, source.LinkType())

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := handle.NextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			fmt.Println("extract: ", "failed to read packet:", err)
			os.Exit(1)
		}

		processPacket(packet)
	}

	<-ctx.Done()

	err = reader.Close()
	if err != nil {
		fmt.Println("extract: ", "failed to close file:", err)
		os.Exit(1)
	}
}
