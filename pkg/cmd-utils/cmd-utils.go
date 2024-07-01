package cmdUtils

import (
	"fmt"
	"os"
	"pcap-go/pkg/lib"
	"regexp"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var (
	pointsRegex = regexp.MustCompile(`\.+`)
	spacesRegex = regexp.MustCompile(`\s+`)
)

var (
    errPrefix string = "ERR"
    fatalPrefix string = "FATAL"
)

const (
	yellow = "\033[33m"
	red    = "\033[31m"
	reset  = "\033[0m"
)

func LogError(reason string, err error) {
	// Print in yellow
	fmt.Fprintf(os.Stderr, "%s%s%s %s%s\n", yellow, errPrefix, reset, reason, err)
}

func LogFatalError(reason string, err error) {
	// Print in red
	fmt.Fprintf(os.Stderr, "%s%s%s %s%s\n", red, fatalPrefix, reset, reason, err)
    os.Exit(1)
}


func PrintProgress(startTime time.Time, packetCount uint64, howOften uint64) {
    if packetCount%howOften == 0 {
		if packetCount > howOften {
			// clear last line
			fmt.Fprint(os.Stderr, "\033[1A\033[K")
		}

		pktPerSec := float64(packetCount) / time.Since(startTime).Seconds()
		pktPerSec /= 1_000

		fmt.Fprintf(os.Stderr, "%s processed %dK packets (%.0f Kpkt/s)\n",
        "euriclea: ", packetCount/1000, pktPerSec)
	}
}

func ShowBodyInfo(packet gopacket.Packet, fp lib.Fingerprint, displayContent bool) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	body := tcpLayer.LayerPayload()

    nonPrintable := 0
	for i := 0; i < len(body); i++ {
		if body[i] < 32 || body[i] > 126 {
			nonPrintable++
			body[i] = '.'
		}
	}
	if !(displayContent) {
		body = []byte("")
	} else if nonPrintable <= len(body)/2 {
		// replace sequences of non-printable characters with ...
		body = pointsRegex.ReplaceAll(body, []byte("..."))
		body = spacesRegex.ReplaceAll(body, []byte(" "))
	} else {
		body = []byte(fmt.Sprintf("... %d bytes of data ...", len(body)))
	}

	if body != nil {
		networkFlow := packet.NetworkLayer().NetworkFlow()
	    //tcpLayer := packet.Layer(layers.LayerTypeTCP)
	    //tcpPacket, _ := tcpLayer.(*layers.TCP)
		tcpFlow := packet.TransportLayer().TransportFlow()
	    //tsVal, tsEcho, _ := lib.ExtractTimestamps(tcpPacket.Options)
        

        fmt.Fprintf(os.Stderr, "\t%15s:%-5s -> %-10s:%-5s %20s:\t%s\n\n %s\n",
            
			networkFlow.Src().String(),
            tcpFlow.Src().String(),
			networkFlow.Dst().String(),
            tcpFlow.Dst().String(),
            fmt.Sprintf("(%s)", fp),
            packet.Metadata().Timestamp,
			body)
	}
}
