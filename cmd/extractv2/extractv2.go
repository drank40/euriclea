package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
    "errors"
    "sync"
	"os/signal"
	"regexp"
	"time"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"pcap-go/pkg/lib"
)

var (
	pointsRegex = regexp.MustCompile(`\.+`)
	spacesRegex = regexp.MustCompile(`\s+`)
)

var startTime time.Time
var fgCollected = make([]lib.Fingerprint, 0)
var fgMutex sync.Mutex

func processPacket(packet gopacket.Packet) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil { // skip non-TCP packets
		return
	}

	fp, err := lib.ExtractFingerprint(packet)
	if err != nil {
		return
	}

	// if a fingerprint is provided, only show packets that match
	if *fingerprintToMatch != "" && fp.Haiku() != *fingerprintToMatch {
		return
	}

    if *listMode {
        fgMutex.Lock()
        exists := false
        for _, collected := range fgCollected {
            if collected.Delta == fp.Delta {
                exists = true
                break
            }
        }
        if !exists {
            fgCollected = append(fgCollected, fp)
        }

        fgMutex.Unlock()
    }

	body := tcpLayer.LayerPayload()

	// if a regex is provided, only show packets that match
	if regex != nil && !regex.Match(body) {
		return
	}

	// count the number of non-printable characters
	// if it is too high, we just show the number of bytes
	nonPrintable := 0
	for i := 0; i < len(body); i++ {
		if body[i] < 32 || body[i] > 126 {
			nonPrintable++
			body[i] = '.'
		}
	}
	if !(*displayData) {
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
		fmt.Printf("\t%15s -> %-15s %15s:\t%s\n",
			networkFlow.Src().String(),
			networkFlow.Dst().String(),
			fmt.Sprintf("(%s)", fp),
			body)
	}

}

var (
	listMode           = flag.Bool("L", false, "suppress regular output, list fingerprints")
	displayData        = flag.Bool("data", false, "display data")
	fingerprintToMatch = flag.String("fg", "", "fingerprint to match")
	showProgress       = flag.Bool("p", false, "show progress")
	regexStr           = flag.String("r", "", "regex to match")
	bpfStr             = flag.String("bpf", "", "BPF filter")
	regex              *regexp.Regexp
)

func main() {
	var err error

	flag.Parse()

	if *regexStr != "" {
		regex, err = regexp.Compile(*regexStr)
		if err != nil {
            lib.LogFatalError("failed to compile regex:", err)
		}
	}

	if len(flag.Args()) != 1 {
        lib.LogFatalError("Usage : euriclea {input.pcap}", errors.New("") )
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	go func() {
		<-ctx.Done()
		cancel()
	}()

    source, reader := lib.OpenPcapSource(flag.Arg(0))

	err = source.SetBPFFilter(*bpfStr)
	if err != nil {
        lib.LogFatalError("failed to set BPF filter: ", err)
	}

	handle := gopacket.NewPacketSource(source, source.LinkType())

	packetCount := uint64(0)

	startTime = time.Now()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		packet, err := handle.NextPacket()
		if err != nil {
			if err == io.EOF {
				cancel()
				break
			}
            lib.LogFatalError("malformed packet: ", err)
		}

		go processPacket(packet)

		packetCount++
        if *showProgress {
		    lib.PrintProgress(startTime, packetCount, 10_000)
        }
	}

    

	// wait for the context to be done
	<-ctx.Done()

    //Va sincronizzato meglio con le goroutine, non ho tempo ora
    if *listMode {
        fmt.Fprintln(os.Stderr, "Collected", len(fgCollected), "fingerprints")
	    for _, fg := range fgCollected {
		    fmt.Fprintln(os.Stderr, "-", fg)
	    }
    }

	err = reader.Close()
	if err != nil {
        lib.LogFatalError("failed to close file: ", err)
	}
}
