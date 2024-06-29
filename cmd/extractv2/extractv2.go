package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	cmdUtils "pcap-go/pkg/cmd-utils"
	"pcap-go/pkg/lib"
	"regexp"
	"sync"
	"time"
    "strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/layers"
)

var startTime time.Time
var fgCollected = make([]lib.Fingerprint, 0)
var sink *pcapgo.Writer

//sync
var fgMutex sync.Mutex
var wg sync.WaitGroup

var fgsToMatch []string

func processPacket(packet gopacket.Packet) {
    wg.Add(1)
    defer wg.Done()
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil { // skip non-TCP packets
		return
	}

	fp, _, _, err := lib.ExtractFingerprint(packet)
	if err != nil {
		return
	}

	// if a fingerprint is provided, only show packets that match
	if *fingerprintToMatch != "" && !fp.ContainedIn(fgsToMatch) {
		return
	}
    
	body := tcpLayer.LayerPayload()
    // if a regex is provided, only show packets that match
	if regex != nil && !regex.Match(body) {
		return
	}

    fgMutex.Lock()
    if *outputPcap != "" {
		sink.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
    }

    if *listMode {
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

    }

    fgMutex.Unlock()

	// count the number of non-printable characters
	// if it is too high, we just show the number of bytes
	cmdUtils.ShowBodyInfo(packet, fp, *displayData)
}

var (
	listMode           = flag.Bool("L", false, "suppress regular output, list fingerprints")
	displayData        = flag.Bool("data", false, "display data")
    outputPcap         = flag.String("o", "", "write the matched pkgs to this pcap")
	fingerprintToMatch = flag.String("fg", "", "fingerprints to match")
	showProgress       = flag.Bool("p", false, "show progress")
	regexStr           = flag.String("r", "", "regex to match")
	bpfStr             = flag.String("bpf", "", "BPF filter")
	regex              *regexp.Regexp
)

func safeCloseIO(file *os.File) {
    err := file.Close()
	if err != nil {
        cmdUtils.LogFatalError("failed to close file: ", err)
	}
}

func main() {
	var err error

	flag.Parse()

    fgsToMatch = strings.Split(*fingerprintToMatch, ",")

	if *regexStr != "" {
		regex, err = regexp.Compile(*regexStr)
		if err != nil {
            cmdUtils.LogFatalError("failed to compile regex:", err)
		}
	}

	if len(flag.Args()) != 1 {
        cmdUtils.LogFatalError("Usage : euriclea {input.pcap}", errors.New("") )
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	go func() {
		<-ctx.Done()
		cancel()
	}()

    source, reader, err := lib.OpenPcapSource(flag.Arg(0))
    defer safeCloseIO(reader)

    if err != nil {
        cmdUtils.LogFatalError("Failed to open pcap source", err)
    }

	err = source.SetBPFFilter(*bpfStr)
	if err != nil {
        cmdUtils.LogFatalError("failed to set BPF filter: ", err)
	}

    if *outputPcap != "" {
        var writer *os.File
        sink, writer, err = lib.OpenPcapSink(*outputPcap)
        defer safeCloseIO(writer)

        if err != nil {
            cmdUtils.LogFatalError("Failed to open pcap sink ", err)
        }
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
            cmdUtils.LogFatalError("malformed packet: ", err)
		}

		go processPacket(packet)

		packetCount++
        if *showProgress {
		    cmdUtils.PrintProgress(startTime, packetCount, 10_000)
        }
	}

	// wait for the context to be done
	<-ctx.Done()
    wg.Wait()

    //Va sincronizzato meglio con le goroutine, non ho tempo ora
    if *listMode {
        fmt.Fprintln(os.Stderr, "Collected", len(fgCollected), "fingerprints")
	    for _, fg := range fgCollected {
		    fmt.Fprint(os.Stderr, fg, ",")
	    }

        fmt.Fprintln(os.Stderr, "")
    }
}
