package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	log "github.com/sirupsen/logrus"

	"pcap-go/pkg/fingerprint"
)

var once sync.Once

var (
	ioIn  *os.File
	ioOut *os.File
)

var (
	verbose     = flag.Bool("v", false, "Turn on verbose output")
	veryVerbose = flag.Bool("vv", false, "Turn on very verbose output")
	outFile     = flag.String("o", "out.pcap", "Output file")
)

func init() {
	flag.Parse()

	log.SetLevel(log.InfoLevel)

	if *verbose {
		log.SetLevel(log.DebugLevel)
		log.Debug("Set log level to debug")
	}

	if *veryVerbose {
		log.SetLevel(log.TraceLevel)
		log.Debug("Set log level to trace")
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		fmt.Fprint(os.Stderr, "\b\b")
		log.Infof("Received signal: %s, stopping...", sig)
		once.Do(epilogue)
		os.Exit(0) // Exit after cleanup
	}()
}

func epilogue() {
	ioIn.Close()
	ioOut.Close()

	log.Infoln("Done!")
}

func handle_err(err error) {
	if err != nil {
		log.Fatalln(err)
	}
}

func main() {
	defer once.Do(epilogue)

	var err error

	if len(flag.Args()) != 2 {
		fmt.Println("Usage: extract <input.pcap> <signature>")
		os.Exit(-1)
	}

	fileIn := flag.Arg(0)
	fingerprintStr := flag.Arg(1)

	ioOut, err = os.Create(*outFile)
	handle_err(err)

	outWriter := pcapgo.NewWriter(ioOut)
	err = outWriter.WriteFileHeader(65536, layers.LinkTypeRaw)
	handle_err(err)

	if fileIn == "-" {
		log.Infoln("Reading from stdin")
		ioIn = os.Stdin
	} else {
		ioIn, err = os.Open(fileIn)
		handle_err(err)
	}

	handle, err := pcap.OpenOfflineFile(ioIn)
	handle_err(err)

	log.Infoln("Starting analysis...")

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	matchedPackets := 0
	for {
		packet, err := packetSource.NextPacket()
		if err != nil && !errors.Is(err, io.EOF) {
			log.Errorln("Read error: ", err, packet.ErrorLayer())
			continue
		} else if err != nil {
			log.Traceln("EOF reached:", err)
			break
		}

		fp, err := fingerprint.ExtractFingerprint(packet)
		if err != nil {
			log.Traceln(err)
			continue
		}

		if !fp.MatchesHaiku(fingerprintStr) {
			continue
		}

		matchedPackets++
		outWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
	}

	log.Infof("Matched %d packets", matchedPackets)
}
