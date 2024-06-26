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
	io_in  *os.File
	io_out *os.File
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
	io_in.Close()
	io_out.Close()

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

	if len(flag.Args()) < 2 {
		fmt.Println("Usage: extract <input.pcap> <signature>")
		os.Exit(-1)
	}

	file_in := flag.Arg(0)
	fingerprintStr := flag.Arg(1)

	io_out, err = os.Create(*outFile)
	handle_err(err)

	outWriter := pcapgo.NewWriter(io_out)
	err = outWriter.WriteFileHeader(65536, layers.LinkTypeEthernet)
	handle_err(err)

	if file_in == "-" {
		log.Infoln("Reading from stdin")
		io_in = os.Stdin
	} else {
		io_in, err = os.Open(file_in)
		handle_err(err)
	}

	rd, err := pcap.OpenOfflineFile(io_in)
	handle_err(err)

	log.Infoln("Starting analysis...")

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(rd, rd.LinkType())

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

		if fp.MatchesHaiku(fingerprintStr) {
			log.Infoln("Matched fingerprint:", fp)
			outWriter.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
		}

	}

}
