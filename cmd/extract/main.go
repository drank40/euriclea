package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
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
	plotFlag    = flag.Bool("p", false, "Turn on time plotting")
	bpf         = flag.String("f", "", "BPF filter")
	regexRule   = flag.String("r", "", "Regex rule")
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
		fmt.Println("Provide an input and output file as plain args.")
		flag.Usage()
		os.Exit(-1)
	}

	file_in := flag.Arg(0)
	file_out := flag.Arg(1)

	io_out, err = os.Create(file_out)
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

	if *bpf != "" {
		log.Infoln("Setting BPF filter to:", *bpf)
		err = rd.SetBPFFilter(strings.Join(flag.Args()[2:], " "))
		handle_err(err)
	}

	filter := func(pkt gopacket.Packet) bool {
		return true
	}
	if *regexRule != "" {
		log.Infoln("Setting regex rule to:", *regexRule)
		rule, err := regexp.Compile(*regexRule)
		handle_err(err)

		filter = func(pkt gopacket.Packet) bool {
			return rule.Match(pkt.Data())
		}
	}

	log.Infoln("Starting analysis...")

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(rd, rd.LinkType())

	fgCollected := make([]fingerprint.Fingerprint, 0)

	for {
		packet, err := packetSource.NextPacket()
		if err != nil && !errors.Is(err, io.EOF) {
			log.Errorln("Read error: ", err, packet.ErrorLayer())
			continue
		} else if err != nil {
			log.Traceln("EOF reached:", err)
			break
		}

		if !filter(packet) {
			continue
		}

		fp, err := fingerprint.ExtractFingerprint(packet)
		if err != nil {
			log.Traceln(err)
			continue
		}

		log.Debugln(packet.Metadata().Timestamp, fp)
		if !slices.Contains(fgCollected, fp) {
			fgCollected = append(fgCollected, fp)
		}

	}

	log.Infoln("Collected", len(fgCollected), "fingerprints")
	for _, fg := range fgCollected {
		log.Infoln("-", fg)
	}
}
