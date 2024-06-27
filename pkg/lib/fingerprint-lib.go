package lib

import (
    "fmt"
    "os"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
    "time"
    "errors"
	"math"
	"github.com/yelinaung/go-haikunator"
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

type Fingerprint struct {
	Delta uint64 // Delta between packet timestamp and host timestamp

	haiku string
}

// Haiku returns a haiku string representation of the fingerprint
func (fg Fingerprint) Haiku() string {
	if fg.haiku == "" {
		fg.haiku = fg.generateHaiku()
	}
	return fg.haiku
}

// String returns a string representation of the fingerprint
func (fg Fingerprint) String() string { return fg.Haiku() }

func ExtractFingerprint(packet gopacket.Packet) (Fingerprint, error) {
	var fg Fingerprint

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return fg, errors.New("no TCP layer")
	}

	tcpPacket, _ := tcpLayer.(*layers.TCP)
	tsVal, _, err := extractTimestamps(tcpPacket.Options)

	if err != nil {
		return fg, err
	}

	delta := roundup(uint64(packet.Metadata().Timestamp.UnixMilli())-tsVal, 1000)
	fg = Fingerprint{Delta: delta}
	return fg, nil

}

func (fg Fingerprint) generateHaiku() string {
	return haikunator.New(int64(fg.Delta)).Haikunate()
}

func roundup(x, n uint64) uint64 {
	return uint64(math.Ceil(float64(x)/float64(n))) * n
}

func extractTimestamps(opts []layers.TCPOption) (uint64, uint64, error) {
	for _, opt := range opts {
		if opt.OptionType == layers.TCPOptionKindTimestamps && len(opt.OptionData) >= 8 { // Check kind and sufficient data length
			tsVal := uint64(opt.OptionData[0])<<24 | uint64(opt.OptionData[1])<<16 | uint64(opt.OptionData[2])<<8 | uint64(opt.OptionData[3])
			tsEchoReply := uint64(opt.OptionData[4])<<24 | uint64(opt.OptionData[5])<<16 | uint64(opt.OptionData[6])<<8 | uint64(opt.OptionData[7])

			return tsVal, tsEchoReply, nil
		}
	}

	return 0, 0, errors.New("no timestamp")
}

func LogError(reason string, err error) {
	// Print in yellow
	fmt.Fprintf(os.Stderr, "%s%s%s %s%s\n", yellow, errPrefix, reset, reason, err)
}

func LogFatalError(reason string, err error) {
	// Print in red
	fmt.Fprintf(os.Stderr, "%s%s%s %s%s\n", red, fatalPrefix, reset, reason, err)
    os.Exit(1)
}

func OpenPcapSource(path string) (*pcap.Handle, *os.File) {
	var err error
	var reader *os.File

    if path == "-" {
		reader = os.Stdin
	} else {
		reader, err = os.Open(path)
		if err != nil {
            LogFatalError(fmt.Sprintf("failed to open file path %s", path), err);
		}
	}

	source, err := pcap.OpenOfflineFile(reader)
	if err != nil {
        LogFatalError("failed to read pcap ", err);
	}

    return source, reader
}

func OpenPcapSink(path string) (*pcapgo.Writer, *os.File) {
	var err error
	var writer *os.File

    if path == "-" {
		writer = os.Stdout
	} else {
		writer, err = os.Open(path)
		if err != nil {
            LogFatalError(fmt.Sprintf("failed to open file path %s", path), err);
		}
	}

    sink := pcapgo.NewWriter(writer)
	err = sink.WriteFileHeader(65536, layers.LinkTypeRaw)
	if err != nil {
        LogFatalError("failed to write head to pcap: ", err);
	}

    return sink, writer
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
