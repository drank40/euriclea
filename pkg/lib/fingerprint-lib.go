package lib

import (
    "os"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
    "errors"
    "time"
	"math"
	"github.com/yelinaung/go-haikunator"
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

func (fg Fingerprint) generateHaiku() string {
	return haikunator.New(int64(fg.Delta)).Haikunate()
}

// String returns a string representation of the fingerprint
func (fg Fingerprint) String() string { return fg.Haiku() }

func (sample Fingerprint) ContainedIn(toMatch []string) (bool) {
    for _, fg := range toMatch {
        if sample.Haiku() == fg {
            return true
        }
    }

    return false
}

var precision uint64 = 10000

func ExtractFingerprint(packet gopacket.Packet) (Fingerprint, uint64, uint64, error) {
	var fg Fingerprint

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return fg, 0, 0, errors.New("no TCP layer")
	}

	tcpPacket, _ := tcpLayer.(*layers.TCP)
	tsVal, _, err := ExtractTimestamps(tcpPacket.Options)

	if err != nil {
		return fg, 0, 0, err
	}


	delta := roundup(uint64(packet.Metadata().Timestamp.UnixMilli())-tsVal, precision)
	fg = Fingerprint{Delta: delta}
	return fg, uint64(packet.Metadata().Timestamp.UnixMilli()), tsVal, nil

}


func ExtractFingerprintRealTime(packet gopacket.Packet, t time.Time) (Fingerprint, uint64, uint64, error) {
	var fg Fingerprint

    if t.IsZero() {
		return fg, 0, 0, errors.New("null time")
    }

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return fg, 0, 0, errors.New("no TCP layer")
	}

	tcpPacket, _ := tcpLayer.(*layers.TCP)
	tsVal, _, err := ExtractTimestamps(tcpPacket.Options)

	if err != nil {
		return fg, 0, 0, err
	}

    millis := t.UnixMilli()

	delta := roundup(uint64(millis)-tsVal, precision)
	fg = Fingerprint{Delta: delta}
	return fg, uint64(millis), tsVal, nil
}


func ExtractFingerprintRealTimeFallback(packet gopacket.Packet) (Fingerprint, uint64, uint64, error) {
	var fg Fingerprint

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return fg, 0, 0, errors.New("no TCP layer")
	}

	tcpPacket, _ := tcpLayer.(*layers.TCP)
	tsVal, _, err := ExtractTimestamps(tcpPacket.Options)

	if err != nil {
		return fg, 0, 0, err
	}

    millis := time.Now().UnixMilli()

	delta := roundup(uint64(millis)-tsVal, precision)
	fg = Fingerprint{Delta: delta}
	return fg, uint64(millis), tsVal, nil
}


func roundup(x, n uint64) uint64 {
	return uint64(math.Ceil(float64(x)/float64(n))) * n
}

func ExtractTimestamps(opts []layers.TCPOption) (uint64, uint64, error) {
	for _, opt := range opts {
		if opt.OptionType == layers.TCPOptionKindTimestamps && len(opt.OptionData) >= 8 { // Check kind and sufficient data length
			tsVal := uint64(opt.OptionData[0])<<24 | uint64(opt.OptionData[1])<<16 | uint64(opt.OptionData[2])<<8 | uint64(opt.OptionData[3])
			tsEchoReply := uint64(opt.OptionData[4])<<24 | uint64(opt.OptionData[5])<<16 | uint64(opt.OptionData[6])<<8 | uint64(opt.OptionData[7])

            if tsEchoReply == 0 {
	            return 0, 0, errors.New("no timestamp")
            }
            
			return tsVal, tsEchoReply, nil
		}
	}

	return 0, 0, errors.New("no timestamp")
}

func OpenPcapSource(path string) (*pcap.Handle, *os.File, error) {
	var err error
	var reader *os.File

    if path == "-" {
		reader = os.Stdin
	} else {
		reader, err = os.Open(path)
		if err != nil {
            return nil, nil, err
		}
	}

	source, err := pcap.OpenOfflineFile(reader)
	if err != nil {
        return nil, nil, err
	}

    return source, reader, nil
}

func OpenPcapSink(path string) (*pcapgo.Writer, *os.File, error) {
	var err error
	var writer *os.File

    if path == "-" {
		writer = os.Stdout
	} else {
		writer, err = os.Create(path)
		if err != nil {
            return nil, nil, err
		}
	}

    sink := pcapgo.NewWriter(writer)
	err = sink.WriteFileHeader(65536, layers.LinkTypeRaw)
	if err != nil {
        return nil, nil, err
	}

    return sink, writer, nil
}
