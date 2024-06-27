package fingerprint

import (
	"errors"
	"math"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
