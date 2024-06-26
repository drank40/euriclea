package fingerprint

import (
	"errors"
	"math"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/yelinaung/go-haikunator"
)

type Fingerprint struct {
	delta uint64
}

func (fg Fingerprint) Haiku() string                  { return haikunator.New(int64(fg.delta)).Haikunate() }
func (fg Fingerprint) String() string                 { return fg.Haiku() }
func (fg Fingerprint) MatchesHaiku(haiku string) bool { return fg.Haiku() == haiku }
func (fg Fingerprint) MatchesDelta(delta uint64) bool { return fg.delta == delta }

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
	fg = Fingerprint{delta: delta}
	return fg, nil

}

func roundup(x, n uint64) uint64 {
	return uint64(math.Ceil(float64(x)/float64(n))) * n
}

func extractTimestamps(opts []layers.TCPOption) (uint64, uint64, error) {
	for _, opt := range opts {
		if opt.OptionType == 8 && len(opt.OptionData) >= 8 { // Check kind and sufficient data length
			tsVal := uint64(opt.OptionData[0])<<24 | uint64(opt.OptionData[1])<<16 | uint64(opt.OptionData[2])<<8 | uint64(opt.OptionData[3])
			tsEchoReply := uint64(opt.OptionData[4])<<24 | uint64(opt.OptionData[5])<<16 | uint64(opt.OptionData[6])<<8 | uint64(opt.OptionData[7])

			return tsVal, tsEchoReply, nil
		}
	}

	return 0, 0, errors.New("no timestamp")
}
