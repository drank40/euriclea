package main

import (
	"errors"
	"flag"
	"math"
    "fmt"
	"os"
    "os/signal"
    "syscall"
    "io"
    "sync"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"   //Serve per scrivere, dont ask why
	log "github.com/sirupsen/logrus"
)

var once sync.Once
var (
	verbose bool
    veryVerbose bool
	plotFlag bool
)
var(
    io_in *os.File
    io_out *os.File
)

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

func fingerprint(packet gopacket.Packet) (Fingerprint, error) {
    var fg Fingerprint

    tcpLayer := packet.Layer(layers.LayerTypeTCP)
    if tcpLayer != nil {
        tcpPacket, _ := tcpLayer.(*layers.TCP)
        tsVal, _, err := extractTimestamps(tcpPacket.Options)

        if(err != nil) {
            log.Traceln(err)
        } else {

            if(plotFlag) {
                add_point(uint64(packet.Metadata().Timestamp.UnixMilli()), tsVal)
            }

            delta := roundup(uint64(packet.Metadata().Timestamp.UnixMilli()) - tsVal, 1000)

            fg = Fingerprint{delta : delta}

            return fg, nil
        }
    }

    return fg, errors.New("no TCP layer")
}

func roundup(x, n uint64) uint64 {
	return uint64(math.Ceil(float64(x)/float64(n))) * n
}

func init() {
	flag.BoolVar(&verbose, "v", false, "Turn on verbose output")
	flag.BoolVar(&veryVerbose, "vv", false, "Turn on very verbose output")
	flag.BoolVar(&plotFlag, "p", false, "Turn on time plotting")

    flag.Parse()
        
    log.SetLevel(log.InfoLevel)

    if(verbose) {
        log.SetLevel(log.DebugLevel)
    }

    if(veryVerbose) {
        log.SetLevel(log.TraceLevel)
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

    if(plotFlag) {
        log.Infoln("Starting plotting...")
        test_plot()
    }

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
    if(file_in == "-") {
        io_in = os.Stdin
    } else {
        io_in, err = os.Open(file_in)
    }

    handle_err(err)

    wr := pcapgo.NewWriter(io_out)
    err = wr.WriteFileHeader(65536, layers.LinkTypeRaw) //writing the header
    handle_err(err)

    rd, err := pcap.OpenOfflineFile(io_in)
    handle_err(err)


    log.Infoln("Starting analysis...")

    // Loop through packets in file
    packetSource := gopacket.NewPacketSource(rd, rd.LinkType())

    for {
        packet, err := packetSource.NextPacket()
        if err != nil {
            if err != io.EOF {
                log.Errorln("Read error: ", err, packet.ErrorLayer())
                continue
            } else {
                log.Traceln("EOF reached:", err)
                break
            }
        } else {
            fg, err := fingerprint(packet)
            if err != nil {
                log.Traceln(err)
            } else {
                log.Debugln(packet.Metadata().Timestamp, fg)

                //WIP
                if(fg.matches_haiku("blue-frog")) {
                    wr.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
                }
            }
        }
    }
}
