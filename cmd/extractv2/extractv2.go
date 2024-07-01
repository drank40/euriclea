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
    "sort"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
	"github.com/google/gopacket/layers"
)

var startTime time.Time

var fgCollected = make([]lib.Fingerprint, 0)
var fgFrequency sync.Map

var sink *pcapgo.Writer

//sync
var fgMutex sync.Mutex
var wg sync.WaitGroup

var fgsToMatch []string
var fgsToUnmatch []string

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
	if (*fingerprintToMatch != "" && !fp.ContainedIn(fgsToMatch)) || (*fingerprintToUnmatch != "" && fp.ContainedIn(fgsToUnmatch)) {
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

    if *frequencyMode {
        incrementSyncMapValue(&fgFrequency, fp.Haiku(), 1)
    }


	// count the number of non-printable characters
	// if it is too high, we just show the number of bytes
	cmdUtils.ShowBodyInfo(packet, fp, *displayData)
}

func incrementSyncMapValue(m *sync.Map, key string, delta int) {
    for {
        // Load current value
        oldValue, ok := m.Load(key)
        if !ok {
            // If the key does not exist, try to store the delta as the new value
            if _, loaded := m.LoadOrStore(key, delta); loaded {
                // If the key was loaded in the meantime, continue the loop to increment properly
                continue
            }
            // If successfully stored new value, break the loop
            return
        }
        
        // Calculate new value
        newValue := oldValue.(int) + delta
        
        // Try to replace the old value with the new value
        if m.CompareAndSwap(key, oldValue, newValue) {
            // If successful, break the loop
            return
        }
        // If not successful, loop to try again
    }
}

var (
	listMode           = flag.Bool("L", false, "suppress regular output, list fingerprints")
	frequencyMode      = flag.Bool("F", false, "suppress regular output, list fingerprints and their frequency")
	displayData        = flag.Bool("data", false, "display data")
    outputPcap         = flag.String("o", "", "write the matched pkgs to this pcap")
	fingerprintToMatch = flag.String("white", "", "fingerprints to match")
	fingerprintToUnmatch = flag.String("black", "", "fingerprints to not match (it has priority over the whitelist)")
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

func listEpilogue() {
    sort.Slice(fgCollected, func(i, j int) bool {
        return fgCollected[i].Haiku() < fgCollected[j].Haiku()
    })

    fmt.Fprintln(os.Stderr, "Collected", len(fgCollected), "fingerprints")
    for i, fg := range fgCollected {
        if i < len(fgCollected)-1 {
            fmt.Fprint(os.Stderr, fg, ",")
        } else {
            fmt.Fprint(os.Stderr, fg)
        }
    }

    fmt.Fprintln(os.Stderr, "")
}

type FgFreq struct {
    Key   string
    Value int
}
func frequencyEpilogue() {
    var kvSlice []FgFreq

    // Collect entries from sync.Map
    fgFrequency.Range(func(key, value interface{}) bool {
        // Assuming the type to be string for keys and int for values
        strKey, okKey := key.(string)
        intValue, okValue := value.(int)
        if okKey && okValue {
            kvSlice = append(kvSlice, FgFreq{Key: strKey, Value: intValue})
        }
        return true // Continue the iteration
    })

    // Sort the slice by values
    sort.Slice(kvSlice, func(i, j int) bool {
        return kvSlice[i].Value < kvSlice[j].Value
    })

    fmt.Fprintln(os.Stderr, "")

    //print sorted
    for _, kv := range kvSlice {
        fmt.Fprintf(os.Stderr, "%s: %d\n", kv.Key, kv.Value)
    }

    fmt.Fprintln(os.Stderr, "")

    for i, kv := range kvSlice {
        if i < len(kvSlice)-1 {
            fmt.Fprint(os.Stderr, kv.Key, ",")
        } else {
            fmt.Fprint(os.Stderr, kv.Key)
        }
    }

    fmt.Fprintln(os.Stderr, "")
}

func main() {
	var err error

	flag.Parse()

    fgsToMatch = strings.Split(*fingerprintToMatch, ",")
    fgsToUnmatch = strings.Split(*fingerprintToUnmatch, ",")

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

    if *listMode {
        defer listEpilogue()
    }

    if *frequencyMode {
        defer frequencyEpilogue()
    }

	startTime = time.Now()
	for {
		select {
		case <-ctx.Done():
            wg.Wait()
			return
		default:
		}

		packet, err := handle.NextPacket()
		if err != nil {
			if err == io.EOF {
				cancel()
				break
			} else {
                cmdUtils.LogError("malformed packet: ", err)
                continue
            }
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

    if *showProgress {
	    cmdUtils.PrintProgress(startTime, packetCount, 1)
    }

}
