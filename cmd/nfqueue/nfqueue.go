package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"time"
    "net"
    "strings"
    "regexp"
	"github.com/florianl/go-nfqueue/v2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/mdlayher/netlink"
	"pcap-go/pkg/lib"
)


var fgsToMatch []string
var fgsToUnmatch []string
var originalFgsToUnmatch []string

//Host (default 10.60.2.1)
var host net.IP

//il regex di Go (RE2) ha una complessità temporale assicurata di O(N)
var flagRegex = regexp.MustCompile(`[A-Z0-9]{31}=`)
var secretRegex *regexp.Regexp 

func processPacket(nf *nfqueue.Nfqueue) nfqueue.HookFunc {
	return func(a nfqueue.Attribute) int {
		id := *a.PacketID

		packet := gopacket.NewPacket(*a.Payload, layers.LayerTypeIPv4, gopacket.Default)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)

		body := tcpLayer.LayerPayload()

		if tcpLayer == nil { // skip non-TCP packets
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

		fp, _, _, err := lib.ExtractFingerprintRealTime(packet, *a.Timestamp)

		if err != nil {
			_ = nf.SetVerdict(id, nfqueue.NfAccept)
			return 0
		}

        dst := packet.NetworkLayer().NetworkFlow().Dst()
        dstIp := net.IP(dst.Raw())

        //no flag ins shall be reject
        if  dstIp.Equal(host) && flagRegex.Match(body) || (*secretRegexString != "" && secretRegex.Match(body))  {
            fmt.Println("\033[33mFLAG-IN OR SECRET DETECTED :\033[0m ", fp)
            if(!fp.ContainedIn(fgsToUnmatch)) {
		        fgsToUnmatch = append(fgsToUnmatch, fp.Haiku())
            }

            body = body[min(len(body), 100):]
            // replace non-printable characters with .
            for i := 0; i < len(body); i++ {
                if body[i] < 32 || body[i] > 126 {
                    body[i] = '.'
                }
            }

            if len(body) != 0 {
                networkFlow := packet.NetworkLayer().NetworkFlow()
                fmt.Printf("[%d]\t%s -> %s (%s): %s\n", id,
                    networkFlow.Src().String(), networkFlow.Dst().String(),
                    fp, body)
            }


			_ = nf.SetVerdict(id, nfqueue.NfAccept)
            return 0
	    }
        
        //only match if the fg is in the blacklist and not in the whitelist
	    if *fingerprintToMatch != "" && fp.ContainedIn(fgsToMatch) && !fp.ContainedIn(fgsToUnmatch) {
			_ = nf.SetVerdict(id, nfqueue.NfDrop)
			return 0
        }

		body = body[min(len(body), 100):]
		// replace non-printable characters with .
		for i := 0; i < len(body); i++ {
			if body[i] < 32 || body[i] > 126 {
				body[i] = '.'
			}
		}

		if len(body) != 0 {
			networkFlow := packet.NetworkLayer().NetworkFlow()
			fmt.Printf("[%d]\t%s -> %s (%s): %s\n", id,
				networkFlow.Src().String(), networkFlow.Dst().String(),
				fp, body)
		}

		_ = nf.SetVerdict(id, nfqueue.NfAccept)
		return 0
	}
}


func difference(slice1, slice2 []string) []string {
    diff := []string{}
    seen := make(map[string]bool)

    for _, item := range slice2 {
        seen[item] = true
    }

    for _, item := range slice1 {
        if _, found := seen[item]; !found {
            diff = append(diff, item)
        }
    }

    return diff
}

func removeDuplicates(elements []string) []string {
    seen := make(map[string]bool)
    unique := []string{}

    for _, element := range elements {
        if _, found := seen[element]; !found {
            seen[element] = true
            unique = append(unique, element)
        }
    }

    return unique
}

var (
	queueNum             = flag.Uint("queue", 420, "nfqueue queue number")
	fingerprintToMatch   = flag.String("black", "", "fingerprints to block")
	fingerprintToUnmatch = flag.String("white", "", "fingerprints to NOT block initially (ovverrides the blacklist if necessary)")
    hostString           = flag.String("host", "10.60.2.1", "host ip, in order to find flag ins")
    secretRegexString    = flag.String("secret", "", "secret regex to whitelist arbirary hosts")
)

func main() {
    var err error
	flag.Parse()

    host = net.ParseIP(*hostString)
    if(*secretRegexString != "") {
		secretRegex = regexp.MustCompile(*secretRegexString)
    }

    if host == nil {
		fmt.Println("could not parse IP")
    }

    if(*fingerprintToMatch != "") {
        fgsToMatch = strings.Split(*fingerprintToMatch, ",")
    }

    if(*fingerprintToUnmatch != "") { 
        fgsToUnmatch = strings.Split(*fingerprintToUnmatch, ",")
        originalFgsToUnmatch = strings.Split(*fingerprintToUnmatch, ",")
    }

	config := nfqueue.Config{
		NfQueue:      uint16(*queueNum),
		MaxPacketLen: 0xFFFF,
		MaxQueueLen:  0xFF,
		Copymode:     nfqueue.NfQnlCopyPacket,
		WriteTimeout: 15 * time.Millisecond,
	}

	queue, err := nfqueue.Open(&config)
	if err != nil {
		fmt.Println("could not open nfqueue socket:", err)
		os.Exit(1)
	}

	// Avoid receiving ENOBUFS errors.
	if err := queue.SetOption(netlink.NoENOBUFS, true); err != nil {
		fmt.Printf("failed to set netlink option %v: %v\n", netlink.NoENOBUFS, err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	go func() {
		<-ctx.Done()
		cancel()
	}()

	errorFunc := func(e error) int {
		fmt.Println("error:", e)
		return 0
	}

	// Register your function to listen on nflqueue queue 100
	err = queue.RegisterWithErrorFunc(ctx, processPacket(queue), errorFunc)
	if err != nil {
		fmt.Println("could not register processPacket:", err)
		os.Exit(1)
	}

	// Block till the context expires
	<-ctx.Done()

	// Close the nfqueue socket
	err = queue.Close()
	if err != nil {
		fmt.Println("could not close nfqueue socket:", err)
		os.Exit(1)
	}

    deduplicated := removeDuplicates(fgsToUnmatch)

    fmt.Println("Updated whitelist: ")

    for i, fg := range deduplicated {
        if i < len(deduplicated)-1 {
            fmt.Print(fg, ",")
        } else {
            fmt.Print(fg)
        }
    }

    fmt.Println("")

    new_fgs := difference(fgsToUnmatch, originalFgsToUnmatch)

    fmt.Println("New fingerprints: ")

    for i, fg := range new_fgs {
        if i < len(new_fgs)-1 {
            fmt.Print(fg, ",")
        } else {
            fmt.Print(fg)
        }
    }

    fmt.Println("")
}
