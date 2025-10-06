package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/x-way/pktdump"
)

func main() {
	absoluteSeq := flag.Bool("absolute-seq", false, "display absolute TCP sequence numbers")
	flag.Parse()

	files := flag.Args()
	if len(files) == 0 {
		log.Fatal("Error: missing pcap filename parameter")
	}

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			log.Fatalf("Could not open pcap file '%s': %v\n", file, err)
		}
		func() {
			defer f.Close()

			handle, err := pcapgo.NewReader(f)
			if err != nil {
				log.Fatalf("Could not create pcap reader: %v\n", err)
			}

			pkgsrc := gopacket.NewPacketSource(handle, handle.LinkType())

			opts := &pktdump.Options{}
			if *absoluteSeq {
				opts.SetRelativeTCPSeq(false)
			}
			formatter := pktdump.NewFormatter(opts)

			for packet := range pkgsrc.Packets() {
				fmt.Printf("%s ", packet.Metadata().CaptureInfo.Timestamp.Local().Format("15:04:05.000000"))
				fmt.Println(formatter.Format(packet))
			}
		}()
	}
}
