package pktdump

import (
	"bytes"
	"github.com/gopacket/gopacket/layers"
	"strings"
)

const httpPort = 80

func (f *Formatter) formatHttp(tcp *layers.TCP) string {
	// GET / HTTP/1.1
	// HTTP/1.1 200 OK
	if len(tcp.Payload) == 0 || len(tcp.Payload) < 16 {
		return ""
	}

	httpPorts := []int{}
	if len(f.opts.httpPorts) > 0 {
		httpPorts = append(httpPorts, f.opts.httpPorts...)
	} else {
		httpPorts = append(httpPorts, httpPort)
	}
	haveHTTP := false
	for _, port := range httpPorts {
		if int(tcp.DstPort) == port || int(tcp.SrcPort) == port {
			haveHTTP = true
			break
		}
	}
	if !haveHTTP {
		return ""
	}

	index := bytes.Index(tcp.Payload, []byte("\r\n"))
	if index <= 0 {
		return ""
	}

	buf := strings.Builder{}
	buf.WriteString("HTTP: ")
	buf.WriteString(string(tcp.Payload[:index]))

	if f.opts.HeaderStyle >= FormatStyleVerbose {
		payloadStr := asciiFormat(tcp.Payload)
		var lines []string
		for _, line := range strings.Split(payloadStr, "\n") {
			line = f.opts.ContentIndent + line
			lines = append(lines, line)
		}
		f.opts.FormatedContent = append(f.opts.FormatedContent, strings.Join(lines, "\n")...)
	}

	return buf.String()
}
