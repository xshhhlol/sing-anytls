// Command tlstrace compares TLS record traces of pcap captures, for example an
// AnyTLS control node and a traffic-shaping node under the same client
// workload, or either against an ordinary HTTPS baseline.
//
//	tcpdump -i eth0 -s 0 -w control.pcap 'tcp port 443'
//	tlstrace -port 443 control=control.pcap shaped=shaped.pcap https=baseline.pcap
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/sagernet/sing-anytls/test/realclient"
)

type captureSet struct {
	name   string
	traces []realclient.Trace
}

func main() {
	port := flag.Uint("port", 443, "server TCP port")
	records := flag.Int("records", 16, "application data records per connection to compare")
	jsonPath := flag.String("json", "", "write the parsed traces to this JSON file")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: tlstrace [flags] [name=]capture.pcap ...\n\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	if flag.NArg() == 0 || *port == 0 || *port > 65535 || *records < 1 {
		flag.Usage()
		os.Exit(2)
	}
	var sets []captureSet
	for _, argument := range flag.Args() {
		name, path, found := strings.Cut(argument, "=")
		if !found {
			path, name = argument, strings.TrimSuffix(filepath.Base(argument), filepath.Ext(argument))
		}
		file, err := os.Open(path)
		if err != nil {
			fatal(err)
		}
		traces, err := realclient.ReadPCAP(file, uint16(*port))
		file.Close()
		if err != nil {
			if traces == nil {
				fatal(fmt.Errorf("%s: %w", path, err))
			}
			fmt.Fprintf(os.Stderr, "warning: %s: %v; using %d connections read so far\n", path, err, len(traces))
		}
		sets = append(sets, captureSet{name: name, traces: traces})
	}

	fmt.Printf("TLS bytes include record headers; record shape covers the first %d application data records per direction.\n", *records)
	fmt.Printf("short = records of at most %d bytes, which can only carry bare control frames.\n\n", realclient.ShortRecordLength)
	writer := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
	fmt.Fprintln(writer, "set\tconns\tmalformed\tup/conn mean\tdown/conn mean\tup total\tdown total\tshort down\tdistinct down\ttop down len (share)\tshort up\tdistinct up\t")
	for _, set := range sets {
		summary := realclient.Summarize(set.traces, *records)
		fmt.Fprintf(writer, "%s\t%d\t%d\t%.0f\t%.0f\t%d\t%d\t%.2f\t%.2f\t%d (%.0f%%)\t%.2f\t%.2f\t\n",
			set.name, summary.Connections, summary.Malformed,
			summary.BytesUp.Mean, summary.BytesDown.Mean, summary.TotalUp, summary.TotalDown,
			summary.Down.Short, summary.Down.Distinct, summary.Down.TopLength, summary.Down.TopShare*100,
			summary.Up.Short, summary.Up.Distinct)
	}
	writer.Flush()

	if len(sets) > 1 {
		fmt.Printf("\nLeave-one-out 1-NN separability against %q (lab indicator, not a DPI result):\n", sets[0].name)
		writer = tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.AlignRight)
		fmt.Fprintln(writer, "set\tsamples\taccuracy\trecall\tfalse positive\t")
		for _, set := range sets[1:] {
			result := realclient.Separate(set.traces, sets[0].traces, *records)
			fmt.Fprintf(writer, "%s\t%d/%d\t%.2f\t%.2f\t%.2f\t\n", set.name, result.Samples[0], result.Samples[1],
				result.Accuracy, result.Recall, result.FalsePositive)
		}
		writer.Flush()
	}

	if *jsonPath != "" {
		output := make(map[string][]realclient.Trace, len(sets))
		for _, set := range sets {
			output[set.name] = set.traces
		}
		data, err := json.MarshalIndent(output, "", "  ")
		if err != nil {
			fatal(err)
		}
		if err = os.WriteFile(*jsonPath, data, 0o644); err != nil {
			fatal(err)
		}
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "tlstrace:", err)
	os.Exit(1)
}
