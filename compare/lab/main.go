// lab is the throwaway VLESS fixture and the packet summary tool for the
// comparison. It does not import the client under test.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "dial":
		err = cmdDial(os.Args[2:])
	case "pcap":
		err = cmdPcap(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: lab serve|dial|pcap [flags]")
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	xray := fs.String("xray", "", "path to xray.exe")
	out := fs.String("out", "", "directory for lab.json and logs")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *xray == "" || *out == "" {
		return fmt.Errorf("serve needs -xray and -out")
	}
	return serve(*xray, *out)
}

func cmdDial(args []string) error {
	fs := flag.NewFlagSet("dial", flag.ContinueOnError)
	xray := fs.String("xray", "", "path to xray.exe")
	lab := fs.String("lab", "", "path to lab.json")
	transport := fs.String("transport", "xhttp", "xhttp or raw")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *xray == "" || *lab == "" {
		return fmt.Errorf("dial needs -xray and -lab")
	}
	return dialSelf(*xray, *lab, *transport)
}

func cmdPcap(args []string) error {
	fs := flag.NewFlagSet("pcap", flag.ContinueOnError)
	in := fs.String("in", "", "pcap or pcapng file")
	out := fs.String("out", "", "summary json")
	var names, nets stringList
	fs.Var(&names, "name", "DNS name to keep (repeatable)")
	fs.Var(&nets, "net", "CIDR to keep (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *in == "" || *out == "" {
		return fmt.Errorf("pcap needs -in and -out")
	}
	return writePcapSummary(*in, *out, names, nets)
}

type stringList []string

func (s *stringList) String() string { return fmt.Sprint([]string(*s)) }
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
