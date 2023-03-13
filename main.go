package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

func main() {
	// Declare variables for storing the input flags and arguments
	var (
		ip         string
		ipList     string
		cidr       string
		cidrList   string
		outputFile string
		verbose    bool
		help       bool
	)

	// Define input flags using the Go "flag" package
	flag.StringVar(&ip, "i", "", "single IP")
	flag.StringVar(&ip, "ip", "", "single IP")
	flag.StringVar(&ipList, "I", "", "list of IP")
	flag.StringVar(&ipList, "ip-list", "", "list of IP")
	flag.StringVar(&cidr, "c", "", "list of CIDR")
	flag.StringVar(&cidr, "cidr", "", "list of CIDR")
	flag.StringVar(&cidrList, "C", "", "list of CIDR")
	flag.StringVar(&cidrList, "cidr-list", "", "list of CIDR")
	flag.StringVar(&outputFile, "o", "", "output file")
	flag.StringVar(&outputFile, "output", "", "output file")
	flag.BoolVar(&verbose, "v", false, "print input flags if set")
	flag.BoolVar(&verbose, "verbose", false, "print input flags if set")
	flag.BoolVar(&help, "h", false, "print this help menu")
	flag.BoolVar(&help, "help", false, "print this help menu")

	// Parse the input flags and arguments
	flag.Parse()
	// If the verbose flag is set, print the input flags
	if verbose {
		fmt.Printf("Input flags:\n  -i | --ip\t%s\n  -I | --ip-list\t%s\n  -c | --cidr\t%s\n  -C | --cidr-list\t%s\n  -o | --output\t%s\n  -v | --verbose\t%v\n  -h | --help\t%v\n", ip, ipList, cidr, cidrList, outputFile, verbose, help)
	}

	// If the help flag is set, print the help menu and exit
	if help {
		printHelp()
		os.Exit(0)
	}

	// Check if at least one of the required flags is set
	if cidr == "" && cidrList == "" && ip == "" && ipList == "" {
		fmt.Println("[-] You must specify at least one of the following flags: (-c | --cidr), (-i | --ip), (-I | --ip-list), (-C | --cidr-list)")
		fmt.Println("Use -h or --help for more information")
		os.Exit(1)
	}

	if (ip != "" && ipList != "") || (ip != "" && cidr != "") || (ip != "" && cidrList != "") || (ipList != "" && cidr != "") || (ipList != "" && cidrList != "") || (cidr != "" && cidrList != "") {
		fmt.Println("[-] You can use one of the (-c | --cidr), (-i | --ip), (-I | --ip-list), (-C | --cidr-list) flags!")
		fmt.Println("[!] Use -h or --help for more information")
		os.Exit(1)
	}

	if ping(ip) {
		fmt.Println("[!] Yes, it's active !")
	} else {
		fmt.Println("[!] No, it's not active!")
	}

}

// Helper function to print the help menu
func printHelp() {
	fmt.Println("Usage: my-program [options]")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -i, --ip\t\tsingle IP")
	fmt.Println("  -I, --ip-list\t\tlist of IP")
	fmt.Println("  -c, --cidr\t\tlist of CIDR")
	fmt.Println("  -C, --cidr-list\tlist of CIDR")
	fmt.Println("  -o, --output\t\toutput file")
	fmt.Println("  -v, --verbose\t\tprint input flags if set")
	fmt.Println("  -h, --help\t\tprint this help menu")
}
func ping(ip string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS { // Check OS type for command
	case "windows":
		cmd = exec.Command("ping", "-n", "1", ip)
	default:
		cmd = exec.Command("ping", "-c", "1", ip)
	}

	err := cmd.Run()
	return (err == nil)
}
