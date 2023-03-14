package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func main() {
	// Declare variables for storing the input flags and arguments
	var (
		ip              string
		ipList          string
		cidr            string
		cidrList        string
		outputFile      string
		verbose         bool
		help            bool
		pingTimeout     time.Duration
		portscanTimeout time.Duration
		fullMode        bool
		pingMode        bool
		portscanMode    bool
		ptrMode         bool
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
	flag.DurationVar(&pingTimeout, "ping-timeout", 500*time.Millisecond, "Ping timeout in milliseconds")
	flag.DurationVar(&portscanTimeout, "portscan-timeout", 200*time.Millisecond, "Port-scan timeout in milliseconds")
	flag.BoolVar(&fullMode, "full", true, "Runs full mode")
	flag.BoolVar(&pingMode, "ping", false, "Runs only ping mode")
	flag.BoolVar(&portscanMode, "portscan", false, "Runs only portscan mode")
	flag.BoolVar(&ptrMode, "ptr", false, "Runs PTR scan")
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

	// Mode detection
	if pingMode && ptrMode && portscanMode {
		fmt.Println("[!] It's also full mode!!!!")
		hasRecord, ptr, err := hasPTRRecord(ip)
		if err != nil {
			fmt.Printf("Error checking for PTR record for %s: %v\n", ip, err)

		}
		if hasRecord {
			fmt.Printf("IP %s has PTR record: %s\n", ip, ptr)
		} else {
			if ok := ping(ip, pingTimeout); ok {
				fmt.Println("[!] Yes, it's active!")
			} else {
				ok, openPorts := scanPorts(ip, portscanTimeout)
				if ok {
					fmt.Println("[!] Yes, IP is active, openport =", openPorts)
				} else {
					fmt.Println("[!] No, it's not active!")
				}
			}
		}

	} else if pingMode && portscanMode {
		fmt.Println("[!] ping mode and portscan mode!")
	} else if pingMode && ptrMode {
		fmt.Println("[!] ping mode and ptr mode!")
	} else if portscanMode && ptrMode {
		fmt.Println("[!] portscan mode and ptr mode!")
	} else if ptrMode {
		fmt.Println("[!] ptr mode!")
	} else if pingMode {
		fmt.Println("[!] ping mode!")
	} else if portscanMode {
		fmt.Println("[!] portscan mode!")
	} else {
		fmt.Println("[!] full mode!")
		hasRecord, ptr, err := hasPTRRecord(ip)
		if err != nil {
			fmt.Printf("Error checking for PTR record for %s: %v\n", ip, err)

		}
		if hasRecord {
			fmt.Printf("IP %s has PTR record: %s\n", ip, ptr)
		} else {
			if ok := ping(ip, pingTimeout); ok {
				fmt.Println("[!] Yes, it's active!")
			} else {
				ok, openPorts := scanPorts(ip, portscanTimeout)
				if ok {
					fmt.Println("[!] Yes, IP is active, openport =", openPorts)
				} else {
					fmt.Println("[!] No, it's not active!")
				}
			}
		}

	}
	fmt.Println("good bye!")
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

// Ping sends an ICMP echo request to the specified IP address and returns true
// if a response is received within the timeout period, otherwise false.
func ping(ip string, timeout time.Duration) bool {
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	// Resolve IP address
	dstAddr, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false
	}

	// Construct ICMP echo request message
	echo := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte(""),
		},
	}

	echoBytes, err := echo.Marshal(nil)
	if err != nil {
		return false
	}

	// Send ICMP echo request
	if _, err := conn.WriteTo(echoBytes, dstAddr); err != nil {
		return false
	}

	// Await for ICMP echo reply
	replyBytes := make([]byte, 1500)
	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}
	n, _, err := conn.ReadFrom(replyBytes)
	if err != nil {
		return false
	}

	// Parse ICMP echo reply
	replyMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), replyBytes[:n])
	if err != nil {
		return false
	}

	// Check for ICMP echo reply
	if replyMsg.Type != ipv4.ICMPTypeEchoReply {
		return false
	}

	return true
}

func hasPTRRecord(ip string) (bool, string, error) {
	// Convert IP address to reverse lookup format
	reverseIP, err := dns.ReverseAddr(ip)
	if err != nil {
		return false, "", fmt.Errorf("error converting IP address to reverse lookup format: %v", err)
	}

	// Set up the DNS client
	client := new(dns.Client)
	message := new(dns.Msg)
	message.SetQuestion(reverseIP, dns.TypePTR)

	// Send the DNS message to DNS server
	response, _, err := client.Exchange(message, net.JoinHostPort("8.8.8.8", "53"))
	if err != nil {
		return false, "", fmt.Errorf("error sending DNS query: %v", err)
	}
	if response == nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
		return false, "", nil
	}

	// Extract the pointer names from the response
	ptrNames := make([]string, 0)
	for _, ans := range response.Answer {
		ptrNames = append(ptrNames, strings.TrimRight(ans.(*dns.PTR).Ptr, "."))
	}
	return true, strings.Join(ptrNames, ", "), nil
}

func scanPorts(target string, timeout time.Duration) (bool, []int) {
	openPorts := []int{}
	ports := []string{"80", "443", "22"}

	var wg sync.WaitGroup // Create a WaitGroup to wait for all goroutines
	for _, port := range ports {

		wg.Add(1) // Increment WaitGroup counter for new goroutine

		go func(target string, port string) {
			defer wg.Done() // Notify WaitGroup when goroutine is done

			address := fmt.Sprintf("%s:%s", target, port)

			conn, err := net.DialTimeout("tcp", address, timeout)

			if err == nil {
				conn.Close()
				portNum, _ := strconv.Atoi(port) // convert port string to int
				openPorts = append(openPorts, portNum)
			}
		}(target, port)
	}

	wg.Wait() // Wait for all goroutines to finish

	if len(openPorts) > 0 {
		return true, openPorts
	} else {
		return false, []int{}
	}
}
