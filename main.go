package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
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
		threads         int
		verbose         bool
		isSilent        bool
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
	flag.BoolVar(&verbose, "v", false, "verbose mode. If it is set, it shows according to which technique the IP is active.")
	flag.BoolVar(&verbose, "verbose", false, "verbose mode. If it is set, it shows according to which technique the IP is active.")
	flag.BoolVar(&isSilent, "s", false, "silent mode")
	flag.BoolVar(&isSilent, "silent", false, "silent mode")
	flag.BoolVar(&help, "h", false, "print this help menu")
	flag.BoolVar(&help, "help", false, "print this help menu")
	flag.DurationVar(&pingTimeout, "ping-timeout", 500*time.Millisecond, "Ping timeout in milliseconds")
	flag.DurationVar(&portscanTimeout, "portscan-timeout", 200*time.Millisecond, "Port-scan timeout in milliseconds")
	flag.BoolVar(&fullMode, "full", true, "Runs full mode")
	flag.BoolVar(&pingMode, "ping", false, "Runs only ping mode")
	flag.BoolVar(&portscanMode, "portscan", false, "Runs only portscan mode")
	flag.BoolVar(&ptrMode, "ptr", false, "Runs PTR scan")
	flag.IntVar(&threads, "t", 5, "number of threads")
	flag.IntVar(&threads, "threads", 5, "number of threads")
	// Parse the input flags and arguments
	flag.Parse()
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

	if outputFile == "" {
		printText(isSilent, "The result will be displayed in stdout.", "Info")

	} else {
		outputDir := filepath.Dir(outputFile)

		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			printText(isSilent, "specified output directory does not exist.", "Error")
			os.Exit(1)
		}

		if _, err := os.Stat(outputFile); err == nil {
			err := os.Remove(outputFile)
			if err != nil {
				printText(isSilent, "unable to remove the output file.", "Error")
				os.Exit(1)
			}
		}

		_, err := os.Create(outputFile)
		if err != nil {
			printText(isSilent, "unable to create output file", "Error")
			os.Exit(1)
		}
	}
	if ipList == "" {
		// create temp directory
		rand.Seed(time.Now().UnixNano())
		randNum := rand.Int63n(8999999999)
		randNum += 1000000000
		tempDir := fmt.Sprintf("%s/active-ip-%d", os.TempDir(), randNum)
		if err := os.MkdirAll(tempDir, 0777); err != nil {
			printText(isSilent, "unable to create temp directory", "Error")
		}
		// temp IP list
		ipList = fmt.Sprintf("%s/temp-ip-list.txt", tempDir)

	}

	// convert cidr or cidr list to ip list
	if cidr != "" {
		ok, hosts := cidrHosts(cidr)
		if !ok {
			fmt.Println("invalid cidr address")
			os.Exit(1)
		}
		output := strings.Join(hosts, "\n") + "\n"
		f, err := os.OpenFile(ipList, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer f.Close()
		_, err = f.WriteString(output)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
	}
	if cidrList != "" {
		file, err := os.Open(cidrList)
		if err != nil {
			fmt.Println("Error opening file:", err)
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		semaphore := make(chan struct{}, 10) // max number of goroutines
		var wg sync.WaitGroup
		for scanner.Scan() {
			wg.Add(1)
			cidr := scanner.Text()
			semaphore <- struct{}{} // acquire semaphore
			go func(cidr string) {
				defer func() { <-semaphore; wg.Done() }() // release semaphore and mark as done
				ok, hosts := cidrHosts(cidr)
				if !ok {
					fmt.Println("there is invalid CIDR address in cidr-list")
					os.Exit(1)
				}
				output := strings.Join(hosts, "\n") + "\n"
				f, err := os.OpenFile(ipList, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					fmt.Println("Error opening file:", err)
					return
				}
				defer f.Close()
				_, err = f.WriteString(output)
				if err != nil {
					fmt.Println("Error writing to file:", err)
					return
				}
			}(cidr)
		}
		wg.Wait()
		if err := scanner.Err(); err != nil {
			fmt.Println("Error scanning file:", err)
		}
	}

	// Mode detection
	if pingMode && ptrMode && portscanMode {
		if ip != "" {
			fullTechnique(ip, outputFile, pingTimeout, portscanTimeout, verbose, isSilent)
		} else {
			// Open the file
			file, _ := os.Open(ipList)
			defer file.Close()

			// Create a scanner
			scanner := bufio.NewScanner(file)
			bufferCh := make(chan string)

			// Initialize a wait group to ensure all goroutines complete before exiting
			var wg sync.WaitGroup
			wg.Add(threads)

			// Read lines concurrently; each goroutine will pass the line to fullTechnique()
			for i := 0; i < threads; i++ {
				go func() {
					defer wg.Done()

					for scanner.Scan() {
						bufferCh <- scanner.Text()
					}
				}()
			}

			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(bufferCh)
			}()

			// Process the buffered lines using fullTechnique() function
			for line := range bufferCh {
				fullTechnique(line, outputFile, pingTimeout, portscanTimeout, verbose, isSilent)

			}
		}
	} else if pingMode && portscanMode {
		if ip != "" {
			pingAndPortscanTechnique(ip, outputFile, pingTimeout, portscanTimeout, verbose, isSilent)

		} else {
			// Open the file
			file, _ := os.Open(ipList)
			defer file.Close()

			// Create a scanner
			scanner := bufio.NewScanner(file)
			bufferCh := make(chan string)

			// Initialize a wait group to ensure all goroutines complete before exiting
			var wg sync.WaitGroup
			wg.Add(threads)

			// Read lines concurrently; each goroutine will pass the line to pingAndPortscanTechnique()
			for i := 0; i < threads; i++ {
				go func() {
					defer wg.Done()

					for scanner.Scan() {
						bufferCh <- scanner.Text()
					}
				}()
			}

			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(bufferCh)
			}()

			// Process the buffered lines using pingAndPortscanTechnique() function
			for line := range bufferCh {
				pingAndPortscanTechnique(line, outputFile, pingTimeout, portscanTimeout, verbose, isSilent)

			}
		}
	} else if pingMode && ptrMode {
		if ip != "" {
			ptrRecordAndPingTechnique(ip, outputFile, pingTimeout, verbose, isSilent)
		} else {
			// Open the file
			file, _ := os.Open(ipList)
			defer file.Close()

			// Create a scanner
			scanner := bufio.NewScanner(file)
			bufferCh := make(chan string)

			// Initialize a wait group to ensure all goroutines complete before exiting
			var wg sync.WaitGroup
			wg.Add(threads)

			// Read lines concurrently; each goroutine will pass the line to ptrRecordAndPingTechnique()
			for i := 0; i < threads; i++ {
				go func() {
					defer wg.Done()

					for scanner.Scan() {
						bufferCh <- scanner.Text()
					}
				}()
			}

			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(bufferCh)
			}()

			// Process the buffered lines using ptrRecordAndPingTechnique() function
			for line := range bufferCh {
				ptrRecordAndPingTechnique(line, outputFile, pingTimeout, verbose, isSilent)

			}
		}
	} else if portscanMode && ptrMode {
		if ip != "" {
			ptrRecordAndPortscanTechnique(ip, outputFile, portscanTimeout, verbose, isSilent)
		} else {
			// Open the file
			file, _ := os.Open(ipList)
			defer file.Close()

			// Create a scanner
			scanner := bufio.NewScanner(file)
			bufferCh := make(chan string)

			// Initialize a wait group to ensure all goroutines complete before exiting
			var wg sync.WaitGroup
			wg.Add(threads)

			// Read lines concurrently; each goroutine will pass the line to ptrRecordAndPortscanTechnique()
			for i := 0; i < threads; i++ {
				go func() {
					defer wg.Done()

					for scanner.Scan() {
						bufferCh <- scanner.Text()
					}
				}()
			}

			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(bufferCh)
			}()

			// Process the buffered lines using ptrRecordAndPortscanTechnique() function
			for line := range bufferCh {
				ptrRecordAndPortscanTechnique(line, outputFile, portscanTimeout, verbose, isSilent)

			}
		}
	} else if ptrMode {
		if ip != "" {
			if !hasPTRRecord(ip, outputFile, verbose, isSilent) {
				printText(isSilent, fmt.Sprintf("%s isn't active", ip), "Info")
			}
		} else {
			// Open the file
			file, _ := os.Open(ipList)
			defer file.Close()

			// Create a scanner
			scanner := bufio.NewScanner(file)
			bufferCh := make(chan string)

			// Initialize a wait group to ensure all goroutines complete before exiting
			var wg sync.WaitGroup
			wg.Add(threads)

			// Read lines concurrently; each goroutine will pass the line to hasPTRRecord()
			for i := 0; i < threads; i++ {
				go func() {
					defer wg.Done()

					for scanner.Scan() {
						bufferCh <- scanner.Text()
					}
				}()
			}

			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(bufferCh)
			}()

			// Process the buffered lines using hasPTRRecord function
			for line := range bufferCh {
				if !hasPTRRecord(line, outputFile, verbose, isSilent) {
					printText(isSilent, fmt.Sprintf("%s isn't active", line), "Info")
				}
			}
		}
	} else if pingMode {
		if ip != "" {
			if !ping(ip, outputFile, pingTimeout, verbose) {
				printText(isSilent, fmt.Sprintf("%s isn't active", ip), "Info")
			}
		} else {
			// Open the file
			file, _ := os.Open(ipList)
			defer file.Close()

			// Create a scanner
			scanner := bufio.NewScanner(file)
			bufferCh := make(chan string)

			// Initialize a wait group to ensure all goroutines complete before exiting
			var wg sync.WaitGroup
			wg.Add(threads)

			// Read lines concurrently; each goroutine will pass the line to ping()
			for i := 0; i < threads; i++ {
				go func() {
					defer wg.Done()

					for scanner.Scan() {
						bufferCh <- scanner.Text()
					}
				}()
			}

			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(bufferCh)
			}()

			// Process the buffered lines using ping() function
			for line := range bufferCh {
				if !ping(line, outputFile, pingTimeout, verbose) {
					printText(isSilent, fmt.Sprintf("%s isn't active", line), "Info")
				}
			}
		}
	} else if portscanMode {
		if ip != "" {
			if !scanPorts(ip, outputFile, portscanTimeout, verbose) {
				printText(isSilent, fmt.Sprintf("%s isn't active", ip), "Info")
			}
		} else {
			// Open the file
			file, _ := os.Open(ipList)
			defer file.Close()

			// Create a scanner
			scanner := bufio.NewScanner(file)
			bufferCh := make(chan string)

			// Initialize a wait group to ensure all goroutines complete before exiting
			var wg sync.WaitGroup
			wg.Add(threads)

			// Read lines concurrently; each goroutine will pass the line to scanPorts()
			for i := 0; i < threads; i++ {
				go func() {
					defer wg.Done()

					for scanner.Scan() {
						bufferCh <- scanner.Text()
					}
				}()
			}

			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(bufferCh)
			}()

			// Process the buffered lines using scanPorts() function
			for line := range bufferCh {
				if !scanPorts(line, outputFile, portscanTimeout, verbose) {
					printText(isSilent, fmt.Sprintf("%s isn't active", line), "Info")
				}
			}
		}
	} else {
		if ip != "" {
			fullTechnique(ip, outputFile, pingTimeout, portscanTimeout, verbose, isSilent)
		} else {
			// Open the file
			file, _ := os.Open(ipList)
			defer file.Close()

			// Create a scanner
			scanner := bufio.NewScanner(file)
			bufferCh := make(chan string)

			// Initialize a wait group to ensure all goroutines complete before exiting
			var wg sync.WaitGroup
			wg.Add(threads)

			// Read lines concurrently; each goroutine will pass the line to fullTechnique()
			for i := 0; i < threads; i++ {
				go func() {
					defer wg.Done()

					for scanner.Scan() {
						bufferCh <- scanner.Text()
					}
				}()
			}

			// Wait for all goroutines to complete
			go func() {
				wg.Wait()
				close(bufferCh)
			}()

			// Process the buffered lines using fullTechnique() function
			for line := range bufferCh {
				fullTechnique(line, outputFile, pingTimeout, portscanTimeout, verbose, isSilent)

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
func ping(ip string, outputFile string, timeout time.Duration, verbose bool) bool {
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
	printOrSaveActiveIP(outputFile, ip, "was pinged", verbose)
	return true
}

func hasPTRRecord(ip string, outputFile string, verbose bool, isSilent bool) bool {
	// Convert IP address to reverse lookup format
	reverseIP, err := dns.ReverseAddr(ip)
	if err != nil {
		printText(isSilent, fmt.Sprintf("error converting IP address to reverse lookup format: %v", err), "Error")
		os.Exit(1)
	}
	// Set up the DNS client
	client := new(dns.Client)
	message := new(dns.Msg)
	message.SetQuestion(reverseIP, dns.TypePTR)

	// Send the DNS message to DNS server
	response, _, err := client.Exchange(message, net.JoinHostPort("8.8.8.8", "53"))
	if err != nil {
		printText(isSilent, fmt.Sprintf("error sending DNS query: %v", err), "Error")
		os.Exit(1)
	}
	if response == nil || response.Rcode != dns.RcodeSuccess || len(response.Answer) == 0 {
		return false
	}

	// Extract the pointer names from the response
	ptrNames := make([]string, 0)
	for _, ans := range response.Answer {
		ptrNames = append(ptrNames, strings.TrimRight(ans.(*dns.PTR).Ptr, "."))
	}
	printOrSaveActiveIP(outputFile, ip, fmt.Sprintf("has PTR record [%s]", strings.Join(ptrNames, ", ")), verbose)

	return true
}

func scanPorts(target string, outputFile string, timeout time.Duration, verbose bool) bool {
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
		printOrSaveActiveIP(outputFile, target, fmt.Sprintf("has open port %v", openPorts), verbose)

		return true
	} else {
		return false
	}
}
func printText(isSilent bool, text string, textType string) {
	if !isSilent {
		if textType == "Info" {
			fmt.Println("[!]", text)
		} else if textType == "Print" {
			fmt.Println(text)
		} else if textType == "Ok" {
			fmt.Println("[+]", text)
		} else if textType == "Error" {
			fmt.Println("[-]", text)
		}
	}
}
func printOrSaveActiveIP(outputFile string, data string, technique string, verbose bool) error {
	if outputFile == "" {
		if verbose {
			fmt.Printf("%s\t%s\n", data, technique)
		} else {
			fmt.Println(data)
		}
		return nil
	}

	f, err := os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if verbose {
		fmt.Fprintf(f, "%s\t%s\n", data, technique)
	} else {
		fmt.Fprint(f, data+"\n")
	}

	return nil
}

func cidrHosts(netw string) (bool, []string) {
	// convert string to IPNet struct
	_, ipv4Net, err := net.ParseCIDR(netw)
	if err != nil {
		return false, []string{}
	}
	// convert IPNet struct mask and address to uint32
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	// find the start IP address
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	// find the final IP address
	finish := (start & mask) | (mask ^ 0xffffffff)
	// make a slice to return host addresses
	var hosts []string
	// loop through addresses as uint32.
	// I used "start + 1" and "finish - 1" to discard the network and broadcast addresses.
	for i := start + 1; i <= finish-1; i++ {
		// convert back to net.IPs
		// Create IP address of type net.IP. IPv4 is 4 bytes, IPv6 is 16 bytes.
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		hosts = append(hosts, ip.String())
	}
	// return a slice of strings containing IP addresses
	return true, hosts
}
func fullTechnique(ip string, outputFile string, pingTimeout time.Duration, portscanTimeout time.Duration, verbose bool, isSilent bool) {
	if !hasPTRRecord(ip, outputFile, verbose, isSilent) {
		if !ping(ip, outputFile, pingTimeout, verbose) {
			if !scanPorts(ip, outputFile, portscanTimeout, verbose) {
				printText(isSilent, fmt.Sprintf("%s isn't active", ip), "Info")
			}
		}
	}
}
func pingAndPortscanTechnique(ip string, outputFile string, pingTimeout time.Duration, portscanTimeout time.Duration, verbose bool, isSilent bool) {
	if !ping(ip, outputFile, pingTimeout, verbose) {
		if !scanPorts(ip, outputFile, portscanTimeout, verbose) {
			printText(isSilent, fmt.Sprintf("%s isn't active", ip), "Info")
		}
	}
}
func ptrRecordAndPingTechnique(ip string, outputFile string, pingTimeout time.Duration, verbose bool, isSilent bool) {
	if !hasPTRRecord(ip, outputFile, verbose, isSilent) {
		if !ping(ip, outputFile, pingTimeout, verbose) {
			printText(isSilent, fmt.Sprintf("%s isn't active", ip), "Info")
		}
	}
}
func ptrRecordAndPortscanTechnique(ip string, outputFile string, portscanTimeout time.Duration, verbose bool, isSilent bool) {
	if !hasPTRRecord(ip, outputFile, verbose, isSilent) {
		if !scanPorts(ip, outputFile, portscanTimeout, verbose) {
			printText(isSilent, fmt.Sprintf("%s isn't active", ip), "Info")
		}
	}
}
