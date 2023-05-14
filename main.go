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
		ports           []string
		tmpPorts        string
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
		tempDir         string
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
	flag.DurationVar(&pingTimeout, "ping-timeout", 400*time.Millisecond, "Ping timeout in milliseconds")
	flag.DurationVar(&portscanTimeout, "portscan-timeout", 400*time.Millisecond, "Port-scan timeout in milliseconds")
	flag.BoolVar(&fullMode, "full", true, "Runs full mode")
	flag.BoolVar(&pingMode, "ping", false, "Runs only ping mode")
	flag.BoolVar(&portscanMode, "portscan", false, "Runs only portscan mode")
	flag.BoolVar(&ptrMode, "ptr", false, "Runs PTR scan")
	flag.StringVar(&tmpPorts, "p", "80,443,22", "Comma-separated list of ports. default: 80,443,22")
	flag.StringVar(&tmpPorts, "port", "80,443,22", "Comma-separated list of ports. default: 80,443,22")
	flag.IntVar(&threads, "t", 5, "number of threads")
	flag.IntVar(&threads, "threads", 5, "number of threads")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Use -h or --help for more information.")
	}
	// Parse the input flags and arguments
	flag.Parse()
	// Get the values of the ports flags
	ports = strings.Split(tmpPorts, ",")
	//show banner
	showBanner(isSilent)
	// If the help flag is set, print the help menu and exit
	if help {
		printHelp()
		os.Exit(0)
	}

	// Check if at least one of the required flags is set
	if cidr == "" && cidrList == "" && ip == "" && ipList == "" {
		printText(isSilent, "You must specify at least one of the following flags: (-c | --cidr), (-i | --ip), (-I | --ip-list), (-C | --cidr-list", "Error")
		printText(isSilent, "Use -h or --help for more information", "Info")
		os.Exit(1)
	}

	if (ip != "" && ipList != "") || (ip != "" && cidr != "") || (ip != "" && cidrList != "") || (ipList != "" && cidr != "") || (ipList != "" && cidrList != "") || (cidr != "" && cidrList != "") {
		printText(isSilent, " You can use one of the (-c | --cidr), (-i | --ip), (-I | --ip-list), (-C | --cidr-list) flags!", "Error")
		printText(isSilent, "Use -h or --help for more information", "Info")
		os.Exit(1)
	}

	if outputFile == "" {
		printText(isSilent, "The result will be displayed in stdout.", "Info")

	} else {
		outputDir := filepath.Dir(outputFile)

		if _, err := os.Stat(outputDir); os.IsNotExist(err) {
			printText(isSilent, "Specified output directory does not exist.", "Error")
			os.Exit(1)
		}

		if _, err := os.Stat(outputFile); err == nil {
			err := os.Remove(outputFile)
			if err != nil {
				printText(isSilent, "Unable to remove the output file.", "Error")
				os.Exit(1)
			}
		}

		_, err := os.Create(outputFile)
		if err != nil {
			printText(isSilent, "Unable to create output file", "Error")
			os.Exit(1)
		}
		printText(isSilent, "The result will be saved in: "+outputFile, "Info")

	}
	if ipList == "" {
		// create temp directory
		rand.Seed(time.Now().UnixNano())
		randNum := rand.Int63n(8999999999)
		randNum += 1000000000
		tempDir = fmt.Sprintf("%s/active-ip-%d", os.TempDir(), randNum)
		if err := os.MkdirAll(tempDir, 0777); err != nil {
			printText(isSilent, "Unable to create temp directory", "Error")
		}
		// temp IP list
		ipList = fmt.Sprintf("%s/temp-ip-list.txt", tempDir)

	}

	// convert cidr or cidr list to ip list
	if cidr != "" {
		ok, hosts := cidrHosts(cidr)
		if !ok {
			printText(isSilent, "invalid cidr address", "Error")
			os.Exit(1)
		}
		output := strings.Join(hosts, "\n") + "\n"
		f, err := os.OpenFile(ipList, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			printText(isSilent, fmt.Sprintf("Error opening file: %v", err), "Error")
			return
		}
		defer f.Close()
		_, err = f.WriteString(output)
		if err != nil {
			printText(isSilent, fmt.Sprintf("Error writing to file: %v", err), "Error")
			return
		}
	}
	if cidrList != "" {
		file, err := os.Open(cidrList)
		if err != nil {
			printText(isSilent, fmt.Sprintf("Error opening file: %v", err), "Error")
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
					printText(isSilent, "there is invalid CIDR address in cidr-list", "Error")
					os.Exit(1)
				}
				output := strings.Join(hosts, "\n") + "\n"
				f, err := os.OpenFile(ipList, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
				if err != nil {
					printText(isSilent, fmt.Sprintf("Error opening file: %v", err), "Error")
					return
				}
				defer f.Close()
				_, err = f.WriteString(output)
				if err != nil {
					printText(isSilent, fmt.Sprintf("Error writing to file: %v", err), "Error")
					return
				}
			}(cidr)
		}
		wg.Wait()
		if err := scanner.Err(); err != nil {
			printText(isSilent, fmt.Sprintf("Error scanning file: %v", err), "Error")
		}
	}

	// Mode detection
	if pingMode && ptrMode && portscanMode {
		printText(isSilent, "Full technique ...", "Info")
		printText(isSilent, fmt.Sprintf("Used following port for portscan: %v", ports), "Info")
		if ip != "" {
			fullTechnique(ip, outputFile, pingTimeout, portscanTimeout, verbose, isSilent, ports)
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
				fullTechnique(line, outputFile, pingTimeout, portscanTimeout, verbose, isSilent, ports)

			}
		}
	} else if pingMode && portscanMode {
		printText(isSilent, "Ping and Portscan technique ...", "Info")
		printText(isSilent, fmt.Sprintf("Used following port for portscan: %v", ports), "Info")
		if ip != "" {
			pingAndPortscanTechnique(ip, outputFile, pingTimeout, portscanTimeout, verbose, isSilent, ports)

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
				pingAndPortscanTechnique(line, outputFile, pingTimeout, portscanTimeout, verbose, isSilent, ports)

			}
		}
	} else if pingMode && ptrMode {
		printText(isSilent, "Ping and PTR technique ...", "Info")
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
		printText(isSilent, "PTR and Portscan technique ...", "Info")
		printText(isSilent, fmt.Sprintf("Used following port for portscan: %v", ports), "Info")
		if ip != "" {
			ptrRecordAndPortscanTechnique(ip, outputFile, portscanTimeout, verbose, isSilent, ports)
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
				ptrRecordAndPortscanTechnique(line, outputFile, portscanTimeout, verbose, isSilent, ports)

			}
		}
	} else if ptrMode {
		printText(isSilent, "PTR technique ...", "Info")
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
		printText(isSilent, "Ping technique ...", "Info")
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
		printText(isSilent, "Portscan technique ...", "Info")
		printText(isSilent, fmt.Sprintf("Used following port for portscan: %v", ports), "Info")
		if ip != "" {
			if !portScan(ip, outputFile, portscanTimeout, verbose, ports) {
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

			// Read lines concurrently; each goroutine will pass the line to portScan()
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

			// Process the buffered lines using portScan() function
			for line := range bufferCh {
				if !portScan(line, outputFile, portscanTimeout, verbose, ports) {
					printText(isSilent, fmt.Sprintf("%s isn't active", line), "Info")
				}
			}
		}
	} else {
		printText(isSilent, "Full technique ...", "Info")
		printText(isSilent, fmt.Sprintf("Used following port for portscan: %v", ports), "Info")
		if ip != "" {
			fullTechnique(ip, outputFile, pingTimeout, portscanTimeout, verbose, isSilent, ports)
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
				fullTechnique(line, outputFile, pingTimeout, portscanTimeout, verbose, isSilent, ports)

			}
		}
	}
	printText(isSilent, "End, good bye:)", "Print")
	if tempDir != "" {
		os.Remove(tempDir)
	}
}

// Helper function to print the help menu
func printHelp() {
	fmt.Printf("Usage of the program: \n \nIP Address Options: \n \n    -i or --ip : Specify a single IP address to scan. \n \n    -I or --ip-list : Specify a list of IPs to scan. \n \n    -c or --cidr : Specify a single CIDR notation to scan (e.g. 192.168.0.0/24). \n \n    -C or --cidr-list : Specify a list of CIDR notations to scan. \n \nOutput Options: \n \n    -o or --output : Write output to a file instead of the terminal. \n \n    -v or --verbose : Enable verbose output to show the results of each technique used for scanning. \n \n    -s or --silent : Run the program silently and do not display any output. \n \n    -h or --help : Display this help menu. \n \nScanning Options:\n \n    -t or --threads : Specify number of threads to be used for scanning. Default is 5.\n\n    -p or --port : Specify a comma-separated list of ports to scan. Default ports are 80,443,22. \n \n    --ping-timeout : Set the timeout for ping scans in milliseconds. Default is 400ms. \n \n    --portscan-timeout : Set the timeout for port scans in milliseconds. Default is 400ms. \n \n    --full : Run complete mode, scanning for active IPs and open ports using all techniques. \n \n    --ping : Run only ping mode, scanning for active IPs. \n \n    --portscan : Run only portscan mode, scanning for open ports. \n \n    --ptr : Run PTR scan (reverse DNS lookup). \n \nNote: At least one IP option or CIDR option must be specified. Both options can be used simultaneously. The program will use default values for any unspecified options. \n \nExample usage: \n \n$ active-ip -i 192.168.0.1 -p 80,443 -v \n \nThis will scan the IP address 192.168.0.1 for open ports 80 and 443, and display verbose output.\n")
}
func showBanner(isSilent bool) {
	printText(isSilent, "            _   _             _       \n  __ _  ___| |_(_)_   _____  (_)_ __  \n / _` |/ __| __| \\ \\ / / _ \\ | | '_ \\ \n| (_| | (__| |_| |\\ V /  __/ | | |_) |\n \\__,_|\\___|\\__|_| \\_/ \\___| |_| .__/ \n                               |_| \n    Written by Ali Khalkhali\n    Github: https://github.com/Alikhalkhali/active-ip\n\n\n", "Print")
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

func portScan(target string, outputFile string, timeout time.Duration, verbose bool, ports []string) bool {
	openPorts := []int{}
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
func fullTechnique(ip string, outputFile string, pingTimeout time.Duration, portscanTimeout time.Duration, verbose bool, isSilent bool, ports []string) {
	if !hasPTRRecord(ip, outputFile, verbose, isSilent) {
		if !ping(ip, outputFile, pingTimeout, verbose) {
			if !portScan(ip, outputFile, portscanTimeout, verbose, ports) {
				printText(isSilent, fmt.Sprintf("%s isn't active", ip), "Info")
			}
		}
	}
}
func pingAndPortscanTechnique(ip string, outputFile string, pingTimeout time.Duration, portscanTimeout time.Duration, verbose bool, isSilent bool, ports []string) {
	if !ping(ip, outputFile, pingTimeout, verbose) {
		if !portScan(ip, outputFile, portscanTimeout, verbose, ports) {
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
func ptrRecordAndPortscanTechnique(ip string, outputFile string, portscanTimeout time.Duration, verbose bool, isSilent bool, ports []string) {
	if !hasPTRRecord(ip, outputFile, verbose, isSilent) {
		if !portScan(ip, outputFile, portscanTimeout, verbose, ports) {
			printText(isSilent, fmt.Sprintf("%s isn't active", ip), "Info")
		}
	}
}
