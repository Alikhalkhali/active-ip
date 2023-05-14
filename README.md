<h2 align="center" >
  Table of Contents 
</h2>
<p align="center">
  <a href="#installation">installation</a> •
  <a href="#usage">usage</a> •
  <a href="#scanning-options">scanning options</a> •
  <a href="#output-options">output options</a> •
  <a href="#contributing">contributing</a> •
  <a href="#license">license</a> •
   <a href="#contact">contact</a> •
  </p>

# Active-IP

Active-IP is a command-line tool written in Go for scanning IP addresses, CIDR notations that extracts live IP addresses from a list of IP addresses or CIDR notations. It supports multiple scanning techniques and output options for flexibility and customization.

## Installation

To install Active-IP, you will need to have Go installed on your system. Then, run the following command:

```bash
go install github.com/Alikhalkhali/active-ip@latest
```

This will download and install the tool and its dependencies.

## Usage

Active-IP is a powerful tool that enables you to customize your scans in many ways. Here are some examples:

### Note 
- If you are using a Unix-based operating system, run the tool with a sudoer user, root, or using the sudo command.
- If you do not set the scanning technique flags, it will use the full technique, which includes port scanning, ping scanning (using ICMP), and PTR scanning. If you explicitly set all three scanning techniques, it will also use the full technique.

### Basic Usage

The most basic usage of Active-IP is to scan a single IP address for open ports:

```
active-ip -i <ip-address>
```

### Advanced Usage

Active-IP supports a wide range of options to help you customize your scans. For example, you can scan multiple IP addresses or CIDR notations at once:

```
# Scan multiple IP addresses 
active-ip -I ./ip-list.txt

# Scan multiple CIDR notations
active-ip -C ./cidr-list.txt
```

You can also specify a custom list of ports to scan:

```
active-ip -i <ip-address> -p 80,443,8080
```

Active-IP supports multithreaded scanning for faster results. You can specify the number of threads to use with the `-t` option:

```
active-ip -i <ip-address> -t 10
```

### Full Scanning Mode

Active-IP provides a full scanning mode that combines multiple scanning techniques to provide a comprehensive overview of your network:

```
active-ip --full 
```

This will scan for active IP addresses and open ports using all available techniques.

### Ping Scanning

Active-IP supports ping scanning to find active IP addresses:

```
active-ip --ping 
```

### Port Scanning

Active-IP supports port scanning to find open ports:

```
active-ip --portscan
```

### PTR Scan

Active-IP supports PTR scanning to perform reverse DNS lookups:

```
active-ip --ptr
```

### Combine different scanning techniques

You can also combine different scanning techniques to get more comprehensive results. For example, you can combine ping scanning with port scanning to find active IP addresses with open ports:

```
active-ip --ping --portscan
```

Or you can combine PTR scanning with ping scanning to perform reverse DNS lookups on active IP addresses:

```
active-ip --ptr --ping
```

Experiment with different combinations to find the scanning technique that best suits your needs.

## Scanning Options

Active-IP provides several options to customize your scans:

- `-i` or `--ip` : Specify a single IP address to scan.
- `-I` or `--ip-list` : Specify a list of IP addresses to scan.
- `-c` or `--cidr` : Specify a single CIDR notation to scan (e.g. 192.168.0.0/24).
- `-C` or `--cidr-list` : Specify a list of CIDR notations to scan.
- `-t` or `--threads` : Specify the number of threads to use for scanning. Default is 5.
- `-p` or `--port` : Specify a comma-separated list of ports to scan. Default ports are 80,443,22.
- `--ping-timeout` : Set the timeout for ping scans in milliseconds. Default is 400ms.
- `--portscan-timeout` : Set the timeout for port scans in milliseconds. Default is 400ms.

Note: At least one IP option or CIDR option must be specified. Both options can be used simultaneously. The program will use default values for any unspecified options.

## Output Options

Active-IP provides several options for customizing output:

- `-o` or `--output` : Write output to a file instead of the terminal.
- `-v` or `--verbose` : Enable verbose output to show the results of each technique used for scanning.
- `-s` or `--silent` : Run the program silently and do not display any output.

## Contributing

If you would like to contribute to this project, please fork the repository and submit a pull request.

## License

This project is licensed under the MIT license. See the LICENSE file for details.

## Contact

If you have any questions or concerns, please feel free to contact me directly on social media:

- Twitter: [ali_khalkhali0](https://twitter.com/ali_khalkhali0)
- Instagram: [ali_khalkhali0](https://instagram.com/ali_khalkhali0)

I am always happy to hear from you and will do my best to respond to your questions as soon as possible.

