# DeadSocket - Asynchronous Network Stress Testing Tool

## Description
DeadSocket (`deadsocket.py`) is a versatile asynchronous network stress testing tool designed to evaluate the performance and resilience of web servers and network services. It supports various test types including HTTP GET/POST/PUT requests, TCP connections, ICMP echo requests, and TCP SYN floods. The tool leverages `asyncio` and `aiohttp` for high-concurrency testing.

## ASCII Banner
```
 ____                 _ ____            _        _   
|  _ \  ___  __ _  __| / ___|  ___   ___| | _____| |_ 
| | | |/ _ \/ _` |/ _` \___ \ / _ \ / __| |/ / _ \ __|
| |_| |  __/ (_| | (_| |___) | (_) | (__|   <  __/ |_ 
|____/ \___|\__,_|\__,_|____/ \___/ \___|_|\_\___|\__|
```

## Features
- **Configurable Parameters**: Easily adjust test parameters like target host, number of requests, and concurrency via command-line arguments.
- **Duration-based Testing**: Run tests for a specified duration rather than a fixed number of requests.
- **HTTP Method & Payload Support**: Specify HTTP methods (GET, POST, PUT, etc.) and include custom payloads for HTTP requests.
- **Custom Request Headers**: Add arbitrary HTTP headers to your requests.
- **Detailed Reporting**: Generate comprehensive reports in console, CSV, or JSON formats.
- **Enhanced Error Handling**: Reports include HTTP status breakdowns and error type counts.
- **Target Lists**: Provide a file with multiple targets and distribute requests across them.
- **Keep-Alive Control**: Optionally disable HTTP keep-alive to force new connections per request.
- **Random User Agents**: Requests are sent with a rotating list of user agents to simulate diverse client traffic.
- **Customizable ASCII Art**: The startup ASCII art can be customized by editing the `ascii_art.txt` file.
- **Multiple Test Types**:
    - **HTTP**: Stress test web servers with configurable methods and payloads.
    - **TCP**: Test raw TCP connection handling.
    - **ICMP**: Perform basic ping-like tests.
    - **SYN Flood**: Simulate a SYN flood attack (requires root/sudo for raw sockets).
    - **UDP**: Send UDP packets to a target host and port.
    - **RUDY**: Simulate a slow POST (RUDY) attack with configurable body size, chunk size, and delay.

## Installation
To run `deadsocket.py`, you need Python 3.7+ and the following libraries:

```bash
pip install aiohttp scapy
```

**Note**: For ICMP and SYN flood tests, `scapy` requires raw socket access, which typically means running the script with `sudo` or appropriate permissions.

## Usage

```bash
python deadsocket.py --help
```

```
usage: deadsocket.py [-h] --test_type {http,tcp,icmp,syn,udp,rudy} --target_host TARGET_HOST [--target_list TARGET_LIST] [--target_port TARGET_PORT] [--num_requests NUM_REQUESTS] [--duration DURATION] [--concurrency CONCURRENCY] [--method METHOD] [--payload PAYLOAD] [--rudy_body_size RUDY_BODY_SIZE] [--rudy_chunk_size RUDY_CHUNK_SIZE] [--rudy_delay RUDY_DELAY] [--headers HEADERS] [--no_keep_alive] [--timeout TIMEOUT] [--verbose] [--output_format {console,csv,json}] [--output_file OUTPUT_FILE]

DeadSocket - Asynchronous Network Test Script

options:
  -h, --help            show this help message and exit
  --test_type {http,tcp,icmp,syn,udp,rudy}
                        Type of test to perform
  --target_host TARGET_HOST
                        Target URL (for HTTP/RUDY) or IP address (for TCP, ICMP, SYN, UDP)
  --target_list TARGET_LIST
                        Path to a file with one target per line
  --target_port TARGET_PORT
                        Target port (for TCP, SYN, and optional for HTTP, UDP)
  --num_requests NUM_REQUESTS
                        Number of requests or connections to send (ignored if --duration is set)
  --duration DURATION   Duration of the test in seconds (overrides --num_requests)
  --concurrency CONCURRENCY
                        Number of concurrent requests or connections
  --method METHOD       HTTP method for HTTP tests (e.g., GET, POST, PUT)
  --payload PAYLOAD     Payload for HTTP POST/PUT requests
  --rudy_body_size RUDY_BODY_SIZE
                        Total bytes to send per RUDY connection
  --rudy_chunk_size RUDY_CHUNK_SIZE
                        Bytes per chunk for RUDY slow POST
  --rudy_delay RUDY_DELAY
                        Delay in seconds between RUDY chunks
  --headers HEADERS     Custom HTTP headers in key:value;key2:value2 format
  --no_keep_alive       Disable HTTP keep-alive (force new connection per request)
  --timeout TIMEOUT     Total timeout in seconds for HTTP/RUDY requests
  --verbose             Enable verbose logging
  --output_format {console,csv,json}
                        Output format for the report
  --output_file OUTPUT_FILE
                        File path to save the report
```

## Examples
See `EXAMPLES.md` for copy/paste‑ready examples with explicit flags.

### HTTP GET Request
Perform 100 HTTP GET requests to example.com with 10 concurrent connections.
```bash
python deadsocket.py --test_type http --target_host https://example.com --num_requests 100 --concurrency 10
```

### HTTP POST Request with Payload
Send 50 HTTP POST requests to an API endpoint with a JSON payload, 5 concurrent connections.
```bash
python deadsocket.py --test_type http --target_host https://api.example.com/data --num_requests 50 --concurrency 5 --method POST --payload '{"key": "value"}'
```

### TCP Connection Test
Establish 200 TCP connections to a server on port 8080 with 20 concurrent connections.
```bash
python deadsocket.py --test_type tcp --target_host 192.168.1.1 --target_port 8080 --num_requests 200 --concurrency 20
```

### ICMP Echo Test (Ping)
Send 10 ICMP echo requests to a host.
```bash
sudo python deadsocket.py --test_type icmp --target_host 8.8.8.8 --num_requests 10
```

### TCP SYN Flood (Requires sudo)
Send 500 TCP SYN packets to a target on port 80.
```bash
sudo python deadsocket.py --test_type syn --target_host 192.168.1.100 --target_port 80 --num_requests 500
```

### UDP Packet Test
Send 100 UDP packets to a target on port 1234 with 10 concurrent connections.
```bash
python deadsocket.py --test_type udp --target_host 192.168.1.100 --target_port 1234 --num_requests 100 --concurrency 10
```

### RUDY Slow POST Test
Send slow POST requests to keep connections open with a 1 MB body sent in 10-byte chunks every 0.5s.
```bash
python deadsocket.py --test_type rudy --target_host https://example.com/upload --num_requests 20 --concurrency 5 --rudy_body_size 1048576 --rudy_chunk_size 10 --rudy_delay 0.5
```

### Target List Example
Distribute HTTP requests across multiple targets listed in a file (one per line).
```bash
python deadsocket.py --test_type http --target_host https://example.com --target_list targets.txt --num_requests 100 --concurrency 10
```
