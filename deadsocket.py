#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import random
import logging
import socket
from aiohttp import ClientError, ClientSession, ClientTimeout, TCPConnector
from scapy.all import sr1, IP, ICMP, TCP, send
from urllib.parse import urlparse

# ASCII Art Section
try:
    with open("ascii_art.txt", "r") as f:
        ASCII_ART = f.read()
except FileNotFoundError:
    ASCII_ART = r"""

 ____                 _ ____            _        _   
|  _ \  ___  __ _  __| / ___|  ___   ___| | _____| |_ 
| | | |/ _ \/ _` |/ _` \___ \ / _ \ / __| |/ / _ \ __|
| |_| |  __/ (_| | (_| |___) | (_) | (__|   <  __/ |_ 
|____/ \___|\__,_|\__,_|____/ \___/ \___|_|\_\___|\__|

"""
print(ASCII_ART)

# User Agents List
user_agents = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6)...",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.164 Mobile Safari/537.36",
]

# Configure logging
logger = logging.getLogger(__name__)


def configure_logging(verbose=False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )


def get_random_user_agent():
    return random.choice(user_agents)


import time
import itertools

async def fetch_url(session: ClientSession, url: str, headers: dict, results: list, method: str, payload: str = None):
    start_time = time.time()
    try:
        async with session.request(method, url, headers=headers, data=payload) as response:
            logger.info(f"Request to {url} returned {response.status}")
            await response.read()
            if response.status >= 400:
                results.append({"success": False, "status": response.status, "error_type": "http_status", "time": time.time() - start_time})
            else:
                results.append({"success": True, "status": response.status, "time": time.time() - start_time})
    except asyncio.TimeoutError as e:
        logger.error(f"Request to {url} timed out: {e}")
        results.append({"success": False, "error": "timeout", "error_type": "timeout", "time": time.time() - start_time})
    except ClientError as e:
        logger.error(f"Request to {url} failed: {e}")
        results.append({"success": False, "error": str(e), "error_type": "client_error", "time": time.time() - start_time})
    except Exception as e:
        logger.error(f"Request to {url} failed: {e}")
        results.append({"success": False, "error": str(e), "error_type": "exception", "time": time.time() - start_time})


async def async_https_get_request(target_urls, num_requests, headers, concurrency, method: str, payload: str = None, duration: int = None, keep_alive: bool = True, timeout: float = None):
    results = []
    client_timeout = ClientTimeout(total=timeout) if timeout else None
    connector = TCPConnector(force_close=not keep_alive)
    async with ClientSession(connector=connector, timeout=client_timeout) as session:
        semaphore = asyncio.Semaphore(concurrency)
        tasks = set()
        start_time = time.time()
        url_cycle = itertools.cycle(target_urls)

        if duration:
            while True:
                elapsed_time = time.time() - start_time
                if elapsed_time >= duration:
                    break
                target_url = next(url_cycle)
                task = asyncio.create_task(fetch_url_with_semaphore(session, target_url, headers, semaphore, results, method, payload))
                tasks.add(task)
                # Remove completed tasks to prevent memory leak
                tasks = {t for t in tasks if not t.done()}
                await asyncio.sleep(0.001) # Small sleep to prevent busy-waiting
        else:
            for _ in range(num_requests):
                target_url = next(url_cycle)
                task = asyncio.create_task(fetch_url_with_semaphore(session, target_url, headers, semaphore, results, method, payload))
                tasks.add(task)

        # Wait for all remaining tasks to complete
        if tasks:
            await asyncio.gather(*tasks)
    return results

async def fetch_url_with_semaphore(session: ClientSession, url: str, headers: dict, semaphore: asyncio.Semaphore, results: list, method: str, payload: str = None):
    async with semaphore:
        await fetch_url(session, url, headers, results, method, payload)

async def async_rudy_test(target_urls, num_requests, headers, concurrency, body_size, chunk_size, delay, duration: int = None, keep_alive: bool = True, timeout: float = None):
    results = []
    connector = TCPConnector(force_close=not keep_alive)
    rudy_timeout = ClientTimeout(total=timeout) if timeout else ClientTimeout(
        total=(max(1, (body_size + chunk_size - 1) // chunk_size) * delay) + 5
    )
    async with ClientSession(connector=connector, timeout=rudy_timeout) as session:
        semaphore = asyncio.Semaphore(concurrency)
        tasks = set()
        start_time = time.time()
        url_cycle = itertools.cycle(target_urls)

        if duration:
            while True:
                elapsed_time = time.time() - start_time
                if elapsed_time >= duration:
                    break
                target_url = next(url_cycle)
                task = asyncio.create_task(rudy_request_with_semaphore(
                    session, target_url, headers, semaphore, results, body_size, chunk_size, delay
                ))
                tasks.add(task)
                tasks = {t for t in tasks if not t.done()}
                await asyncio.sleep(0.001)
        else:
            for _ in range(num_requests):
                target_url = next(url_cycle)
                task = asyncio.create_task(rudy_request_with_semaphore(
                    session, target_url, headers, semaphore, results, body_size, chunk_size, delay
                ))
                tasks.add(task)

        if tasks:
            await asyncio.gather(*tasks)
    return results

async def rudy_request_with_semaphore(session: ClientSession, url: str, headers: dict, semaphore: asyncio.Semaphore, results: list, body_size: int, chunk_size: int, delay: float):
    async with semaphore:
        await slow_post_request(session, url, headers, results, body_size, chunk_size, delay)

async def slow_post_request(session: ClientSession, url: str, headers: dict, results: list, body_size: int, chunk_size: int, delay: float):
    start_time = time.time()
    request_headers = dict(headers)
    request_headers["Content-Length"] = str(body_size)

    async def slow_body():
        sent = 0
        while sent < body_size:
            remaining = body_size - sent
            payload_size = chunk_size if remaining > chunk_size else remaining
            sent += payload_size
            yield b"a" * payload_size
            await asyncio.sleep(delay)

    try:
        async with session.post(url, headers=request_headers, data=slow_body()) as response:
            await response.read()
            if response.status >= 400:
                results.append({"success": False, "status": response.status, "error_type": "http_status", "time": time.time() - start_time})
            else:
                results.append({"success": True, "status": response.status, "time": time.time() - start_time})
    except ClientError as e:
        logger.error(f"RUDY request to {url} failed: {e}")
        results.append({"success": False, "error": str(e), "error_type": "client_error", "time": time.time() - start_time})
    except asyncio.TimeoutError as e:
        logger.error(f"RUDY request to {url} timed out: {e}")
        results.append({"success": False, "error": "timeout", "error_type": "timeout", "time": time.time() - start_time})
    except Exception as e:
        logger.error(f"RUDY request to {url} failed: {e}")
        results.append({"success": False, "error": str(e), "error_type": "exception", "time": time.time() - start_time})


async def async_tcp_test(target_hosts, target_port, num_connections, concurrency, duration: int = None):
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    tasks = set()
    start_time = time.time()
    host_cycle = itertools.cycle(target_hosts)

    if duration:
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time >= duration:
                break
            target_host = next(host_cycle)
            task = asyncio.create_task(tcp_connection_with_semaphore(target_host, target_port, semaphore, results))
            tasks.add(task)
            tasks = {t for t in tasks if not t.done()}
            await asyncio.sleep(0.001)
    else:
        for _ in range(num_connections):
            target_host = next(host_cycle)
            task = asyncio.create_task(tcp_connection_with_semaphore(target_host, target_port, semaphore, results))
            tasks.add(task)

    if tasks:
        await asyncio.gather(*tasks)
    return results

async def async_udp_test(target_hosts, target_port, num_requests, concurrency, duration: int = None):
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    tasks = set()
    start_time = time.time()
    host_cycle = itertools.cycle(target_hosts)

    if duration:
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time >= duration:
                break
            target_host = next(host_cycle)
            task = asyncio.create_task(send_udp_packet_with_semaphore(target_host, target_port, semaphore, results))
            tasks.add(task)
            tasks = {t for t in tasks if not t.done()}
            await asyncio.sleep(0.001)
    else:
        for _ in range(num_requests):
            target_host = next(host_cycle)
            task = asyncio.create_task(send_udp_packet_with_semaphore(target_host, target_port, semaphore, results))
            tasks.add(task)

    if tasks:
        await asyncio.gather(*tasks)
    return results

async def send_udp_packet_with_semaphore(target_host, target_port, semaphore: asyncio.Semaphore, results: list):
    async with semaphore:
        await send_udp_packet(target_host, target_port, results)

async def tcp_connection_with_semaphore(target_host, target_port, semaphore: asyncio.Semaphore, results: list):
    async with semaphore:
        await tcp_connection(target_host, target_port, results)


async def tcp_connection(target_host, target_port, results: list):
    start_time = time.time()
    try:
        reader, writer = await asyncio.open_connection(target_host, target_port)
        logger.info(f"Connected to TCP {target_host}:{target_port}")
        writer.close()
        await writer.wait_closed()
        results.append({"success": True, "time": time.time() - start_time})
    except Exception as e:
        logger.error(f"TCP connection to {target_host}:{target_port} failed: {e}")
        results.append({"success": False, "error": str(e), "error_type": "exception", "time": time.time() - start_time})

async def send_udp_packet(target_host, target_port, results: list):
    start_time = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(b"hello", (target_host, target_port))
        sock.close()
        logger.info(f"Sent UDP packet to {target_host}:{target_port}")
        results.append({"success": True, "time": time.time() - start_time})
    except Exception as e:
        logger.error(f"UDP packet to {target_host}:{target_port} failed: {e}")
        results.append({"success": False, "error": str(e), "error_type": "exception", "time": time.time() - start_time})


def send_icmp_echo(target_host, num_requests):
    for _ in range(num_requests):
        packet = IP(dst=target_host) / ICMP()
        resp = sr1(packet, timeout=1, verbose=0)
        if resp:
            logger.info(f"ICMP Reply from {target_host}: {resp.summary()}")
        else:
            logger.info(f"No ICMP Reply from {target_host}")


def send_tcp_syn(target_host, target_port, num_requests):
    for _ in range(num_requests):
        syn_packet = IP(dst=target_host) / TCP(dport=target_port, flags="S")
        resp = sr1(syn_packet, timeout=1, verbose=0)
        if resp and resp.getlayer(TCP).flags & 0x12:  # SYN/ACK flags
            logger.info(f"Received SYN/ACK from {target_host}:{target_port}")
            # Properly tear down the connection by sending a RST packet
            rst_packet = IP(dst=target_host) / TCP(
                dport=target_port, flags="R", seq=resp.ack
            )
            send(rst_packet, verbose=0)
        else:
            logger.info(f"No SYN/ACK from {target_host}:{target_port}")


def validate_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception as e:
        logger.error(f"URL validation error: {e}")
        return False


def validate_ip(ip_address):
    try:
        socket.inet_aton(ip_address)
        return True
    except socket.error as e:
        logger.error(f"IP validation error: {e}")
        return False


def parse_custom_headers(headers_string):
    headers = {}
    if headers_string:
        pairs = headers_string.split(';')
        for pair in pairs:
            if ':' in pair:
                key, value = pair.split(':', 1)
                headers[key.strip()] = value.strip()
    return headers

def parse_target_list(target_list_path):
    targets = []
    try:
        with open(target_list_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                targets.append(line)
    except OSError as e:
        logger.error(f"Could not read target list file {target_list_path}: {e}")
    return targets

def apply_port_to_url(url, target_port):
    if not target_port:
        return url
    parsed_url = urlparse(url)
    if not parsed_url.hostname:
        return url
    netloc_with_port = f"{parsed_url.hostname}:{target_port}"
    return parsed_url._replace(netloc=netloc_with_port).geturl()

def parse_args():
    parser = argparse.ArgumentParser(description="DeadSocket - Asynchronous Network Test Script")
    parser.add_argument("--test_type", required=True, choices=["http", "tcp", "icmp", "syn", "udp", "rudy"], help="Type of test to perform")
    parser.add_argument("--target_host", required=True, help="Target URL (for HTTP/RUDY) or IP address (for TCP, ICMP, SYN)")
    parser.add_argument("--target_list", type=str, help="Path to a file with one target per line")
    parser.add_argument("--target_port", type=int, help="Target port (for TCP, SYN, and optional for HTTP)")
    parser.add_argument("--num_requests", type=int, default=1, help="Number of requests or connections to send (ignored if --duration is set)")
    parser.add_argument("--duration", type=int, help="Duration of the test in seconds (overrides --num_requests)")
    parser.add_argument("--concurrency", type=int, default=1, help="Number of concurrent requests or connections")
    parser.add_argument("--method", type=str, default="GET", help="HTTP method for HTTP tests (e.g., GET, POST, PUT)")
    parser.add_argument("--payload", type=str, help="Payload for HTTP POST/PUT requests")
    parser.add_argument("--rudy_body_size", type=int, default=1024 * 1024, help="Total bytes to send per RUDY connection")
    parser.add_argument("--rudy_chunk_size", type=int, default=10, help="Bytes per chunk for RUDY slow POST")
    parser.add_argument("--rudy_delay", type=float, default=0.5, help="Delay in seconds between RUDY chunks")
    parser.add_argument("--headers", type=str, help="Custom HTTP headers in key:value;key2:value2 format")
    parser.add_argument("--no_keep_alive", action="store_true", help="Disable HTTP keep-alive (force new connection per request)")
    parser.add_argument("--timeout", type=float, help="Total timeout in seconds for HTTP/RUDY requests")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--output_format", type=str, choices=["console", "csv", "json"], default="console", help="Output format for the report")
    parser.add_argument("--output_file", type=str, help="File path to save the report")
    return parser.parse_args()


import json
import csv

def generate_and_print_report(results: list, test_type: str, output_format: str = "console", output_file: str = None):
    total_requests = len(results)
    successful_requests = sum(1 for r in results if r["success"])
    failed_requests = total_requests - successful_requests
    total_time = sum(r["time"] for r in results)
    average_time = total_time / total_requests if total_requests > 0 else 0

    report_data = {
        "total_requests": total_requests,
        "successful_requests": successful_requests,
        "failed_requests": failed_requests,
        "total_time": total_time,
        "average_response_time": average_time,
    }

    if test_type in ("HTTP", "RUDY") and failed_requests > 0:
        status_code_counts = {}
        for r in results:
            if not r["success"] and "status" in r:
                status_code_counts[r["status"]] = status_code_counts.get(r["status"], 0) + 1
        if status_code_counts:
            report_data["http_error_status_code_breakdown"] = status_code_counts
    if failed_requests > 0:
        error_type_counts = {}
        for r in results:
            if not r["success"] and "error_type" in r:
                error_type_counts[r["error_type"]] = error_type_counts.get(r["error_type"], 0) + 1
        if error_type_counts:
            report_data["error_type_breakdown"] = error_type_counts

    if output_format == "console":
        print(f"\n--- {test_type} Test Report ---")
        print(f"Total Requests: {report_data['total_requests']}")
        print(f"Successful Requests: {report_data['successful_requests']}")
        print(f"Failed Requests: {report_data['failed_requests']}")

        if "http_error_status_code_breakdown" in report_data:
            print("\nHTTP Error Status Code Breakdown:")
            for status_code, count in sorted(report_data["http_error_status_code_breakdown"].items()):
                print(f"  Status {status_code}: {count} requests")

        if "error_type_breakdown" in report_data:
            print("\nError Type Breakdown:")
            for error_type, count in sorted(report_data["error_type_breakdown"].items()):
                print(f"  {error_type}: {count} requests")

        print(f"Total Time: {report_data['total_time']:.2f} seconds")
        print(f"Average Response Time: {report_data['average_response_time']:.4f} seconds")
        print("---------------------------")
    elif output_file:
        try:
            with open(output_file, 'w') as f:
                if output_format == "json":
                    json.dump(report_data, f, indent=4)
                elif output_format == "csv":
                    # For CSV, we'll simplify and just write the main stats
                    # More complex CSV for status codes would require more logic
                    writer = csv.writer(f)
                    writer.writerow(["Metric", "Value"])
                    for key, value in report_data.items():
                        if isinstance(value, dict): # Skip nested dicts for simple CSV
                            continue
                        writer.writerow([key, value])
            logger.info(f"Report saved to {output_file} in {output_format} format.")
        except IOError as e:
            logger.error(f"Could not write report to file {output_file}: {e}")

async def main():

    args = parse_args()
    configure_logging(args.verbose)
    headers = {"User-Agent": get_random_user_agent()}
    if args.headers:
        custom_headers = parse_custom_headers(args.headers)
        headers.update(custom_headers)

    if args.timeout is not None and args.timeout <= 0:
        logger.error("Timeout must be a positive number of seconds.")
        return

    target_list = []
    if args.target_list:
        target_list = parse_target_list(args.target_list)
        if not target_list:
            logger.error("Target list is empty or could not be read.")
            return

    print(ASCII_ART)

    if args.test_type == "http":
        target_urls = target_list if target_list else [args.target_host]
        target_urls = [apply_port_to_url(url, args.target_port) for url in target_urls]
        invalid_urls = [url for url in target_urls if not validate_url(url)]
        if invalid_urls:
            logger.error(f"Invalid URL format: {', '.join(invalid_urls)}")
            return
        results = await async_https_get_request(
            target_urls,
            args.num_requests,
            headers,
            args.concurrency,
            args.method,
            args.payload,
            args.duration,
            keep_alive=not args.no_keep_alive,
            timeout=args.timeout,
        )
        generate_and_print_report(results, "HTTP", args.output_format, args.output_file)
    elif args.test_type == "rudy":
        target_urls = target_list if target_list else [args.target_host]
        target_urls = [apply_port_to_url(url, args.target_port) for url in target_urls]
        invalid_urls = [url for url in target_urls if not validate_url(url)]
        if invalid_urls:
            logger.error(f"Invalid URL format: {', '.join(invalid_urls)}")
            return
        if args.rudy_body_size <= 0 or args.rudy_chunk_size <= 0 or args.rudy_delay < 0:
            logger.error("RUDY parameters must be positive values.")
            return
        results = await async_rudy_test(
            target_urls,
            args.num_requests,
            headers,
            args.concurrency,
            args.rudy_body_size,
            args.rudy_chunk_size,
            args.rudy_delay,
            args.duration,
            keep_alive=not args.no_keep_alive,
            timeout=args.timeout,
        )
        generate_and_print_report(results, "RUDY", args.output_format, args.output_file)
    elif args.test_type == "tcp":
        target_hosts = target_list if target_list else [args.target_host]
        invalid_hosts = [host for host in target_hosts if not validate_ip(host)]
        if invalid_hosts:
            logger.error(f"Invalid IP address format: {', '.join(invalid_hosts)}")
            return
        results = await async_tcp_test(target_hosts, args.target_port, args.num_requests, args.concurrency, args.duration)
        generate_and_print_report(results, "TCP", args.output_format, args.output_file)
    elif args.test_type == "udp":
        target_hosts = target_list if target_list else [args.target_host]
        invalid_hosts = [host for host in target_hosts if not validate_ip(host)]
        if invalid_hosts:
            logger.error(f"Invalid IP address format: {', '.join(invalid_hosts)}")
            return
        if not args.target_port:
            logger.error("Target port is required for UDP tests.")
            return
        results = await async_udp_test(target_hosts, args.target_port, args.num_requests, args.concurrency, args.duration)
        generate_and_print_report(results, "UDP", args.output_format, args.output_file)
    elif args.test_type == "icmp":
        target_hosts = target_list if target_list else [args.target_host]
        invalid_hosts = [host for host in target_hosts if not validate_ip(host)]
        if invalid_hosts:
            logger.error(f"Invalid IP address format: {', '.join(invalid_hosts)}")
            return
        host_cycle = itertools.cycle(target_hosts)
        for _ in range(args.num_requests):
            send_icmp_echo(next(host_cycle), 1)
    elif args.test_type == "syn":
        target_hosts = target_list if target_list else [args.target_host]
        invalid_hosts = [host for host in target_hosts if not validate_ip(host)]
        if invalid_hosts:
            logger.error(f"Invalid IP address format: {', '.join(invalid_hosts)}")
            return
        host_cycle = itertools.cycle(target_hosts)
        for _ in range(args.num_requests):
            send_tcp_syn(next(host_cycle), args.target_port, 1)


if __name__ == "__main__":
    asyncio.run(main())
