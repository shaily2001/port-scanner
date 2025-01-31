import sys
import socket
import time
from argparse import ArgumentParser
from threading import Thread, Lock
from queue import Queue

# Global list to store open ports (protected by a lock)
open_ports = []
lock = Lock()

def prepare_args():
    """Parses command-line arguments and ensures validity."""
    if len(sys.argv) == 1:  # No arguments provided (likely running in IDLE)
        sys.argv.append("127.0.0.1")  # Default IP for testing

    parser = ArgumentParser(
        description="Python-based fast port scanner",
        usage="%(prog)s 192.168.1.2",
        epilog="Example - %(prog)s -s 20 -e 40000 -t 500 -V 192.168.1.2",
    )
    parser.add_argument("ip", metavar="IPv4", help="Host to scan")
    parser.add_argument("-s", "--start", metavar="", type=int, help="Starting port", default=1)
    parser.add_argument("-e", "--end", metavar="", type=int, help="Ending port", default=65535)
    parser.add_argument("-t", "--threads", metavar="", type=int, help="Threads to use", default=500)
    parser.add_argument("-V", "--verbose", action="store_true", help="Verbose output", default=False)
    parser.add_argument("-v", "--version", action="version", version="%(prog)s 1.0", help="Display version")
    
    args = parser.parse_args()

    # Validate port range
    if args.start > args.end:
        parser.error("Starting port must be less than or equal to the ending port.")

    return args

def prepare_port_queue(start: int, end: int):
    """Creates a queue of ports for scanning."""
    q = Queue()
    for port in range(start, end + 1):
        q.put(port)
    return q

def get_service_name(port):
    """Returns the service name for the given port number, or 'unknown' if not found."""
    try:
        return socket.getservbyport(port)
    except OSError:
        return "unknown"

def scan_port(ip, port_queue, verbose, retries=3):
    """Scans ports from the queue and checks for open ones."""
    while not port_queue.empty():
        port = port_queue.get()
        attempt = 0
        success = False
        while attempt < retries:
            try:
                s = socket.socket()
                s.settimeout(0.5)  # 0.5 second timeout for faster results
                s.connect((ip, port))
                with lock:
                    service = get_service_name(port)
                    open_ports.append((port, service))
                success = True
                break  # Exit loop on successful connection
            except (ConnectionRefusedError, socket.timeout):
                attempt += 1
            except Exception as e:
                break  # Exit if any other exception occurs
            finally:
                s.close()

        if success:
            port_queue.task_done()  # Mark the task as done only after successful connection
        else:
            port_queue.task_done()  # Ensure task_done is called even when failing

def prepare_threads(ip, port_queue, threads: int, verbose):
    """Creates and starts threads for parallel port scanning."""
    thread_list = []
    for _ in range(threads):
        thread = Thread(target=scan_port, args=(ip, port_queue, verbose))
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()
    for thread in thread_list:
        thread.join()

def print_results():
    """Prints open ports in the desired format."""
    print(f"{'PORT':<10}{'STATE':<10}{'SERVICE':<20}")
    for port, service in open_ports:
        print(f"{port}/tcp  open      {service}")

if __name__ == "__main__":
    arguments = prepare_args()
    port_queue = prepare_port_queue(arguments.start, arguments.end)

    start_time = time.time()
    prepare_threads(arguments.ip, port_queue, arguments.threads, arguments.verbose)
    end_time = time.time()

    if arguments.verbose:
        print()  # New line after verbose output

    print_results()  # Display the open ports in the desired format
    print(f"\nTime Taken - {round(end_time - start_time, 2)} seconds")
