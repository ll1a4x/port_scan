#!/usr/bin/python3

# Script filename: port_scan.py
# Author: Lynden L.
# GitHub: github.com/ll1a4x/port_scan
# Description: 
# This is a python3 script that scans a host IP's
# all ports by multithreading and print open
# ports. This is particularly useful for quick 
# scanning on the pivot host during the lateral 
# movement.

import socket
import threading
import sys
from queue import Queue
from datetime import datetime

def print_banners():
	print("=" * 50)
	print("Script filename: port_scan.py")
	print("Author: Lynden L.")
	print("GitHub: github.com/ll1a4x/port_scan")
	print("Description:")
	print("This is a python3 script that scans a host IP's")
	print("all ports by multithreading and print open")
	print("ports. This is particularly useful for quick")
	print("scanning on the pivot host during the lateral")
	print("movement.")
	print("=" * 50)

def getInputs():
	if len(sys.argv) != 3:
		print("USAGE: ./port_scan.py TARGET_HOST THREAD_NUM")
		print("Recommended THREAD_NUM: 200")
		sys.exit()
		
	target = sys.argv[1]
	thread_num = int(sys.argv[2])
	try:
		target_ip = socket.gethostbyname(target)
	except (UnboundLocalError, socket.gaierror):
		print("\n****IP is invalid. Please enter a valid IP.*****\n")
		sys.exit()
	
	return target_ip, thread_num
	
def beginTiming(target_ip):
	print("Scanning target IP: "+ target_ip)
	print("Time started: "+ str(datetime.now()))
	time_start = datetime.now()
	return time_start

def portscan_multithreads(open_ports, target_ip, thread_num):
	socket.setdefaulttimeout(0.60)
	print_lock = threading.Lock()
      
	ports_queue = Queue()
	 
	for x in range(thread_num):
		t = threading.Thread(target=portscan_thread, args=(open_ports, target_ip, print_lock, ports_queue))
		t.daemon = True
		t.start()
	
	for port in range(1, 65536):
		ports_queue.put(port)

	ports_queue.join()

def portscan_thread(open_ports, target_ip, print_lock, ports_queue):
	while True:
		port = ports_queue.get()
		
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		try:
			portx = s.connect((target_ip, port))
			with print_lock:
				print("Port {} is open".format(port))
				open_ports.append(port)
			portx.close()
		except (ConnectionRefusedError, AttributeError, OSError):
			pass
			
		ports_queue.task_done()

def endTiming(time_start):
	time_end = datetime.now()
	time_scanning = time_end - time_start
	print("Port scan completed in "+ str(time_scanning))

def printOpenPorts(open_ports):
	open_ports.sort()
	open_ports_sorted = [str(port) for port in open_ports]
	open_ports_output = ",".join(open_ports_sorted)
	print("=" * 50)
	print("Open ports are: \n" + open_ports_output)

def main():
	print_banners()

	open_ports = []

	target_ip, thread_num = getInputs()

	time_start = beginTiming(target_ip)

	portscan_multithreads(open_ports, target_ip, thread_num)
	
	endTiming(time_start)
	
	printOpenPorts(open_ports)
	
if __name__ == '__main__':

	main()
