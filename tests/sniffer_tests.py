
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6, ICMPv6ND_NS
import scapy.contrib.igmp
import unittest
import subprocess
import threading
import queue
from time import sleep
import signal
from termcolor import colored
import re

path = "../ipk-sniffer"

def sendMldReport():
    mld_report = ICMPv6MLReport2()
    mld_report.numaddr = 1
    send(IPv6(src="::1", dst="::1") / mld_report / ICMPv6MLDMultAddrRec(rtype=4, dst="ff02::1"))

def sendNdpPacket():
    send(IPv6(src="::1", dst="::1") / "00:01:02:03:04:05" / ICMPv6NDOptSrcLLAddr(lladdr=ll_addr))

def sendIcmpv6Echo_message():
    send(IPv6(src="::1", dst="::1") / ICMPv6EchoRequest(data="LOL KEK 1337 420"))

def sendRouterSolicitation():
    send(ICMPv6ND_RS() / IPv6(src="::1", dst="::1"))

def sendIcmpv4():
    send(IP(dst="127.0.0.1") / ICMP() / "aww yiss, ICMPv4 packet!")

def sendIcmpv6Echo():
    send(IPv6(dst="::1") / ICMPv6EchoRequest() / "Custom Message for ICMPv6 Echo")

def sendArpRequest():
    send(ARP(pdst='127.0.0.1'))

def sendNdpNs():
    send(IPv6(dst="::1") / ICMPv6ND_NS(tgt="::1"))

def sendIgmp():
    send(IP(dst="127.0.0.1")/scapy.contrib.igmp.IGMP())

def sendUdpPacket():
    send(IP(dst="127.0.0.1") / UDP(dport=12345) / "HELLO UDP!")

def sendTcpPacket():
    send(IP(dst="127.0.0.1")/TCP(dport=4567, flags='S') / "no way this is tcp packet")

class SnifferTests(unittest.TestCase):
    def setUp(self):
        test_name = self.id().split('.')[-1]
        print(f"\nRunning test: {test_name}")

    def read_stdout(self, queue):
        for line in iter(self.sniffer.stdout.readline, ""):
            print(colored(line, "green"), end="")
            queue.put(line)

    def execute(self, input_data):
        self.sniffer.stdin.write(input_data + "\n")
        self.sniffer.stdin.flush()
        sleep(0.2)

    def get_stdout(self):
        sleep(2)
        output = []
        while not self.stdout_queue.empty():
            output.append(self.stdout_queue.get())
        return "".join(output)
    
    def startSniffer(self, args):
        sleep(0.2)
        self.stdout_queue = queue.Queue()
        self.stderr_queue = queue.Queue()
        try:
            self.sniffer = subprocess.Popen([path] + args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        except Exception as e:
            self.fail(f"Error executing binary file: {e}")
        self._start_thread(self.read_stdout, self.stdout_queue)
        self.return_code = None
        sleep(1)

    def _start_thread(self, target, queue):
        thread = threading.Thread(target=target, args=(queue,))
        thread.daemon = True 
        thread.start()
    
    def start_tshark_capture(self, filter_expression, output_file):
        with open(output_file, 'w') as f:
            f.write('')
        tshark_cmd = ['tshark', '-i', 'lo', '-f', filter_expression, '-V', '-w', output_file] 
        self.tshark_process = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self._start_thread(self.read_tshark_stdout, self.tshark_process.stdout)
         
    def read_tshark_stdout(self, stdout_stream):
        for line in iter(stdout_stream.readline, ""):
            if re.match(r'^\d{4}', line):
                print(colored("TSHARK:", "magenta"), colored(line, "magenta"), end="")

    def stop_tshark_capture(self):
        sleep(1)
        self.tshark_process.terminate()
        self.tshark_process.wait()
        self.tshark_process.stdout.close()
        self.tshark_process.stderr.close()

    def tearDown(self):
        self.sniffer.send_signal(signal.SIGINT)
        self.sniffer.terminate()
        self.sniffer.wait()
        self.sniffer.stdout.close()
        self.sniffer.stderr.close()

    def testMLD(self):      
        self.startSniffer(["-i", "lo", "--mld"])
        sendTcpPacket()
        sendArpRequest()
        sendMldReport()
        output = self.get_stdout()
        self.assertIn("MLD", output, "MLD packet not detected")

        
    def testIcmpv4(self):
        self.startSniffer(["-i", "lo", "--icmp4"])
        sendNdpNs()
        sendIcmpv6Echo_message()
        sendIcmpv4()
        output = self.get_stdout()
        self.assertIn("ICMP", output, "ICMPv4 packet not detected")

    def testIcmpv6Echo(self):
        self.startSniffer(["-i", "lo", "--icmp6"])
        sendRouterSolicitation()
        sendIcmpv6Echo()
        output = self.get_stdout()
        self.assertIn("ICMPv6", output, "ICMPv6 Echo Request packet not detected")

    def testArpRequest(self):
        self.startSniffer(["-i", "lo", "--arp"])
        sendMldReport()
        sendIcmpv4()
        sendArpRequest()
        output = self.get_stdout()
        self.assertIn("ARP", output, "ARP Request packet not detected")

    def testNdpNs(self):
        self.startSniffer(["-i", "lo", "--ndp"])
        sendIcmpv6Echo_message()
        sendUdpPacket()
        sendNdpNs()
        output = self.get_stdout()
        self.assertIn("src IP: ::1", output, "NDP NS packet not detected")

    def testIgmp(self):
        self.startSniffer(["-i", "lo", "--igmp"])
        sendIcmpv6Echo_message()
        sendTcpPacket()
        sendIgmp()
        output = self.get_stdout()
        self.assertIn("IGMP", output, "IGMP packet not detected")

    def testUdpPacket(self):
        self.startSniffer(["-i", "lo", "--udp"])
        sendIcmpv6Echo_message()
        sendMldReport()
        sendUdpPacket()
        output = self.get_stdout()
        self.assertIn("src MAC: 00:00:00:00:00:00", output, "MAC SRC not found in appropriate format")
        self.assertIn("dst MAC: ff:ff:ff:ff:ff:ff", output, "MAC DST not found in appropriate format")

    def testTcpPacket(self):
        self.startSniffer(["-i", "lo", "--tcp"])
        sendIgmp()
        sendNdpNs()
        sendTcpPacket()
        output = self.get_stdout()
        self.assertIn("src MAC: 00:00:00:00:00:00", output, "MAC SRC not found in appropriate format")
        self.assertIn("dst MAC: ff:ff:ff:ff:ff:ff", output, "MAC DST not found in appropriate format")

    
if __name__ == '__main__':
    unittest.main()
