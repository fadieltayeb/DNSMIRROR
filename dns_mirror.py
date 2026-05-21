#!/usr/bin/env python3
"""
Proactive DNS Mirror - DNS Deception Framework
Modified: Generates decoys that align with real attack patterns
70% common subdomains + 30% random strings
EXCLUDES legitimate advertised subdomains (www, mail, vpn, admin)

VM2: 192.168.1.60
Forwards legitimate queries to BIND9 (192.168.1.50)
Detects and logs enumeration attempts on decoy subdomains
"""

import socket
import random
import string
import json
import time
import logging
import os
from datetime import datetime

# Try to import DNS libraries
try:
    import dns.message
    import dns.query
    import dns.rdatatype
    import dns.rdataclass
    import dns.rrset
    import dns.name
    import dns.rdata
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("Warning: dnspython not fully available - using raw sockets")

# ============================================================
# CONFIGURATION
# ============================================================

# Network configuration
BIND9_IP = "192.168.1.50"
BIND9_PORT = 53
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53

# Response configuration
DECOY_RESPONSE_IP = "10.255.255.1"

# Legitimate advertised subdomains (DO NOT generate as decoys!)
LEGITIMATE_SUBDOMAINS = ["www", "mail", "vpn", "admin"]

# Decoy generation configuration
TOTAL_DECOYS = 150
COMMON_PERCENTAGE = 70  # 70% common subdomains from wordlist
RANDOM_PERCENTAGE = 30  # 30% random strings

# Path to common subdomains wordlist
COMMON_WORDLIST = "/snap/seclists/current/Discovery/DNS/subdomains-top1million-5000.txt"
# Fallback if wordlist not found
FALLBACK_WORDLIST = "/opt/dnsmirror/wordlists/subdomains-top1million-5000.txt"

# ============================================================
# GLOBAL VARIABLES
# ============================================================

decoy_registry = set()      # Stores all generated decoy subdomains

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/opt/dnsmirror/dnsmirror.log', mode='a')
    ]
)
logger = logging.getLogger(__name__)


# ============================================================
# DECOY GENERATION FUNCTIONS
# ============================================================

def load_common_subdomains(wordlist_path, max_count=105):
    """Load common subdomains from SecLists wordlist, EXCLUDING legitimate ones"""
    common_subdomains = []
    legitimate_set = set(LEGITIMATE_SUBDOMAINS)
    
    try:
        # Try primary path first
        if not os.path.exists(wordlist_path):
            wordlist_path = FALLBACK_WORDLIST
        
        with open(wordlist_path, 'r') as f:
            all_lines = [line.strip().lower() for line in f if line.strip()]
            unique_subdomains = list(dict.fromkeys(all_lines))
            filtered_subdomains = [sub for sub in unique_subdomains if sub not in legitimate_set]
            common_subdomains = filtered_subdomains[:max_count]
            logger.info(f"Loaded {len(common_subdomains)} common subdomains from wordlist")
            
    except FileNotFoundError:
        logger.warning(f"Wordlist not found at {wordlist_path}. Using fallback.")
        fallback = [
            "ftp", "localhost", "webmail", "test", "dev", "api", "blog", 
            "shop", "internal", "remote", "secure", "backup", "staging", 
            "prod", "dashboard", "login", "cdn", "static", "assets", "docs", 
            "support", "help", "status", "monitor", "ns1", "ns2", "mx", "pop3", 
            "smtp", "imap", "cloud", "storage", "db", "database", "redis", 
            "cache", "analytics", "tracking", "metrics", "logs", "monitoring",
            "alerts", "notifications", "web", "app", "api2", "api3", "v2", "v3",
            "beta", "alpha", "demo", "sandbox", "test2", "dev2", "staging2"
        ]
        filtered_fallback = [sub for sub in fallback if sub not in legitimate_set]
        common_subdomains = filtered_fallback[:max_count]
        logger.info(f"Using fallback: {len(common_subdomains)} common subdomains")
    
    logger.info(f"Excluded legitimate subdomains: {', '.join(legitimate_set)}")
    return common_subdomains


def generate_random_string(length=8):
    """Generate random alphanumeric string"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def generate_decoy_subdomains(domain="mirrortest.lab", total_count=TOTAL_DECOYS):
    """Generate decoy subdomains: 70% common + 30% random, excludes legitimate"""
    decoys = []
    legitimate_set = set(LEGITIMATE_SUBDOMAINS)
    
    common_count = int(total_count * COMMON_PERCENTAGE / 100)
    random_count = total_count - common_count
    
    logger.info(f"Generating {total_count} decoys: {common_count} common ({COMMON_PERCENTAGE}%) + {random_count} random ({RANDOM_PERCENTAGE}%)")
    
    # Load common subdomains from wordlist (excluding legitimate ones)
    common_subdomains = load_common_subdomains(COMMON_WORDLIST, common_count)
    
    # Add common subdomains as decoys
    for sub in common_subdomains:
        decoy = f"{sub}.{domain}"
        decoys.append(decoy)
    
    # Add random string decoys
    for _ in range(random_count):
        random_chars = generate_random_string(8)
        decoy = f"{random_chars}.{domain}"
        decoys.append(decoy)
    
    # Final safety check: ensure no legitimate subdomains are in decoys
    final_decoys = []
    for decoy in decoys:
        subdomain_part = decoy.replace(f".{domain}", "")
        if subdomain_part not in legitimate_set:
            final_decoys.append(decoy)
        else:
            logger.warning(f"Removed {decoy} from decoys (was legitimate)")
    
    random.shuffle(final_decoys)
    logger.info(f"Generated {len(final_decoys)} total decoys (legitimate excluded)")
    return final_decoys


def load_legitimate_zones(domain="mirrortest.lab"):
    """Create set of legitimate subdomains (these are NOT decoys)"""
    return {f"{sub}.{domain}" for sub in LEGITIMATE_SUBDOMAINS}


def save_decoys_to_file(decoys):
    """Save generated decoys to a file for reference"""
    os.makedirs("/opt/dnsmirror", exist_ok=True)
    with open("/opt/dnsmirror/generated_decoys.txt", "w") as f:
        f.write("# DNSMirror Generated Decoys\n")
        f.write(f"# Total: {len(decoys)}\n")
        f.write(f"# Composition: {COMMON_PERCENTAGE}% common + {RANDOM_PERCENTAGE}% random\n")
        f.write(f"# Excluded legitimate: {', '.join(LEGITIMATE_SUBDOMAINS)}\n")
        f.write("# ===========================================\n\n")
        for decoy in sorted(decoys):
            f.write(decoy + "\n")
    logger.info(f"Saved {len(decoys)} decoys to /opt/dnsmirror/generated_decoys.txt")


# ============================================================
# DNS RESPONSE FUNCTIONS
# ============================================================

def build_dns_response(query_data, response_ip, query_name):
    """Build a DNS A-record response with the specified IP"""
    if not DNS_AVAILABLE:
        return None
    
    try:
        request = dns.message.from_wire(query_data)
        response = dns.message.make_response(request)
        response.answer = []
        
        # Ensure query_name is absolute (FQDN with trailing dot)
        if not query_name.endswith('.'):
            query_name = query_name + '.'
        
        name = dns.name.from_text(query_name)
        rrset = dns.rrset.RRset(name, dns.rdataclass.IN, dns.rdatatype.A)
        rrset.ttl = 300
        
        rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, response_ip)
        rrset.add(rdata)
        response.answer.append(rrset)
        
        return response.to_wire()
        
    except Exception as e:
        logger.error(f"Error building response for {query_name}: {e}")
        return None


def forward_to_bind9(query_data, client_addr, timeout=2.0):
    """Forward query to BIND9 and return response"""
    try:
        if DNS_AVAILABLE:
            query = dns.message.from_wire(query_data)
            response = dns.query.udp(query, BIND9_IP, port=BIND9_PORT, timeout=timeout)
            return response.to_wire()
        else:
            # Fallback to raw sockets if dnspython not available
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(query_data, (BIND9_IP, BIND9_PORT))
            response, _ = sock.recvfrom(4096)
            sock.close()
            return response
    except socket.timeout:
        logger.warning(f"Timeout forwarding query from {client_addr}")
        return None
    except Exception as e:
        logger.error(f"Forwarding error: {e}")
        return None


def extract_query_name(data):
    """Extract the queried domain name from DNS packet"""
    try:
        if DNS_AVAILABLE:
            request = dns.message.from_wire(data)
            if request.question:
                # Return name as string without trailing dot for consistent storage
                return str(request.question[0].name).rstrip('.')
    except Exception as e:
        logger.debug(f"Error extracting query name: {e}")
    return None


# ============================================================
# LOGGING FUNCTIONS - FIXED WITH LATENCY PARAMETER
# ============================================================

def log_attack(source_ip, queried_subdomain, response_ip, latency_ms):
    """Log detected enumeration attempt WITH latency measurement"""
    os.makedirs("/opt/dnsmirror", exist_ok=True)
    
    attack_entry = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "queried_subdomain": queried_subdomain,
        "response_ip": response_ip,
        "action": "DECOY_HIT",
        "detection_type": "deterministic",
        "latency_ms": round(latency_ms, 2)  # ✅ FIXED: Now properly passed and rounded
    }
    
    # Append to NDJSON file (one JSON object per line)
    with open("/opt/dnsmirror/attacks.json", "a") as f:
        f.write(json.dumps(attack_entry) + "\n")
    
    logger.warning(f"🚨 DECOY HIT! {source_ip} queried {queried_subdomain} → {response_ip} ({latency_ms:.2f}ms)")


def log_forward(source_ip, queried_subdomain, bind9_response_time_ms):
    """Log forwarded legitimate query"""
    os.makedirs("/opt/dnsmirror", exist_ok=True)
    
    forward_entry = {
        "timestamp": datetime.now().isoformat(),
        "source_ip": source_ip,
        "queried_subdomain": queried_subdomain,
        "action": "FORWARDED",
        "bind9_response_time_ms": round(bind9_response_time_ms, 2)
    }
    
    # Append to NDJSON file
    with open("/opt/dnsmirror/forward.log", "a") as f:
        f.write(json.dumps(forward_entry) + "\n")


# ============================================================
# MAIN DNS MIRROR FUNCTION - FIXED LATENCY MEASUREMENT
# ============================================================

def start_dns_mirror():
    """Main DNS Mirror listener with proper latency tracking"""
    # Generate decoy subdomains
    decoys = generate_decoy_subdomains()
    decoy_registry.update(decoys)
    
    # Save decoys for reference
    save_decoys_to_file(decoys)
    
    legitimate_zones = load_legitimate_zones()
    
    # Print startup banner
    print("\n" + "="*70)
    print("🛡️  PROACTIVE DNS MIRROR - DECEPTION FRAMEWORK")
    print("="*70)
    print(f"📡 Listening on:      0.0.0.0:{LISTEN_PORT}")
    print(f"🔄 Forwarding to:     {BIND9_IP}:{BIND9_PORT}")
    print(f"🎯 Decoy generation:  {COMMON_PERCENTAGE}% common + {RANDOM_PERCENTAGE}% random")
    print(f"📋 Total decoys:      {len(decoy_registry)}")
    print(f"✅ Legitimate zones:  {len(legitimate_zones)}")
    print(f"   → {', '.join(legitimate_zones)}")
    print(f"🔧 Decoy response:    {DECOY_RESPONSE_IP}")
    print("="*70)
    
    # Show sample decoys
    print("\n📋 Sample decoys (first 15):")
    for i, decoy in enumerate(list(decoy_registry)[:15], 1):
        subdomain = decoy.replace(".mirrortest.lab", "")
        if len(subdomain) == 8 and subdomain.isalnum():
            print(f"   {i:2}. {decoy} 🔀 (random)")
        else:
            print(f"   {i:2}. {decoy} 📚 (common)")
    if len(decoy_registry) > 15:
        print(f"   ... and {len(decoy_registry) - 15} more")
    print("="*70 + "\n")
    
    logger.info("DNS Mirror is running. Waiting for queries...")
    
    # Create UDP socket (requires root for port 53)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((LISTEN_IP, LISTEN_PORT))
        logger.info("🟢 DNS Mirror running on port 53")
    except PermissionError:
        logger.error("❌ Permission denied. Run with: sudo python3 dns_mirror.py")
        return
    except Exception as e:
        logger.error(f"❌ Socket error: {e}")
        return
    
    try:
        query_count = 0
        decoy_hits = 0
        legit_forwards = 0
        
        while True:
            data, client_addr = sock.recvfrom(4096)
            client_ip = client_addr[0]
            query_count += 1
            
            # Extract query name
            query_name = extract_query_name(data)
            if not query_name:
                continue
            
            # ✅ START TIMING for ALL queries (for accurate latency measurement)
            query_start = time.perf_counter()
            
            # Check if query is for a decoy subdomain
            if query_name in decoy_registry:
                # Build decoy response
                response = build_dns_response(data, DECOY_RESPONSE_IP, query_name)
                
                # ✅ CALCULATE LATENCY for decoy detection
                latency_ms = (time.perf_counter() - query_start) * 1000
                
                if response:
                    sock.sendto(response, client_addr)
                    # ✅ PASS latency_ms to log_attack (FIXED)
                    log_attack(client_ip, query_name, DECOY_RESPONSE_IP, latency_ms)
                    decoy_hits += 1
                    if decoy_hits % 10 == 0:
                        logger.info(f"🎯 Decoy hit #{decoy_hits}: {query_name} ({latency_ms:.2f}ms)")
            
            # Check if query is for legitimate zone
            elif query_name in legitimate_zones:
                # Forward to BIND9
                response = forward_to_bind9(data, client_addr)
                
                # ✅ CALCULATE LATENCY for legitimate forwarding
                latency_ms = (time.perf_counter() - query_start) * 1000
                
                if response:
                    sock.sendto(response, client_addr)
                    log_forward(client_ip, query_name, latency_ms)
                    legit_forwards += 1
                    if legit_forwards % 10 == 0:
                        logger.info(f"✅ Forwarded: {query_name} ({latency_ms:.2f}ms)")
            
            else:
                # Unknown domain - silently ignore (stealth mode)
                if query_count % 200 == 0:
                    logger.debug(f"Ignored unknown query: {query_name}")
    
    except KeyboardInterrupt:
        print("\n" + "="*70)
        print("🛑 SHUTTING DOWN DNS MIRROR")
        print("="*70)
        print(f"📊 Total queries:        {query_count}")
        print(f"🚨 Decoy hits (attacks): {decoy_hits}")
        print(f"📋 Legitimate forwards:  {legit_forwards}")
        print(f"📁 Logs saved:")
        print(f"   → /opt/dnsmirror/attacks.json")
        print(f"   → /opt/dnsmirror/forward.log")
        print(f"   → /opt/dnsmirror/generated_decoys.txt")
        print("="*70)
    finally:
        sock.close()
        logger.info("Socket closed. DNS Mirror stopped.")


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    # Ensure log directory exists
    os.makedirs("/opt/dnsmirror", exist_ok=True)
    
    logger.info("Starting Proactive DNSMirror framework...")
    start_dns_mirror()
