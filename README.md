Proactive DNSMirror is a lightweight DNS deception framework that generates unadvertised, randomly named subdomains and monitors for queries to these domains. Since legitimate users have no knowledge of these decoy subdomains, any query constitutes deterministic detection of DNS enumeration. Upon detection, the framework responds with decoy IP addresses while transparently forwarding legitimate queries to authoritative DNS servers.
# Clone or copy dns_mirror.py to your target VM 
sudo mkdir -p /opt/dnsmirror
sudo cp dns_mirror.py /opt/dnsmirror/
sudo chmod +x /opt/dnsmirror/dns_mirror.py

# Install optional dependency for robust DNS handling
pip3 install dnspython
# Start DNSMirror (requires sudo for port 53)
cd /opt/dnsmirror
sudo python3 dns_mirror.py
