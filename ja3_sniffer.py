from scapy.all import sniff
from scapy.layers.tls.all import TLSClientHello
import hashlib
import warnings

# Suppress specific warnings
warnings.filterwarnings("ignore", category=UserWarning, module='scapy.layers.tls')

# Example list of known cipher suites (in numerical format)
known_cipher_suites = {
    0x0005,  # TLS_RSA_WITH_RC4_128_MD5
    0x000A,  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
    0x0035,  # TLS_RSA_WITH_AES_128_CBC_SHA
    0x003C,  # TLS_RSA_WITH_AES_256_CBC_SHA
    0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    # Add more known cipher suites as needed
}

unknown_cipher_suites = set()  # Set to store unknown cipher suites

def extract_ja3(tls_client_hello):
    global unknown_cipher_suites
    try:
        tls_version = tls_client_hello.version if hasattr(tls_client_hello, 'version') else 'unknown'
        cipher_suites = tls_client_hello.ciphers if hasattr(tls_client_hello, 'ciphers') else []
        extensions = tls_client_hello.extensions if hasattr(tls_client_hello, 'extensions') else []
        
        # Log unknown cipher suites
        for cipher in cipher_suites:
            if cipher not in known_cipher_suites:  # Check against the known list
                unknown_cipher_suites.add(cipher)

        ja3_string = f"{tls_version},{','.join(map(str, cipher_suites))},{','.join(map(str, extensions))}"
        return ja3_string
    except Exception as e:
        print(f"Error extracting JA3: {e}")
        return None

def ja3_hash(ja3_string):
    return hashlib.md5(ja3_string.encode()).hexdigest()

def packet_callback(packet):
    if packet.haslayer(TLSClientHello):
        tls_layer = packet.getlayer(TLSClientHello)
        ja3 = extract_ja3(tls_layer)
        if ja3:
            ja3_hash_value = ja3_hash(ja3)
            # Get the source and destination IP addresses
            src_ip = packet[1].src  # Source IP (client)
            dst_ip = packet[1].dst  # Destination IP (server)
            print(f"Client IP: {src_ip}, Server IP: {dst_ip}, JA3 Fingerprint: {ja3}, Hash: {ja3_hash_value}")
# Print unknown cipher suites after sniffing
def print_unknown_cipher_suites():
    if unknown_cipher_suites:
        print("Unknown Cipher Suites:")
        for cipher in unknown_cipher_suites:
            print(f" - {cipher}")

print("Sniffing for TLS Client Hello packets...")
sniff(filter="tcp port 443", prn=packet_callback, store=0)

# Call this function when you stop sniffing (e.g., with Ctrl+C)
print_unknown_cipher_suites()
