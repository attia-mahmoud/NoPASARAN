import ssl
import socket
from typing import Dict, Any
from aioquic.quic.configuration import QuicConfiguration
from nopasaran.http_2_utils import generate_temp_certificates

# HTTP/3 configuration settings
H3_CONFIG_SETTINGS = {
    'max_datagram_frame_size': 65536,
    'max_stream_data': 1048576,
    'max_data': 10485760,
}

# SSL configuration for HTTP/3
class SSL_CONFIG:
    MAX_BUFFER_SIZE = 65535
    CERT_FILE = None
    KEY_FILE = None

def create_ssl_context(is_client=True):
    """Create SSL context for HTTP/3 connections"""
    context = ssl.create_default_context()
    
    if is_client:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    else:
        # Server configuration
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    # Set ALPN protocols for HTTP/3
    context.set_alpn_protocols(['h3'])
    
    return context

def create_quic_configuration(is_client=True, verify_mode=None):
    """Create QUIC configuration for HTTP/3"""
    if verify_mode is None:
        verify_mode = ssl.CERT_NONE if is_client else ssl.CERT_REQUIRED
        
    config = QuicConfiguration(
        is_client=is_client,
        alpn_protocols=["h3"],
        verify_mode=verify_mode
    )
    
    # Configure certificates for server
    if not is_client:
        # Generate temporary certificates for server
        temp_cert, temp_key = generate_temp_certificates()
        config.load_cert_chain(temp_cert, temp_key)
        
        # Clean up temporary files
        import os
        os.unlink(temp_cert)
        os.unlink(temp_key)
    
    return config

def create_socket(host: str, port: int, is_server=False):
    """Create socket for HTTP/3 connections"""
    if is_server:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        return sock
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return sock