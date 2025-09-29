import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple, Any
from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import H3Event, HeadersReceived, DataReceived
from aioquic.quic.events import QuicEvent
from nopasaran.definitions.events import EventNames
from nopasaran.http_3_utils import create_quic_configuration
from nopasaran.tools.http_3_socket_base import HTTP3SocketBase
import nopasaran.tools.http_3_overwrite

logger = logging.getLogger("http3_client")

class HTTP3SocketClient(HTTP3SocketBase):
    """HTTP/3 client implementation with deterministic frame injection support"""

    async def start(self):
        """Start the HTTP/3 client"""
        try:
            # Create QUIC configuration (TLS always enabled for HTTP/3, SSL key logging always enabled for client)
            configuration = create_quic_configuration(
                is_client=True,
                verify_mode=False
            )
            
            # Connect to server
            self._protocol_context = connect(
                self.host,
                self.port,
                configuration=configuration,
                create_protocol=QuicConnectionProtocol,
            )
            
            self.protocol = await self._protocol_context.__aenter__()
            self.connection = H3Connection(self.protocol._quic)
            
            # Add connection attributes
            self.connection.host = self.host
            self.connection.scheme = 'https'  # HTTP/3 always uses HTTPS
            
            # Wait for connection to be established and give server time to start listening
            await asyncio.sleep(1)
            
            selected_protocol = 'h3'  # HTTP/3 always uses h3
            return EventNames.CLIENT_STARTED.name, f"Client successfully connected to {self.host}:{self.port} with TLS and ALPN protocol {selected_protocol}."
                
        except asyncio.TimeoutError:
            return EventNames.ERROR.name, f"Timeout occurred after {self.TIMEOUT}s while trying to connect to server at {self.host}:{self.port}"
        except ConnectionRefusedError as e:
            return EventNames.ERROR.name, f"Connection refused by server at {self.host}:{self.port}. Server may not be running or port may be blocked: {e}"
        except Exception as e:
            return EventNames.ERROR.name, f"Error connecting to {self.host}:{self.port}: {str(e)}"

    async def run_communication(self, frame_spec: Dict[str, Any] = None):
        """
        Run client-side HTTP/3 communication with optional deterministic frame injection.
        
        Args:
            frame_spec: Dictionary containing client_frames and server_frames to inject
        """
        if frame_spec:
            self.set_deterministic_frames(frame_spec)
        
        try:
            # Send deterministic client frames if configured
            if self.deterministic_frames and "client_frames" in self.deterministic_frames:
                result = await self.send_deterministic_frames("client_frames")
                logger.info(f"Sent deterministic client frames: {result}")
            else:
                # Send a normal HTTP/3 request
                await self._send_normal_request()
            
            # Listen for server responses
            await self._listen_for_responses()
            
        except Exception as e:
            logger.error(f"Error in client communication: {e}")
            return EventNames.ERROR.name, f"Client communication error: {str(e)}"

    async def _send_normal_request(self):
        """Send a normal HTTP/3 request"""
        # Get next available stream
        stream_id = self.protocol._quic.get_next_available_stream_id()
        
        # Send headers for a normal GET request
        headers = [
            (b':method', b'GET'),
            (b':path', b'/'),
            (b':scheme', self.connection.scheme.encode()),
            (b':authority', self.host.encode()),
            (b'user-agent', b'nopasaran-http3-client'),
        ]
        
        self.connection.send_headers(stream_id, headers, end_stream=True)
        self.protocol.transmit()
        
        logger.info(f"Sent normal HTTP/3 request on stream {stream_id}")

    async def _listen_for_responses(self):
        """Listen for responses from the server"""
        timeout_start = time.time()
        
        while time.time() - timeout_start < self.TIMEOUT:
            events = await self._receive_frame(timeout=1.0)
            
            if events:
                for event in events:
                    if isinstance(event, HeadersReceived):
                        logger.info(f"Client received headers: {event.headers}")
                    elif isinstance(event, DataReceived):
                        logger.info(f"Client received data: {event.data}")
            
            await asyncio.sleep(0.01)

    async def close(self):
        """Close the HTTP/3 client connection"""
        try:
            if hasattr(self, '_protocol_context'):
                await self._protocol_context.__aexit__(None, None, None)
            
            return await super().close()
        except Exception as e:
            return EventNames.ERROR.name
