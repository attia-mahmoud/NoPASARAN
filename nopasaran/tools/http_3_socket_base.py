import asyncio
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import H3Event, HeadersReceived, DataReceived
from aioquic.quic.events import QuicEvent, ConnectionTerminated, StreamReset
from nopasaran.definitions.events import EventNames
import nopasaran.tools.http_3_overwrite

logger = logging.getLogger("http3_base")

class HTTP3SocketBase:
    """Base class for HTTP/3 socket operations"""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.connection: Optional[H3Connection] = None
        self.protocol: Optional[QuicConnectionProtocol] = None
        self.MAX_RETRY_ATTEMPTS = 3
        self.TIMEOUT = 5.0

    async def _receive_frame(self, timeout=None) -> Optional[List[H3Event]]:
        """Helper method to receive H3 events with timeout"""
        if timeout is None:
            timeout = self.TIMEOUT
            
        try:
            start_time = time.time()
            while time.time() - start_time < timeout:
                if self.protocol and self.connection:
                    # Process QUIC events and convert to H3 events
                    quic_events = self.protocol._quic.next_event()
                    if quic_events:
                        h3_events = []
                        for quic_event in quic_events:
                            events = self.connection.handle_event(quic_event)
                            h3_events.extend(events)
                        if h3_events:
                            return h3_events
                await asyncio.sleep(0.01)
            return None
        except Exception as e:
            logger.error(f"Error receiving frame: {e}")
            return None

    async def _receive_quic_events(self, timeout=None) -> Optional[List[QuicEvent]]:
        """Helper method to receive QUIC-level events (for GOAWAY/RESET detection)"""
        if timeout is None:
            timeout = self.TIMEOUT
            
        try:
            start_time = time.time()
            quic_events = []
            
            while time.time() - start_time < timeout:
                if self.protocol:
                    # Get QUIC events directly without H3 processing
                    event = self.protocol._quic.next_event()
                    if event:
                        quic_events.append(event)
                        # Check for connection/stream termination events
                        if isinstance(event, (ConnectionTerminated, StreamReset)):
                            return quic_events
                    else:
                        break
                await asyncio.sleep(0.01)
            
            return quic_events if quic_events else None
        except Exception as e:
            logger.error(f"Error receiving QUIC events: {e}")
            return None

    def set_headers_frames(self, frame_spec: Dict[str, Any]):
        """Set the deterministic frames to inject during communication"""
        self.deterministic_frames = frame_spec

    async def send_headers_frames(self, frame_type: str = "client_frames"):
        """Send deterministic frames based on the frame specification"""
        if not self.deterministic_frames or frame_type not in self.deterministic_frames:
            return EventNames.ERROR.name, [], "No deterministic frames configured"
            
        frames = self.deterministic_frames[frame_type]
        return await self.send_frames(frames)

    async def send_frames(self, frames):
        """Send frames and handle responses"""
        if not self.connection or not self.protocol:
            return EventNames.ERROR.name, [], "Connection not established"
            
        sent_frames = []
        
        for frame in frames:
            try:
                # Get next available stream for the request
                stream_id = self.protocol._quic.get_next_available_stream_id()
                
                if frame.get("type") == "HEADERS":
                    headers = self._convert_headers(frame.get("headers", {}))
                    end_stream = frame.get("end_stream", True)
                    
                    self.connection.send_headers(stream_id, headers, end_stream=end_stream)
                    sent_frames.append(frame)
                
                # Transmit the data
                self.protocol.transmit()
                
                # Brief pause to allow for responses
                await asyncio.sleep(0.1)
                
                # Check for immediate responses (like connection termination)
                events = await self._receive_frame(timeout=0.3)
                if events:
                    for event in events:
                        if isinstance(event, HeadersReceived):
                            # Check for error status codes
                            for name, value in event.headers:
                                if name == b':status' and value.startswith(b'5'):
                                    return (
                                        EventNames.REJECTED.name,
                                        sent_frames,
                                        f"Received 5xx status code {value.decode()} after sending {len(sent_frames)}/{len(frames)} frames."
                                    )
                
                # Also check for QUIC-level events (GOAWAY/RESET)
                quic_events = await self._receive_quic_events(timeout=0.1)
                if quic_events:
                    for quic_event in quic_events:
                        if isinstance(quic_event, ConnectionTerminated):
                            return (
                                EventNames.GOAWAY_RECEIVED.name,
                                sent_frames,
                                f"Connection terminated by peer: Received GOAWAY/connection termination after sending {len(sent_frames)} of {len(frames)} frames. Error code {getattr(quic_event, 'error_code', 'unknown')}."
                            )
                        elif isinstance(quic_event, StreamReset):
                            return (
                                EventNames.RESET_RECEIVED.name,
                                sent_frames,
                                f"Stream {quic_event.stream_id} reset by peer: Received StreamReset after sending frame #{len(sent_frames)} of {len(frames)}: {frame.get('type')}. Error code {getattr(quic_event, 'error_code', 'unknown')}"
                            )
                        
            except Exception as e:
                return EventNames.ERROR.name, sent_frames, f"Error sending frame: {str(e)}"
        
        return EventNames.FRAMES_SENT.name, sent_frames, f"Successfully sent {len(sent_frames)} frames."

    def _convert_headers(self, headers_dict: Dict[str, str]) -> List[Tuple[bytes, bytes]]:
        """Convert headers dict to list of byte tuples"""
        return [(key.encode() if isinstance(key, str) else key, 
                value.encode() if isinstance(value, str) else value) 
                for key, value in headers_dict.items()]

    # async def receive_test_frames(self, test_frames) -> Tuple[str, str, str]:
    #     """Wait for test frames with adaptive timeout"""
    #     frames_received = []
    #     expected_frame_count = len(test_frames)
    #     last_frame_time = time.time()
    #     start_time = time.time()
        
    #     while len(frames_received) < expected_frame_count:
    #         # Check for overall timeout
    #         if time.time() - start_time > self.TIMEOUT * 2:
    #             return EventNames.TIMEOUT.name, f"Overall timeout after {self.TIMEOUT * 2}s. Received {len(frames_received)} of {expected_frame_count} expected frames.", str(frames_received)
            
    #         # Check for timeout since last frame
    #         if time.time() - last_frame_time > self.TIMEOUT:
    #             return EventNames.TIMEOUT.name, f"Timeout after {self.TIMEOUT}s since last frame. Received {len(frames_received)} of {expected_frame_count} expected frames.", str(frames_received)
            
    #         events = await self._receive_frame(timeout=1.0)
            
    #         if events:
    #             last_frame_time = time.time()
                
    #             for event in events:
    #                 # Skip connection setup events
    #                 if isinstance(event, HeadersReceived):
    #                     # Check for 5xx status codes
    #                     for name, value in event.headers:
    #                         if name == b':status' and value.startswith(b'5'):
    #                             return EventNames.REJECTED.name, f"Received 5xx status code {value.decode()} after receiving {len(frames_received)}/{expected_frame_count} frames.", str(event)
                    
    #                 elif isinstance(event, DataReceived):
    #                     pass
                    
    #                 frames_received.append(event)
                    
    #                 # Handle test cases if present
    #                 for frame in test_frames:
    #                     if frame.get('test'):
    #                         result = self._handle_test(event, frame)
    #                         if result is not None:
    #                             return EventNames.RECEIVED_FRAMES.name, f"Test result: {result}", str(frames_received)
                    
    #                 if len(frames_received) == expected_frame_count:
    #                     return EventNames.RECEIVED_FRAMES.name, f"Successfully received all {len(frames_received)}/{expected_frame_count} frames.", str(frames_received)
            
    #         await asyncio.sleep(0.01)
        
    #     return EventNames.RECEIVED_FRAMES.name, f"Successfully received all {len(frames_received)}/{expected_frame_count} frames.", str(frames_received)

    # def _handle_test(self, event, frame) -> Optional[str]:
    #     """Handle test cases for received frames"""
    #     test = frame.get('test', {})
        
    #     if not test:
    #         return None
            
    #     # Import function_map here to avoid circular imports
    #     try:
    #         from nopasaran.tools.checks import function_map
    #         function_name = test.get('function')
    #         params = test.get('params', {})
            
    #         function = function_map.get(function_name)
    #         if not function:
    #             return None
            
    #         # Execute the function with unpacked dictionary parameters
    #         result = function(event, **params)
            
    #         # Return based on the test result and specified conditions
    #         if result is True:
    #             return test.get('if_true')
    #         elif result is False:
    #             return test.get('if_false')
    #         elif result is None:
    #             return None
    #     except Exception as e:
    #         logger.error(f"Error handling test: {e}")
    #         return None

    async def close(self):
        """Close the HTTP/3 connection and clean up resources"""
        try:
            if self.connection and self.protocol:
                # Close the QUIC connection gracefully
                self.protocol._quic.close()
                
            # Clear references
            self.connection = None
            self.protocol = None
            
            return EventNames.CONNECTION_CLOSED.name
        except Exception as e:
            return EventNames.ERROR.name
