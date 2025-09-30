import asyncio
import time
import logging
from typing import Dict, List, Optional, Tuple, Any
from aioquic.asyncio import QuicConnectionProtocol
from aioquic.h3.connection import H3Connection
from aioquic.h3.events import H3Event, HeadersReceived, DataReceived
from aioquic.quic.events import QuicEvent, ConnectionTerminated, StreamReset
from aioquic.quic.connection import QuicConnectionState
from nopasaran.definitions.events import EventNames
import nopasaran.tools.http_3_overwrite


class EventCapturingProtocol(QuicConnectionProtocol):
    """Custom protocol that intercepts QUIC events before they're consumed"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._captured_events: List[QuicEvent] = []
        self._capture_enabled = False
        self._original_next_event = None
    
    def enable_capture(self):
        """Enable event capturing by monkey-patching next_event"""
        self._capture_enabled = True
        self._captured_events.clear()
        
        # Save original next_event if not already saved
        if self._original_next_event is None:
            self._original_next_event = self._quic.next_event
        
        # Replace next_event with our capturing version
        def capturing_next_event():
            event = self._original_next_event()
            if event is not None and self._capture_enabled:
                self._captured_events.append(event)
            return event
        
        self._quic.next_event = capturing_next_event
    
    def disable_capture(self):
        """Disable event capturing and restore original next_event"""
        self._capture_enabled = False
        if self._original_next_event is not None:
            self._quic.next_event = self._original_next_event
    
    def get_captured_events(self) -> List[QuicEvent]:
        """Return captured events (don't clear - let disable_capture handle that)"""
        return self._captured_events.copy()

class HTTP3SocketBase:
    """Base class for HTTP/3 socket operations"""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.connection: Optional[H3Connection] = None
        self.protocol: Optional[QuicConnectionProtocol] = None
        self.MAX_RETRY_ATTEMPTS = 3
        self.TIMEOUT = 5.0
        
        # Persistent event loop for the connection lifecycle
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread = None
        
        # Event capture buffer - store all H3 events as they're generated
        self._captured_events: List[Any] = []
        self._event_capture_enabled = False

    def _ensure_loop(self):
        """Ensure we have a dedicated event loop running in a background thread."""
        if self._loop and self._loop.is_running():
            return
        
        def _run_loop(loop: asyncio.AbstractEventLoop):
            asyncio.set_event_loop(loop)
            loop.run_forever()
        
        self._loop = asyncio.new_event_loop()
        import threading
        self._loop_thread = threading.Thread(target=_run_loop, args=(self._loop,), daemon=True)
        self._loop_thread.start()
        
        # Give the thread a moment to start
        time.sleep(0.01)

    def run_sync(self, coro):
        """Run a coroutine on the persistent event loop."""
        self._ensure_loop()
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result()

    # Synchronous wrappers for primitives
    def start_sync(self):
        return self.run_sync(self.start())

    def send_deterministic_frames_sync(self, frame_type: str = "client_frames"):
        return self.run_sync(self.send_deterministic_frames(frame_type))

    def close_sync(self):
        result = self.run_sync(self.close())
        # Stop the background loop
        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        self._loop = None
        return result

    async def _check_for_any_response(self, timeout=2.0) -> Optional[Tuple[str, str, List]]:
        """
        Check for ANY response by processing available QUIC events.
        Returns (event_name, message, headers_list) if response detected, None otherwise.
        """
        try:
            if not self.protocol or not self.connection:
                return None
            
            responses_found = []
            
            # Process all available QUIC events
            while True:
                quic_event = self.protocol._quic.next_event()
                if quic_event is None:
                    break
                
                # Check for QUIC-level termination events
                if isinstance(quic_event, ConnectionTerminated):
                    error_code = getattr(quic_event, 'error_code', 'unknown')
                    return (
                        EventNames.GOAWAY_RECEIVED.name,
                        f"Connection terminated by peer with error code {error_code}",
                        []
                    )
                elif isinstance(quic_event, StreamReset):
                    error_code = getattr(quic_event, 'error_code', 'unknown')
                    stream_id_val = quic_event.stream_id
                    return (
                        EventNames.RESET_RECEIVED.name,
                        f"Stream {stream_id_val} reset by peer with error code {error_code}",
                        []
                    )
                
                # Convert to H3 events and capture ALL responses
                h3_events = self.connection.handle_event(quic_event)
                for h3_event in h3_events:
                    if isinstance(h3_event, HeadersReceived):
                        # Capture ALL HeadersReceived events
                        headers_dict = {}
                        status_code = None
                        
                        for name, value in h3_event.headers:
                            name_str = name.decode() if isinstance(name, bytes) else str(name)
                            value_str = value.decode(errors='ignore') if isinstance(value, bytes) else str(value)
                            headers_dict[name_str] = value_str
                            
                            if name_str == ':status':
                                status_code = value_str
                        
                        responses_found.append({
                            'stream_id': getattr(h3_event, 'stream_id', 'unknown'),
                            'headers': headers_dict,
                            'status': status_code
                        })
                        
                        # If we found a status code, determine the event type
                        if status_code:
                            if status_code.startswith('4') or status_code.startswith('5'):
                                return (
                                    EventNames.REJECTED.name,
                                    f"Received {status_code} status code",
                                    responses_found
                                )
                            elif status_code.startswith('2'):
                                return (
                                    EventNames.FRAMES_SENT.name,
                                    f"Received {status_code} status code",
                                    responses_found
                                )
                            else:
                                return (
                                    EventNames.FRAMES_SENT.name,
                                    f"Received {status_code} status code",
                                    responses_found
                                )
            
            # If we found responses but no status codes
            if responses_found:
                return (
                    EventNames.FRAMES_SENT.name,
                    f"Received {len(responses_found)} response(s) without status codes",
                    responses_found
                )
            
            return None
        except Exception as e:
            return None

    async def _receive_frame(self, timeout=None) -> Optional[List[H3Event]]:
        """Helper method to receive H3 events with timeout"""
        if timeout is None:
            timeout = self.TIMEOUT
            
        try:
            start_time = time.time()
            while time.time() - start_time < timeout:
                if self.protocol and self.connection:
                    # Process QUIC events and convert to H3 events
                    h3_events = []
                    while True:
                        quic_event = self.protocol._quic.next_event()
                        if quic_event is None:
                            break
                        events = self.connection.handle_event(quic_event)
                        h3_events.extend(events)
                    if h3_events:
                        return h3_events
                await asyncio.sleep(0.01)
            return None
        except Exception as e:
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
                    while True:
                        event = self.protocol._quic.next_event()
                        if event is None:
                            break
                        quic_events.append(event)
                        # Check for connection/stream termination events
                        if isinstance(event, (ConnectionTerminated, StreamReset)):
                            return quic_events
                    
                    if quic_events:
                        break
                        
                await asyncio.sleep(0.01)
            
            return quic_events if quic_events else None
        except Exception as e:
            return None

    def set_deterministic_frames(self, frame_spec: Dict[str, Any]):
        """Set the deterministic frames to inject during communication"""
        self.deterministic_frames = frame_spec

    async def send_deterministic_frames(self, frame_type: str = "client_frames"):
        """Send deterministic frames based on the frame specification"""
        if not self.deterministic_frames or frame_type not in self.deterministic_frames:
            return EventNames.ERROR.name, [], "No deterministic frames configured"
            
        frames = self.deterministic_frames[frame_type]
        return await self.send_frames(frames)

    async def send_frames(self, frames):
        """Send frames and handle responses"""
        if not self.connection or not self.protocol:
            return EventNames.ERROR.name, [], "Connection not established"
        
        # Ensure QUIC connection is in CONNECTED state before attempting to send
        try:
            current_state = getattr(self.protocol._quic, "_state", None)
            if current_state != QuicConnectionState.CONNECTED:
                return (
                    EventNames.ERROR.name,
                    [],
                    f"Connection is not active (state={getattr(current_state, 'name', current_state)})."
                )
        except Exception:
            # If we cannot determine state, proceed cautiously
            pass
        
        sent_frames = []
        
        for frame in frames:
            try:
                # Get next available stream for the request
                stream_id = self.protocol._quic.get_next_available_stream_id()
                
                if frame.get("type") == "HEADERS":
                    headers_dict = frame.get("headers", {})
                    # Normalize scheme for HTTP/3 (always HTTPS over QUIC)
                    if ":scheme" in headers_dict and headers_dict.get(":scheme") == "http":
                        headers_dict[":scheme"] = "https"
                    headers = self._convert_headers(headers_dict)
                    end_stream = frame.get("end_stream", True)
                    
                    self.connection.send_headers(stream_id, headers, end_stream=end_stream)
                    sent_frames.append(frame)
                
                # Enable event capture BEFORE transmitting
                # This will intercept ALL calls to next_event(), even internal ones
                if hasattr(self.protocol, 'enable_capture'):
                    self.protocol.enable_capture()
                
                # Transmit the data
                self.protocol.transmit()
                
                # Wait for the response to arrive and be captured
                # The EventCapturingProtocol will intercept ALL next_event() calls
                for i in range(50):  # 50 * 1ms = 50ms initial rapid check
                    await asyncio.sleep(0.001)
                    
                    # Check captured events every 10ms
                    if i % 10 == 9:
                        if hasattr(self.protocol, 'get_captured_events'):
                            captured = self.protocol.get_captured_events()
                            if captured:
                                result = self._process_captured_events(captured)
                                if result:
                                    if hasattr(self.protocol, 'disable_capture'):
                                        self.protocol.disable_capture()
                                    event_name, message, responses = result
                                    detailed_msg = f"{message}. Responses: {responses}"
                                    return event_name, sent_frames, detailed_msg
                
                # Continue checking for slower responses
                for check_attempt in range(20):  # 20 * 100ms = 2 seconds
                    await asyncio.sleep(0.1)
                    
                    if hasattr(self.protocol, 'get_captured_events'):
                        captured = self.protocol.get_captured_events()
                        if captured:
                            result = self._process_captured_events(captured)
                            if result:
                                if hasattr(self.protocol, 'disable_capture'):
                                    self.protocol.disable_capture()
                                event_name, message, responses = result
                                detailed_msg = f"{message}. Responses: {responses}"
                                return event_name, sent_frames, detailed_msg
                
                # Disable capture if no response found
                if hasattr(self.protocol, 'disable_capture'):
                    self.protocol.disable_capture()
                        
            except Exception as e:
                return EventNames.ERROR.name, sent_frames, f"Error sending frame: {str(e)}"
        
        return EventNames.FRAMES_SENT.name, sent_frames, f"Successfully sent {len(sent_frames)} frames on stream {stream_id}."

    def _process_captured_events(self, quic_events: List[QuicEvent]) -> Optional[Tuple[str, str, List[Dict]]]:
        """Process captured QUIC events and check for responses"""
        responses_found = []
        
        for quic_event in quic_events:
            # Check for QUIC-level termination
            if isinstance(quic_event, ConnectionTerminated):
                return (
                    EventNames.REJECTED.name,
                    f"Connection terminated with error code {quic_event.error_code}",
                    [{"type": "ConnectionTerminated", "error_code": quic_event.error_code}]
                )
            
            if isinstance(quic_event, StreamReset):
                return (
                    EventNames.REJECTED.name,
                    f"Stream {quic_event.stream_id} reset with error code {quic_event.error_code}",
                    [{"type": "StreamReset", "stream_id": quic_event.stream_id, "error_code": quic_event.error_code}]
                )
            
            # Process through H3Connection to get H3 events
            try:
                h3_events = self.connection.handle_event(quic_event)
                for h3_event in h3_events:
                    if isinstance(h3_event, HeadersReceived):
                        status_code = None
                        for name, value in h3_event.headers:
                            if name == b':status':
                                status_code = value.decode()
                                break
                        
                        response_info = {
                            "type": "HeadersReceived",
                            "stream_id": h3_event.stream_id,
                            "status": status_code,
                            "headers": dict(h3_event.headers)
                        }
                        responses_found.append(response_info)
                        
                        # Check for ANY status code (we want to record all responses)
                        if status_code:
                            return (
                                EventNames.REJECTED.name,
                                f"Received HTTP status {status_code}",
                                responses_found
                            )
                    
                    elif isinstance(h3_event, DataReceived):
                        responses_found.append({
                            "type": "DataReceived",
                            "stream_id": h3_event.stream_id,
                            "data_length": len(h3_event.data) if h3_event.data else 0
                        })
            except Exception as e:
                pass
        
        if responses_found:
            return (
                EventNames.REJECTED.name,
                f"Received {len(responses_found)} response events",
                responses_found
            )
        
        return None
    
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
