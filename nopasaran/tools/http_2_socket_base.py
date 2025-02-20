import time
import select
import h2.connection
import h2.config
import h2.events
from nopasaran.tools.checks import function_map
from nopasaran.definitions.events import EventNames
from nopasaran.http_2_utils import (
    SSL_CONFIG,
    send_frame
)

class HTTP2SocketBase:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None
        self.conn = None
        self.MAX_RETRY_ATTEMPTS = 3
        self.TIMEOUT = 5

    def _receive_frame(self) -> bytes:
        """Helper method to receive data"""
        start_time = time.time()
        socket_to_check = self.sock if not hasattr(self, 'client_socket') else self.client_socket
        
        while True:
            elapsed_time = time.time() - start_time
            if elapsed_time > self.TIMEOUT:
                return None
            
            ready_to_read, _, _ = select.select([socket_to_check], [], [], self.TIMEOUT)
            
            if ready_to_read:
                frame = socket_to_check.recv(SSL_CONFIG.MAX_BUFFER_SIZE)
                return frame

    def send_frames(self, frames):
        """Send frames based on test case"""
        socket_to_use = self.sock if not hasattr(self, 'client_socket') else self.client_socket
        sent_frames = []
        
        for frame in frames:
            send_frame(self.conn, socket_to_use, frame)
            sent_frames.append(frame)
        
        # Add a small delay to ensure frames are transmitted
        # time.sleep(0.1)

        return EventNames.FRAMES_SENT.name, str(sent_frames)

    def _handle_test(self, event, frame) -> bool | int | None:
        """
        Handle test cases for received frames.
        Each scenario can have multiple tests, where each test contains multiple checks.
        A test passes if all its checks pass. A scenario passes if one of its tests passes.

        Returns:
            - True if the test passed
            - False if the test failed
            - None if no tests were found for that frame
        """
        tests = frame.get('tests', [])

        if not tests:
            return None, None
        
        for test_index, test in enumerate(tests, 1):
            all_checks_passed = True
            
            # Try all checks in this test
            for check in test:
                function_name = check['function']
                params = check['params']
                
                function = function_map.get(function_name)

                # check if check exists
                if not function:
                    all_checks_passed = False
                    break
                
                if not function(event, *params):
                    all_checks_passed = False
                    break
            
            if all_checks_passed:
                return True, test_index  # Exit after first successful test
        
        # If we get here, all tests failed
        return False, None
    
    def wait_for_preface(self) -> str:
        """Wait for preface"""
        data = self._receive_frame()
        if data is None:
            return EventNames.TIMEOUT.name, "Timeout occurred while waiting for preface", None
        
        events = self.conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.RemoteSettingsChanged):
                outbound_data = self.conn.data_to_send()  # This will generate SETTINGS ACK
                if outbound_data:
                    socket_to_use = self.sock if not hasattr(self, 'client_socket') else self.client_socket
                    socket_to_use.sendall(outbound_data)

                return EventNames.PREFACE_RECEIVED.name, "Preface received", str(event)

        return EventNames.ERROR.name, "Proxy returned an error", str(events)
    
        
    def wait_for_preface_ack(self) -> str:
        """Wait for PREFACE_ACK frame"""
        data = self._receive_frame()
        if data is None:
            return EventNames.TIMEOUT.name, "Timeout occurred while waiting for PREFACE_ACK frame"
        
        events = self.conn.receive_data(data)
        for event in events:
            if isinstance(event, h2.events.SettingsAcknowledged):
                outbound_data = self.conn.data_to_send()
                if outbound_data:
                    socket_to_use = self.sock if not hasattr(self, 'client_socket') else self.client_socket
                    socket_to_use.sendall(outbound_data)

        return EventNames.ACK_RECEIVED.name, "PREFACE_ACK frame received"
    
    def receive_test_frames(self, test_frames) -> str:
        """Wait for test frames"""
        frames_received = []
        retry_count = 0
        initial_settings_received = False
        initial_ack_received = False
        expected_frame_count = len(test_frames)
        
        while retry_count < self.MAX_RETRY_ATTEMPTS:
            data = self._receive_frame()
            
            if data is None:
                retry_count += 1
                if retry_count >= self.MAX_RETRY_ATTEMPTS:
                    return EventNames.TIMEOUT.name, f"Timeout occurred after {retry_count} attempts. Received {len(frames_received)}/{expected_frame_count} frames", str(frames_received)
                continue
            
            # Check if it's a HEADERS frame (type = 0x1)
            if len(data) >= 4:  # Make sure we have enough data to check frame type
                frame_type = data[3]
                is_headers = frame_type == 0x1
                print(f"Received frame type: {hex(frame_type)}")  # Debug info
            
            events = self.conn.receive_data(data)
            
            for event in events:
                if isinstance(event, h2.events.ConnectionTerminated):
                    return EventNames.CONNECTION_TERMINATED.name, "Proxy terminated the connection", str(frames_received)
                
                # Skip initial settings frame
                if isinstance(event, h2.events.RemoteSettingsChanged):
                    settings = event.changed_settings.items()
                    if len(settings) == 7:
                        continue
                
                # Skip initial settings ACK
                if isinstance(event, h2.events.SettingsAcknowledged):
                    if not initial_ack_received:
                        initial_ack_received = True
                        continue

                if isinstance(event, h2.events.StreamEnded):
                    continue

                frames_received.append(event)
                
                # Check tests after each frame is received
                for expected_frame in test_frames:
                    result, test_index = self._handle_test(event, expected_frame)
                    if result is True:
                        return EventNames.TEST_COMPLETED.name, f'Test {test_index} passed with frame {event}', str(frames_received)
            
            # If we've received all expected frames and no test has passed,
            # we should return with a failure
            if len(frames_received) >= expected_frame_count:
                if expected_frame_count == 0:
                    if len(frames_received) == 0:
                        return EventNames.TEST_COMPLETED.name, "No test frames were received or expected", str(frames_received)
                    else:
                        return EventNames.TEST_COMPLETED.name, f"Received {len(frames_received)} frames but no frames were expected", str(frames_received)
                
                return EventNames.TEST_COMPLETED.name, f"Received {len(frames_received)}/{expected_frame_count} frames but all tests failed", str(frames_received)

        return EventNames.TIMEOUT.name, f"Timeout occurred after {retry_count} attempts. Received {len(frames_received)}/{expected_frame_count} frames", str(frames_received)
    
    def close(self):
        """Close the HTTP/2 connection and clean up resources"""
        try:
            if self.conn:
                # Send GOAWAY frame to indicate graceful shutdown
                self.conn.close_connection()
                socket_to_use = self.sock if not hasattr(self, 'client_socket') else self.client_socket
                if socket_to_use:
                    socket_to_use.sendall(self.conn.data_to_send())
            
            # Close sockets
            if hasattr(self, 'client_socket') and self.client_socket:
                self.client_socket.close()
            if self.sock:
                self.sock.close()
            
            # Clear references
            self.conn = None
            if hasattr(self, 'client_socket'):
                self.client_socket = None
            self.sock = None
            
            return EventNames.CONNECTION_CLOSED.name
        except Exception as e:
            return EventNames.ERROR.name