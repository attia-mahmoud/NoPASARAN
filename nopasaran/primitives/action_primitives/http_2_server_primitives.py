from nopasaran.decorators import parsing_decorator
from nopasaran.tools.http_2_socket_server import HTTP2SocketServer

class HTTP2ServerPrimitives:
    """
    Class containing HTTP/2 server action primitives for the state machine.
    """

    @staticmethod
    @parsing_decorator(input_args=2, output_args=1)
    def create_http_2_server(inputs, outputs, state_machine):
        """
        Create an instance of HTTP2SocketServer.

        Number of input arguments: 2
            - The host
            - The port

        Number of output arguments: 1
            - The created HTTP2SocketServer instance

        Args:
            inputs (List[str]): The list of input variable names. No input arguments for this method.

            outputs (List[str]): The list of output variable names. It contains one output argument:
                - The name of the variable to store the HTTP2SocketServer instance.

            state_machine: The state machine object.

        Returns:
            None
        """
        host = state_machine.get_variable_value(inputs[0])
        port = state_machine.get_variable_value(inputs[1])
        port = int(port)
        server = HTTP2SocketServer(host, port)
        state_machine.set_variable_value(outputs[0], server)


    @staticmethod
    @parsing_decorator(input_args=4, output_args=0)
    def start_http_2_server(inputs, outputs, state_machine):
        """
        Start the HTTP/2 server.

        Number of input arguments: 4
            - The HTTP2SocketServer instance
            - The tls_enabled flag
            - The TLS protocol to use
            - The connection settings for the server

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names containing:
                - The name of the HTTP2SocketServer instance variable
                - The name of the tls_enabled flag variable
                - The name of the TLS protocol variable
                - The name of the connection settings variable

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        server = state_machine.get_variable_value(inputs[0])
        tls_enabled = state_machine.get_variable_value(inputs[1])
        protocol = state_machine.get_variable_value(inputs[2])
        connection_settings_server = state_machine.get_variable_value(inputs[3])

        if tls_enabled == 'true':
            tls_enabled = True
        else:
            tls_enabled = False

        server.start(tls_enabled, protocol, connection_settings_server)

    @staticmethod
    @parsing_decorator(input_args=1, output_args=0)
    def wait_for_client_preface(inputs, outputs, state_machine):
        """
        Wait for the client's connection preface.

        Number of input arguments: 1
            - The HTTP2SocketServer instance

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names containing:
                - The name of the HTTP2SocketServer instance variable

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        server = state_machine.get_variable_value(inputs[0])
        server.wait_for_client_preface()
    
    @staticmethod
    @parsing_decorator(input_args=1, output_args=0)
    def wait_for_client_ack(inputs, outputs, state_machine):
        """
        Wait for the client's SETTINGS_ACK frame.

        Number of input arguments: 1
            - The HTTP2SocketServer instance

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names containing:
                - The name of the HTTP2SocketServer instance variable

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        server = state_machine.get_variable_value(inputs[0])
        server.wait_for_client_ack()

    @staticmethod
    @parsing_decorator(input_args=2, output_args=1)
    def receive_client_frames(inputs, outputs, state_machine):
        """
        Wait for the client's frames.

        Number of input arguments: 2
            - The HTTP2SocketServer instance
            - The client frames to receive

        Number of output arguments: 1
            - The result of the tests (if any)

        Args:
            inputs (List[str]): The list of input variable names containing:
                - The name of the HTTP2SocketServer instance variable
                - The name of the client frames variable

            outputs (List[str]): The list of output variable names. It contains one output argument:
                - The name of the variable to store the result of the tests

            state_machine: The state machine object.

        Returns:
            None
        """
        server = state_machine.get_variable_value(inputs[0])
        client_frames = state_machine.get_variable_value(inputs[1])
        result = server.receive_client_frames(client_frames)
        state_machine.set_variable_value(outputs[0], result)
    
    @staticmethod
    @parsing_decorator(input_args=2, output_args=0)
    def send_server_frames(inputs, outputs, state_machine):
        """
        Send the server's frames.

        Number of input arguments: 2
            - The HTTP2SocketServer instance
            - The frames to send

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names containing:
                - The name of the HTTP2SocketServer instance variable
                - The name of the server frames variable

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        server = state_machine.get_variable_value(inputs[0])
        server_frames = state_machine.get_variable_value(inputs[1])
        server.send_frames(server_frames)

    @staticmethod
    @parsing_decorator(input_args=1, output_args=0)
    def close_server_connection(inputs, outputs, state_machine):
        """
        Close the connection.

        Number of input arguments: 1
            - The HTTP2SocketServer instance

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names containing:
                - The name of the HTTP2SocketServer instance variable

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        server = state_machine.get_variable_value(inputs[0])
        server.close_connection()