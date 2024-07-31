from nopasaran.decorators import parsing_decorator

from nopasaran.tools.http_1_response_handler import HTTP1ResponseHandler

class HTTP1ResponsePrimitives:
    """
    Class containing HTTP server action primitives for the state machine.
    """

    @staticmethod
    @parsing_decorator(input_args=5, output_args=0)
    def add_http_1_route(inputs, outputs, state_machine):
        """
        Add a route to the HTTP server.

        Number of input arguments: 5
            - The path
            - The method (e.g., 'GET', 'POST')
            - The response body
            - The status code (default: 200)
            - The headers (optional, dictionary format)

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names. It contains five mandatory input arguments:
                - The name of the variable containing the path.
                - The name of the variable containing the method.
                - The name of the variable containing the response body.
                - The name of the variable containing the status code.
                - The name of the variable containing the headers.

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        path = state_machine.get_variable_value(inputs[0])
        method = state_machine.get_variable_value(inputs[1])
        response_body = state_machine.get_variable_value(inputs[2])
        status_code = int(state_machine.get_variable_value(inputs[3]))
        headers = state_machine.get_variable_value(inputs[4])

        HTTP1ResponseHandler.add_route(path, method, response_body, status_code, headers)

    @staticmethod
    @parsing_decorator(input_args=2, output_args=0)
    def remove_http_1_route(inputs, outputs, state_machine):
        """
        Remove a route from the HTTP server.

        Number of input arguments: 2
            - The path
            - The method (e.g., 'GET', 'POST')

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names. It contains two mandatory input arguments:
                - The name of the variable containing the path.
                - The name of the variable containing the method.

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        path = state_machine.get_variable_value(inputs[0])
        method = state_machine.get_variable_value(inputs[1])

        HTTP1ResponseHandler.remove_route(path, method)

    @staticmethod
    @parsing_decorator(input_args=2, output_args=0)
    def wait_for_http_1_request(inputs, outputs, state_machine):
        """
        Wait for an HTTP request.

        Number of input arguments: 2
            - The port to run the server on.
            - The timeout duration in seconds.

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names. It contains two mandatory input arguments:
                - The name of the variable containing the port.
                - The name of the variable containing the timeout duration.

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        port = int(state_machine.get_variable_value(inputs[0]))
        timeout = int(state_machine.get_variable_value(inputs[1]))
        
        HTTP1ResponseHandler.wait_for_request(state_machine, port=port, timeout=timeout)

    @staticmethod
    @parsing_decorator(input_args=4, output_args=0)
    def add_http_1_response_header(inputs, outputs, state_machine):
        """
        Add a header to a route on the HTTP server.

        Number of input arguments: 4
            - The path
            - The method (e.g., 'GET', 'POST')
            - The header name
            - The header value

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names. It contains four mandatory input arguments:
                - The name of the variable containing the path.
                - The name of the variable containing the method.
                - The name of the variable containing the header name.
                - The name of the variable containing the header value.

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        path = state_machine.get_variable_value(inputs[0])
        method = state_machine.get_variable_value(inputs[1])
        header_name = state_machine.get_variable_value(inputs[2])
        header_value = state_machine.get_variable_value(inputs[3])

        HTTP1ResponseHandler.add_header(path, method, header_name, header_value)

    @staticmethod
    @parsing_decorator(input_args=3, output_args=0)
    def remove_http_1_response_header(inputs, outputs, state_machine):
        """
        Remove a header from a route on the HTTP server.

        Number of input arguments: 3
            - The path
            - The method (e.g., 'GET', 'POST')
            - The header name

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names. It contains three mandatory input arguments:
                - The name of the variable containing the path.
                - The name of the variable containing the method.
                - The name of the variable containing the header name.

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        path = state_machine.get_variable_value(inputs[0])
        method = state_machine.get_variable_value(inputs[1])
        header_name = state_machine.get_variable_value(inputs[2])

        HTTP1ResponseHandler.remove_header(path, method, header_name)

    @staticmethod
    @parsing_decorator(input_args=2, output_args=0)
    def add_http_1_response_content_length_header(inputs, outputs, state_machine):
        """
        Add a Content-Length header to a route on the HTTP server.

        Number of input arguments: 2
            - The path
            - The method (e.g., 'GET', 'POST')

        Number of output arguments: 0

        Args:
            inputs (List[str]): The list of input variable names. It contains two mandatory input arguments:
                - The name of the variable containing the path.
                - The name of the variable containing the method.

            outputs (List[str]): The list of output variable names. No output arguments for this method.

            state_machine: The state machine object.

        Returns:
            None
        """
        path = state_machine.get_variable_value(inputs[0])
        method = state_machine.get_variable_value(inputs[1])

        HTTP1ResponseHandler.add_content_length_header(path, method)
