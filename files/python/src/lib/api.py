import http.client
import json
import logging
import os
import ssl

logger = logging.getLogger("transformer")


"""
Makes a REST API call to the specified host and endpoint.

Args:
    host (str): The hostname of the server to connect to.
    endpoint (str): The API endpoint to call.
    port (int, optional): The port to connect to. Defaults to None.
    method (str, optional): The HTTP method to use (e.g., "GET", "POST"). Defaults to "GET".
    headers (dict, optional): A dictionary of HTTP headers to include in the request. Defaults to None.
    body (str, optional): The body of the request, if any. Defaults to None.
    context (ssl.SSLContext, optional): SSL context for HTTPS connection. Defaults to ssl.create_default_context().

Returns:
    dict: The JSON response from the API call if successful.
    None: If the API call fails or an exception occurs.

Raises:
    Exception: If an error occurs during the API call.
"""


def call_rest_api(
    host,
    endpoint,
    port=8146,
    method="GET",
    headers=None,
    body=None,
    context=ssl._create_unverified_context(),
    isJson=True,
    cert_verify=1,
    cert_file=None,
    key_file=None,
    ca_cert=None,
):
    try:
        # Create SSL context using the provided ca_cert
        if bool(cert_verify) and ca_cert and os.path.isfile(ca_cert):
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_cert)
            if cert_file and key_file and os.path.isfile(cert_file) and os.path.isfile(key_file):
                context.load_cert_chain(certfile=cert_file, keyfile=key_file)

        # Connect to the server
        conn = http.client.HTTPSConnection(host, port, context=context)
        conn.request(method, endpoint, body, headers if headers else {})
        response = conn.getresponse()
        data = response.read()
        conn.close()
        logger.info(f"API call to {endpoint} returned status: {response.status}")
        if isJson:
            return {"status": response.status, "data": json.loads(data)}
        else:
            return {"status": response.status, "data": data}

    except ssl.SSLError as ssl_err:
        logger.error(f"SSL error: {ssl_err}")
        return None
    except http.client.HTTPException as http_err:
        logger.error(f"HTTP error: {http_err}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return None
