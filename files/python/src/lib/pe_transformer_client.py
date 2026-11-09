import logging


import json

from .api import call_rest_api
from datetime import datetime, timezone
from os.path import exists
from os.path import dirname
# Configure logging


logger = logging.getLogger("transformer")

"""
Registers a host by making a REST API call to the specified endpoint with the provided parameters.

Args:
    pe_params (dict): A dictionary containing the following keys:
        - "name" (str): The name of the host to register.
        - "description" (str): A description of the host.
        - "token" (str): The token for authentication.
        - "host" (str): The hostname of the server to connect to.
        - "endpoint" (str): The API endpoint to call.
        - "transformer_id" (str): The transformer ID to include in the endpoint URL.
        - "cert_verify" (int, optional): Whether to verify the server's certificate. Defaults to 1.
        - "cert_file" (str, optional): The path to the client certificate file.
        - "key_file" (str, optional): The path to the client key file.
        - "ca_cert" (str, optional): The path to the CA certificate file.

Returns:
    dict: The JSON response from the API call if successful, containing the status and data.
"""


def register_host(pe_params):
    body = json.dumps(
        {"name": pe_params["name"], "description": pe_params["description"]}
    )
    headers = {
        "Content-Type": "application/json",
        "X-Authentication": pe_params["token"],
    }
    endpoint = '/vrs/v1/command/register-transformer'
    response = call_rest_api(
        pe_params["host"],
        "{0}/{1}".format(endpoint, pe_params["transformer_id"]),
        port=int(pe_params["port"]),
        method="POST",
        headers=headers,
        body=body,
        cert_verify = int(pe_params.get("cert_verify",1)),
        cert_file=pe_params.get("cert_file"),
        key_file=pe_params.get("key_file"),
        ca_cert=pe_params.get("ca_cert"),
    )
    if response is None:
        return {"status": 500, "data": "Error occured"}

    return response

"""
Posts the results of a transformer to the PE server.
Args:
    params (dict): A dictionary containing the following keys:
        - transformer_id (str): The ID of the transformer to add results to.
        - token (str): The token for authentication.
        - host (str): The hostname of the server to connect to.
        - port (int): The port number to connect to the server.
        - post_body_filepath (str): Optional filepath to output POST body.
    data (dict): The data to add to the transformer.
    scan_date (int): The timestamp of the scan date.
Returns:
    dict: A dictionary containing the status and data of the API call.
"""
def post_transformer_res_to_pe(params, data, scan_date):
    body = json.dumps(data)
    post_body_filepath = params['post_body_filepath']
    if len(post_body_filepath):
        if exists(dirname(post_body_filepath)):
            with open(post_body_filepath, "w") as f:
                f.write(body)
                logger.info(f"Request body stored at {post_body_filepath}")
        else:
            logger.info(f"Directory {dirname(post_body_filepath)} does not exist, POST Request body will not be stored")
    headers = {
        'Content-Type': 'application/json',
        'X-Authentication': params['token']
    }
    # True UTC, because the 'Z' has to mean what it says. `fromtimestamp` with
    # no tz returns local time, and the upstream nessus_transformer stamped a
    # literal 'Z' on it anyway; on a +10:00 host that told PE every scan
    # happened ten hours after it did. Consistently wrong, so ordering still
    # worked and nobody noticed, but the whole reason this sends a per-host
    # scan end rather than push time is so a stale scan cannot read as current,
    # and reporting it ahead of reality is that failure in the line that
    # reports freshness.
    #
    # Correcting it moves the date backwards by the UTC offset once, so PE
    # answers 409 until a scan genuinely passes the inflated value it already
    # holds. That is one nightly cycle and it heals itself; it is not a reason
    # to keep lying.
    scan_date = datetime.fromtimestamp(scan_date, tz=timezone.utc)
    scan_date_iso = scan_date.strftime('%Y-%m-%dT%H:%M:%SZ')
    logger.info(f"Adding results for transformer {params['transformer_id']} with scan date {scan_date_iso}")
    endpoint = "/vrs/v1/command/add-results/{0}?scan_date={1}".format(params['transformer_id'], scan_date_iso)
    response = call_rest_api(
        params["host"],
        endpoint,
        port=int(params["port"]),
        method="POST",
        headers=headers,
        body=body,
        cert_verify = int(params.get("cert_verify",1)),
        cert_file=params.get("cert_file"),
        key_file=params.get("key_file"),
        ca_cert=params.get("ca_cert"),
    )
    if response is None:
        return {'status': 500, "data": "Error occurred"}
    
    return response