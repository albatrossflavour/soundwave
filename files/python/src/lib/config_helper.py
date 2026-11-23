import configparser
import re
from subprocess import run
from os import path
import logging

logger = logging.getLogger("transformer")
basepath = path.dirname(__file__)
filepath = path.abspath(path.join(basepath, "..", "..", "config.ini"))
"""
Load transformer parameters from a configuration file.

:param config_file: Path to the configuration file.
:param section: Section in the configuration file to read.
:return: Dictionary containing transformer parameters.
"""


def load_transformer_parameters(config_file=filepath, section=None):
    config = configparser.ConfigParser()
    config.read(config_file)

    if section not in config:
        raise ValueError(f"Section {section} not found in the {config_file} file")

    transformer_params = {}
    for key in config[section]:
        if "PKCS7" in config[section][key]:
            transformer_params[key] = decrypt(config[section][key])
        else:
            transformer_params[key] = config[section][key]

    return transformer_params


def load_pe_token(pe_params):
    """Set pe_params["token"] from token_file when one is configured.

    rbac_token renews the file in place between runs, so it is read at the start
    of every run rather than once at install. Without token_file the token from
    config.ini stands.
    """
    token_file = pe_params.get("token_file", "")
    if not token_file:
        return
    try:
        with open(token_file) as f:
            token = f.read().strip()
    except OSError as e:
        raise RuntimeError(f"Cannot read the PE token from {token_file}: {e.strerror}. "
                           "rbac_token writes it on the node's next Puppet run.") from e
    if not token:
        raise RuntimeError(f"The PE token file {token_file} is empty")
    pe_params["token"] = token


"""
Decrypt agent encrypted value

:param value: Value to decrypt.
:return: Decrypted value.
"""


def decrypt(value):
    try:
        value = re.sub(" PKCS7", "PKCS7", value)
        value = re.sub(" ", chr(10), value)
        value = re.sub("PKCS7", " PKCS7", value)
        result = run(
            ["/opt/puppetlabs/bin/puppet", "node", "decrypt", "--env", "PKCS7_VALUE"],
            env={"PKCS7_VALUE": value},
            capture_output=True,
            text=True,
        )
        return result.stdout.rstrip()
    except Exception as e:
        logger.error(f"Exception occurred: {e}")
        return None
