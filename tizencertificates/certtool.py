import json
import logging
import os
import struct
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

debug_mode = False


def get_cache_path() -> Path:
    """Get the path to the cache file"""
    cache_dir = Path.home() / ".config" / "tizen-cert"
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir / "config.json"


def load_cached_config() -> Optional[Dict[str, str]]:
    """Load cached configuration if it exists and is valid"""
    cache_path = get_cache_path()
    if not cache_path.exists():
        return None

    try:
        with open(cache_path, "r") as f:
            data = json.load(f)

        # Check if cache is expired (7 days)
        cached_time = datetime.fromisoformat(data.get("timestamp", "2000-01-01"))
        if datetime.now() - cached_time > timedelta(days=7):
            logging.info("Cache expired, will fetch fresh configuration")
            return None

        required_keys = ["SERVICE_ID", "loginUrl", "DISTRIBUTOR_URL", "AUTHOR_URL"]
        if all(key in data for key in required_keys):
            logging.info("Using cached configuration")
            return {
                "SERVICE_ID": data.get("SERVICE_ID", None),
                "loginUrl": data.get("loginUrl", None),
                "DISTRIBUTOR_URL": data.get("DISTRIBUTOR_URL", None),
                "AUTHOR_URL": data.get("AUTHOR_URL", None),
            }
        else:
            missing_keys = [key for key in required_keys if key not in data]
            logging.warning(
                f"Cached configuration is missing required keys: {', '.join(missing_keys)}"
            )
            return None
    except Exception as e:
        logging.warning(f"Failed to load cache: {e}")

    return None


def save_config_cache(config: Dict[str, str]):
    """Save configuration to cache"""
    cache_path = get_cache_path()
    try:
        cache_data = {
            "SERVICE_ID": config["SERVICE_ID"],
            "loginUrl": config["loginUrl"],
            "DISTRIBUTOR_URL": config["DISTRIBUTOR_URL"],
            "AUTHOR_URL": config["AUTHOR_URL"],
            "timestamp": datetime.now().isoformat(),
        }
        with open(cache_path, "w") as f:
            json.dump(cache_data, f, indent=2)
        logging.info("Saved configuration to cache")
    except Exception as e:
        logging.warning(f"Failed to save cache: {e}")


def initialize_server_config(
    use_cached_config: bool = True, use_cached_zip: bool = False
) -> Dict[str, str]:
    """Initialize server configuration, using cache if available"""
    # Try to load from cache first
    if use_cached_config:
        cached_config = load_cached_config()
        if cached_config:
            return cached_config

    variables = {
        "SERVICE_ID": None,
        "loginUrl": None,
        "DISTRIBUTOR_URL": None,
        "AUTHOR_URL": None,
    }

    # Download and process configuration
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
    }
    response = requests.get(
        "https://download.tizen.org/sdk/tizenstudio/official/extension_info.xml",
        headers=headers,
    )
    if response.status_code == 200:
        logging.info("Downloaded repository XML. Getting certificate extension URL.")
        tree = ET.ElementTree(ET.fromstring(response.text))
        root = tree.getroot()

        url = None
        for extension in root:
            extension_dict = {}
            for tag in extension:
                extension_dict[tag.tag] = tag.text
            if "name" in extension_dict:
                if extension_dict["name"] == "Samsung Certificate Extension":
                    if "repository" in extension_dict:
                        url = extension_dict["repository"].strip()

    if not url:
        logging.warning("Could not find url, using default")
        url = "https://download.tizen.org/sdk/extensions/tizen-certificate-extension_2.0.74.zip"

    if not use_cached_zip or not os.path.exists(
        os.path.join(os.path.dirname(__file__), "certificate_extension.zip")
    ):
        logging.info("Downloading certificate extension zip file")
        zip_response = requests.get(url)
        if zip_response.status_code == 200:
            with open("certificate_extension.zip", "wb") as f:
                f.write(zip_response.content)

    logging.info("Extracting certificate extension zip file")
    # Extract certificates and configuration
    with zipfile.ZipFile("certificate_extension.zip", "r") as extension_zip_ref:
        for extension_member in extension_zip_ref.infolist():
            ext_fn = extension_member.filename.split("/")[-1]
            if ext_fn.startswith("cert-add-on") and ext_fn.endswith("ubuntu-64.zip"):
                binary_zipfile = extension_zip_ref.read(extension_member.filename)
                with zipfile.ZipFile(BytesIO(binary_zipfile), "r") as binary_zip_ref:
                    for binary_member in binary_zip_ref.infolist():
                        fn = binary_member.filename.split("/")[-1]

                        if fn.startswith("org.tizen.common.cert") and fn.endswith(
                            ".jar"
                        ):
                            jarfile = binary_zip_ref.read(binary_member.filename)

                            with zipfile.ZipFile(BytesIO(jarfile), "r") as jar_ref:
                                for member in jar_ref.infolist():
                                    fn = member.filename.split("/")[-1]

                                    if member.filename.endswith(
                                        ".cer"
                                    ) or member.filename.endswith(".crt"):
                                        member.filename = fn
                                        jar_ref.extract(member, "ca")

                                    # Debugging: print all constants from any class with http in their value
                                    if debug_mode:
                                        if member.filename.endswith(".class"):
                                            constants = get_constants(
                                                BytesIO(jar_ref.read(member.filename))
                                            )
                                            for i, constant in enumerate(constants):
                                                if all(
                                                    x in constant
                                                    for x in ["https", "apis/"]
                                                ):
                                                    logging.info(
                                                        f"{constants[i - 1]}: {constants[i]} in "
                                                        f"{member.filename}"
                                                    )

                                    if any(
                                        x in member.filename
                                        for x in [
                                            "SigninDialog.class",
                                            "CertConstant.class",
                                        ]
                                    ):
                                        constants = get_constants(
                                            BytesIO(jar_ref.read(member.filename))
                                        )

                                        for i, constant in enumerate(constants):
                                            try:
                                                if constant in variables:
                                                    variables[constant] = constants[
                                                        i + 1
                                                    ]
                                            except Exception as e:
                                                logging.info(e)
                                                pass

    # Cache the configuration if it was successfully retrieved
    if variables["SERVICE_ID"] and variables["loginUrl"]:
        save_config_cache(variables)
    else:
        logging.error("Failed to get complete configuration")

    return variables


def read_bytes(fh, count: int) -> bytes:
    """Read specified number of bytes from file handle"""
    return fh.read(count)


def bytes_to_int(b: bytes) -> int:
    """Convert bytes to integer based on length"""
    if len(b) == 1:
        return b[0]
    elif len(b) == 2:
        return struct.unpack(">H", b)[0]
    elif len(b) == 4:
        return struct.unpack(">I", b)[0]
    elif len(b) == 8:
        return struct.unpack(">Q", b)[0]
    raise ValueError(f"Cannot convert {len(b)} bytes to int")


def parse_utf8(fh) -> str:
    """Parse UTF8 constant"""
    length = bytes_to_int(read_bytes(fh, 2))
    return read_bytes(fh, length).decode("utf-8")


def parse_constant(fh, tag: int) -> Tuple[Optional[str], bool]:
    """
    Parse a single constant based on its tag.
    Returns a tuple of (value, takes_two_slots) where takes_two_slots indicates
    if this constant takes up two slots in the constant pool (true for LONG and DOUBLE).
    """
    if tag == 0:  # Padding entry
        return None, False
    elif tag == 1:  # CONSTANT_Utf8
        return parse_utf8(fh), False
    elif tag in (3, 4):  # CONSTANT_Integer or CONSTANT_Float
        val = bytes_to_int(read_bytes(fh, 4))
        return str(val), False
    elif tag in (5, 6):  # CONSTANT_Long or CONSTANT_Double
        val = bytes_to_int(read_bytes(fh, 8))
        return str(val), True  # These types take up two slots
    elif tag == 7:  # CONSTANT_Class
        # Skip index
        read_bytes(fh, 2)
        return None, False
    elif tag == 8:  # CONSTANT_String
        # Skip string index
        read_bytes(fh, 2)
        return None, False
    elif tag in (
        9,
        10,
        11,
    ):  # CONSTANT_Fieldref, CONSTANT_Methodref, CONSTANT_InterfaceMethodref
        # Skip class and name/type indices
        read_bytes(fh, 4)
        return None, False
    elif tag == 12:  # CONSTANT_NameAndType
        # Skip name and descriptor indices
        read_bytes(fh, 4)
        return None, False
    else:
        raise ValueError(f"Unknown constant tag: {tag}")


def get_constants(class_bytes: BytesIO) -> List[str]:
    """
    Parse a Java class file from bytes and return a list of its constants as strings.
    Only includes actual constant values (strings, numbers), not structural constants.

    Args:
        class_bytes (BytesIO): BytesIO object containing the Java class file contents

    Returns:
        list[str]: List of constants as strings
    """
    constants = []

    # Skip magic number
    read_bytes(class_bytes, 4)

    # Skip version info
    read_bytes(class_bytes, 4)

    # Read constant pool count
    const_count = bytes_to_int(read_bytes(class_bytes, 2)) - 1

    # Parse constants
    i = 0
    while i < const_count:
        tag = bytes_to_int(read_bytes(class_bytes, 1))
        value, takes_two_slots = parse_constant(class_bytes, tag)
        if value is not None:
            constants.append(value)
        if takes_two_slots:
            i += 1  # Skip the next slot as it's used for padding
        i += 1

    return constants


# #Summary of commands

# # Get access token here:
# # https://account.samsung.com/accounts/TDC/signInGate?clientId=<SERVICE_ID>&tokenType=TOKEN

# # Find the CA certificates here:
# # https://gitlab.com/andreas-mausch/moonwatch/-/tree/master/certificates

# # Author certificate
# openssl genrsa -out author.key.pem 2048
# openssl rsa -in author.key.pem -outform PEM -pubout -out author.key.pem.pub
# openssl req -new -key author.key.pem -out author.csr -subj "/CN=gear-certificate@protonmail.com"
# curl -v -X POST https://dev.tizen.samsung.com:443/apis/v2/authors -F access_token=<ACCESS_TOKEN> -F user_id=<USER_ID> -F csr=@author.csr --output author.crt
# cat author.crt ca/gear_test_author_CA.cer > author-and-ca.crt
# openssl pkcs12 -export -out author.p12 -inkey author.key.pem -in author-and-ca.crt -name usercertificate

# # Distributor certificate
# openssl genrsa -out distributor.key.pem 2048
# openssl rsa -in distributor.key.pem -outform PEM -pubout -out distributor.key.pem.pub
# openssl req -new -key distributor.key.pem -out distributor.csr -subj "/CN=TizenSDK" -addext "subjectAltName = URI:URN:tizen:packageid=,URI:URN:tizen:deviceid=<DEVICE_ID>"
# curl -v -X POST https://dev.tizen.samsung.com:443/apis/v2/distributors -F access_token=<ACCESS_TOKEN> -F user_id=<USER_ID> -F privilege_level=Public -F developer_type=Individual -F csr=@distributor.csr --output distributor.crt
# cat distributor.crt ca/samsung_tizen_dev_public2.crt > distributor-and-ca.crt
# openssl pkcs12 -export -out distributor.p12 -inkey distributor.key.pem -in distributor-and-ca.crt -name usercertificate

# Generating certificates for TV (VD) looks a bit different:

# # Author certificate VD
# openssl req -new -key author.key.pem -out author.csr -subj "/CN=<EMAIL_OR_NAME>"
# curl -v -X POST https://dev.tizen.samsung.com:443/apis/v2/authors -F access_token=<ACCESS_TOKEN> -F user_id=<USER_ID> -F platform=VD -F csr=@author.csr --output author.crt
# cat author.crt ca/vd_tizen_dev_author_ca.cer > author-and-ca.crt
# openssl pkcs12 -export -out author.p12 -inkey author.key.pem -in author-and-ca.crt -name usercertificate -legacy

# # Distributor certificate VD
# openssl req -new -key distributor.key.pem -out distributor.csr -subj "/CN=TizenSDK/emailAddress=<EMAIL>" -addext "subjectAltName = URI:URN:tizen:packageid=,URI:URN:tizen:deviceid=<DEVICE_ID>"
# curl -v -X POST https://dev.tizen.samsung.com:443/apis/v2/distributors -F access_token=<ACCESS_TOKEN> -F user_id=<USER_ID> -F platform=VD -F privilege_level=Public -F developer_type=Individual -F csr=@distributor.csr --output distributor.crt
# cat distributor.crt ca/vd_tizen_dev_public2.crt > distributor-and-ca.crt
# openssl pkcs12 -export -out distributor.p12 -inkey distributor.key.pem -in distributor-and-ca.crt -name usercertificate -legacy
