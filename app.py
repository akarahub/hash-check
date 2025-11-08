import requests
import hashlib
import sys
from typing import List
import argparse
import yaml
import logging
from datetime import datetime

# YAML config
try:
    with open(r".\config.yaml", "r") as f:
        config = yaml.safe_load(f)
except Exception as e:
    raise

# Logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(funcName)s - %(message)s",
    filename=config["log_dir"] +
    f"{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}.log",
    filemode="w"
)
logger = logging.getLogger(__name__)

logger.info("Config file and logger setup completed.")


def fetch_api_data(query_char: str) -> requests.Response:
    """
    Fetches data from the HaveIBeenPwned API for a given query character.

    Args:
        query_char: The query character to search for.

    Returns:
        The response object from the API.

    Raises:
        RuntimeError: If the API request fails.
    """
    url = config["API_BASE_URL"] + query_char
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching data from API: {e}")
        raise


def get_password_leak_count(response: requests.Response, hash_to_check: str) -> int:
    """
    Processes the API response to determine the number of times a password hash has been leaked.

    Args:
        response: The response object from the API.
        hash_to_check: The password hash to search for.

    Returns:
        The number of times the password hash has been leaked, or 0 if not found.
    """
    try:
        hashes = (line.split(":") for line in response.text.splitlines())
        count = 0
        for h, c in hashes:
            if h == hash_to_check:
                count = int(c)  # Convert count to integer
                break
        return count
    except (ValueError, IndexError) as e:
        logger.warning(f"Error processing API response: {e}")
        return 0


def check_password_pwned(password: str) -> int:
    """
    Checks a password against the HaveIBeenPwned API.

    Args:
        password: The password to check.

    Returns:
        The number of times the password has been leaked, or 0 if not found.
    """
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    try:
        response = fetch_api_data(first5_char)
        leak_count = get_password_leak_count(response, tail)
        return leak_count
    except Exception as e:
        logger.error(f"Error checking password {password}: {e}")
        return 0


def run(args: List[str]) -> int:
    """
    Main function to check passwords against the HaveIBeenPwned API.

    Args:
        args: A list of passwords to check.

    Returns:
        An exit code (0 for success, non-zero for failure).
    """
    exit_code = 0
    for password in args:
        count = check_password_pwned(password)
        if count:
            print(f"{password} was found {count} times!")
            logger.info(f"{password} was found {count} times!")
        else:
            print(f"{password} was NOT found!")
            logger.info(f"{password} was NOT found!")
    return exit_code

# parser = argparse.ArgumentParser(description="Check a password against the HaveIBeenPwned API.")
# parser.add_argument("-p", "--passwords", metavar="", nargs="+", help="List of passwords to check.")
# args = parser.parse_args()


sys.exit(run(sys.argv[1:]))
