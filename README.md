# hash-check
Password Leak Detection

This script checks passwords against the HaveIBeenPwned API to determine if they have been compromised. It fetches data from the API using `requests` and processes the response to count leaked password hashes. The script utilizes YAML configuration for API details and logging for debugging. Error handling is implemented to gracefully manage API request failures and data processing issues, ensuring robust operation.  The core logic involves SHA1 hashing and API data parsing for efficient leak detection.
