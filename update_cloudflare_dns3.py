#!/usr/bin/env python3
import urllib.request
import urllib.error
import urllib.parse
import json
import sys
import logging
import configparser
from pathlib import Path


def load_config():
    """Load configuration from config.ini file."""
    config = configparser.ConfigParser()

    # Look for config.ini in the script directory
    script_dir = Path(__file__).parent
    config_path = script_dir / 'config.ini'

    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found at {config_path}")

    config.read(config_path)
    return config


# Load configuration
config = load_config()

# Configure logging
logging.basicConfig(
    level=getattr(logging, config['settings']['log_level']),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config['settings']['log_file']),
        logging.StreamHandler()
    ]
)


def make_request(url, method='GET', data=None, params=None):
    """Make an HTTP request with proper headers and error handling."""
    headers = {
        'Authorization': f'Bearer {config["cloudflare"]["api_token"]}',
        'Content-Type': 'application/json'
    }

    # Add query parameters to URL if provided
    if params:
        query_string = urllib.parse.urlencode(params)
        url = f"{url}?{query_string}"

    # Prepare the request
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode('utf-8') if data else None,
        headers=headers,
        method=method
    )

    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode('utf-8'))
    except urllib.error.URLError as e:
        logging.error(f"Request failed: {e}")
        return None


def get_public_ip():
    """Get the current public IP address."""
    try:
        with urllib.request.urlopen('https://api.ipify.org?format=json', timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))['ip']
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        logging.error(f"Failed to get public IP: {e}")
        return None


def get_dns_record():
    """Get the current DNS record from Cloudflare."""
    url = f'https://api.cloudflare.com/client/v4/zones/{config["cloudflare"]["zone_id"]}/dns_records'
    params = {
        'name': config['cloudflare']['domain_name'],
        'type': config['cloudflare']['record_type']
    }

    response = make_request(url, params=params)
    if response and response.get('result'):
        return response['result'][0]
    return None


def update_dns_record(record_id, ip_address):
    """Update the DNS record with the new IP address."""
    url = f'https://api.cloudflare.com/client/v4/zones/{config["cloudflare"]["zone_id"]}/dns_records/{record_id}'
    data = {
        'type': config['cloudflare']['record_type'],
        'name': config['cloudflare']['domain_name'],
        'content': ip_address,
        'proxied': config['cloudflare'].getboolean('proxied')
    }

    response = make_request(url, method='PUT', data=data)
    return response and response.get('success', False)


def main():
    """Main function to update DNS if IP has changed."""
    logging.info("Starting Cloudflare DDNS update check")

    # Get current public IP
    current_ip = get_public_ip()
    if not current_ip:
        logging.error("Could not get current public IP")
        return False

    # Get existing DNS record
    dns_record = get_dns_record()
    if not dns_record:
        logging.error("Could not get existing DNS record")
        return False

    # Check if IP needs to be updated
    if dns_record['content'] == current_ip:
        logging.info("IP address hasn't changed, no update needed")
        return True

    # Update DNS record
    logging.info(f"Updating DNS record from {dns_record['content']} to {current_ip}")
    success = update_dns_record(dns_record['id'], current_ip)

    if success:
        logging.info("Successfully updated DNS record")
        return True
    else:
        logging.error("Failed to update DNS record")
        return False


if __name__ == "__main__":
    try:
        logging.info("Starting Cloudflare DDNS updater")

        try:
            main()
        except Exception as e:
            logging.error(f"Unexpected error: {e}")


    except KeyboardInterrupt:
        logging.info("Shutting down Cloudflare DDNS updater")
        sys.exit(0)