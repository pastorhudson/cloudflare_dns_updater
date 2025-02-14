#!/usr/bin/env python3
import urllib.request
import urllib.error
import urllib.parse
import json
import sys
import logging
import configparser
from pathlib import Path
from typing import Dict, List, Optional


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


def make_request(url: str, api_token: str, method: str = 'GET', data: Optional[Dict] = None,
                 params: Optional[Dict] = None) -> Optional[Dict]:
    """Make an HTTP request with proper headers and error handling."""
    headers = {
        'Authorization': f'Bearer {api_token}',
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
        if hasattr(e, 'code'):
            logging.error(f"Request failed with status code {e.code}: {e.reason}")
            if e.code == 403:
                logging.error("This might be due to an invalid API token or insufficient permissions")
        else:
            logging.error(f"Request failed: {e}")
        if hasattr(e, 'read'):
            error_details = e.read().decode('utf-8')
            logging.error(f"Error details: {error_details}")
        return None


def get_public_ip() -> Optional[str]:
    """Get the current public IP address."""
    try:
        with urllib.request.urlopen('https://api.ipify.org?format=json', timeout=10) as response:
            return json.loads(response.read().decode('utf-8'))['ip']
    except (urllib.error.URLError, json.JSONDecodeError) as e:
        logging.error(f"Failed to get public IP: {e}")
        return None


def get_dns_record(zone_id: str, domain_name: str, record_type: str, api_token: str) -> Optional[Dict]:
    """Get the current DNS record from Cloudflare."""
    url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records'
    params = {
        'name': domain_name,
        'type': record_type
    }

    response = make_request(url, api_token, params=params)
    if response and response.get('result'):
        return response['result'][0]
    return None


def update_dns_record(zone_id: str, record_id: str, domain_name: str, record_type: str, ip_address: str, proxied: bool,
                      api_token: str) -> bool:
    """Update the DNS record with the new IP address."""
    url = f'https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}'
    data = {
        'type': record_type,
        'name': domain_name,
        'content': ip_address,
        'proxied': proxied
    }

    response = make_request(url, api_token, method='PUT', data=data)
    return response and response.get('success', False)


def get_domain_configs() -> List[Dict]:
    """Get list of domain configurations from config file."""
    domains = []
    for section in config.sections():
        if section.startswith('domain:'):
            domain_config = {
                'name': config[section]['domain_name'],
                'zone_id': config[section]['zone_id'],
                'record_type': config[section]['record_type'],
                'proxied': config[section].getboolean('proxied', fallback=False)
            }
            domains.append(domain_config)
    return domains


def main() -> bool:
    """Main function to update DNS if IP has changed."""
    logging.info("Starting Cloudflare DDNS update check")

    # Get API token
    try:
        api_token = config['cloudflare']['api_token']
    except KeyError:
        logging.error("API token not found in config")
        return False

    # Get current public IP
    current_ip = get_public_ip()
    if not current_ip:
        logging.error("Could not get current public IP")
        return False

    # Get all domain configurations
    domains = get_domain_configs()
    if not domains:
        logging.error("No domain configurations found")
        return False

    success = True
    for domain in domains:
        try:
            # Get existing DNS record
            dns_record = get_dns_record(
                domain['zone_id'],
                domain['name'],
                domain['record_type'],
                api_token
            )

            if not dns_record:
                logging.error(f"Could not get existing DNS record for {domain['name']}")
                success = False
                continue

            # Check if IP needs to be updated
            if dns_record['content'] == current_ip:
                logging.info(f"IP address hasn't changed for {domain['name']}, no update needed")
                continue

            # Update DNS record
            logging.info(f"Updating DNS record for {domain['name']} from {dns_record['content']} to {current_ip}")
            update_success = update_dns_record(
                domain['zone_id'],
                dns_record['id'],
                domain['name'],
                domain['record_type'],
                current_ip,
                domain['proxied'],
                api_token
            )

            if update_success:
                logging.info(f"Successfully updated DNS record for {domain['name']}")
            else:
                logging.error(f"Failed to update DNS record for {domain['name']}")
                success = False

        except Exception as e:
            logging.error(f"Error processing domain {domain['name']}: {e}")
            success = False

    return success


if __name__ == "__main__":
    try:
        logging.info("Starting Cloudflare DDNS updater")
        main()
    except KeyboardInterrupt:
        logging.info("Shutting down Cloudflare DDNS updater")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        sys.exit(1)
