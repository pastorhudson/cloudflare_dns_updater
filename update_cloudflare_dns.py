#!/usr/bin/env python
from __future__ import print_function
import urllib2
import json
import sys
import os
import logging
import ConfigParser


def load_config():
    """Load configuration from config.ini file."""
    config = ConfigParser.ConfigParser()

    # Look for config.ini in the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.ini')

    if not os.path.exists(config_path):
        raise IOError("Configuration file not found at %s" % config_path)

    config.read(config_path)
    return config


# Load configuration
config = load_config()

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.get('settings', 'log_level')),
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.get('settings', 'log_file')),
        logging.StreamHandler()
    ]
)


def make_request(url, method='GET', data=None, params=None):
    """Make an HTTP request with proper headers and error handling."""
    headers = {
        'Authorization': 'Bearer %s' % config.get('cloudflare', 'api_token'),
        'Content-Type': 'application/json'
    }

    # Add query parameters to URL if provided
    if params:
        param_list = []
        for key, value in params.items():
            param_list.append('%s=%s' % (urllib2.quote(key), urllib2.quote(str(value))))
        url = '%s?%s' % (url, '&'.join(param_list))

    # Prepare the request
    req = urllib2.Request(url)

    # Add headers
    for key, value in headers.items():
        req.add_header(key, value)

    # Set the method and data
    if data:
        req.add_data(json.dumps(data))
    if method != 'GET':
        req.get_method = lambda: method

    try:
        response = urllib2.urlopen(req)
        return json.loads(response.read())
    except urllib2.URLError as e:
        logging.error("Request failed: %s", e)
        return None


def get_public_ip():
    """Get the current public IP address."""
    try:
        response = urllib2.urlopen('https://api.ipify.org?format=json', timeout=10)
        return json.loads(response.read())['ip']
    except (urllib2.URLError, ValueError) as e:
        logging.error("Failed to get public IP: %s", e)
        return None


def get_dns_record():
    """Get the current DNS record from Cloudflare."""
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records' % config.get('cloudflare', 'zone_id')
    params = {
        'name': config.get('cloudflare', 'domain_name'),
        'type': config.get('cloudflare', 'record_type')
    }

    response = make_request(url, params=params)
    if response and response.get('result'):
        return response['result'][0]
    return None


def update_dns_record(record_id, ip_address):
    """Update the DNS record with the new IP address."""
    url = 'https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s' % (
        config.get('cloudflare', 'zone_id'),
        record_id
    )
    data = {
        'type': config.get('cloudflare', 'record_type'),
        'name': config.get('cloudflare', 'domain_name'),
        'content': ip_address,
        'proxied': config.getboolean('cloudflare', 'proxied')
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
    logging.info("Updating DNS record from %s to %s", dns_record['content'], current_ip)
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
            logging.error("Unexpected error: %s", e)


    except KeyboardInterrupt:
        logging.info("Shutting down Cloudflare DDNS updater")
        sys.exit(0)