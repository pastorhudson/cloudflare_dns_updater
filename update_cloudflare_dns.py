#!/usr/bin/env python2
from __future__ import print_function
import urllib2
import json
import sys
import logging
import ConfigParser as configparser
import os
from urlparse import urljoin, urlparse


def load_config():
    """Load configuration from config.ini file."""
    config = configparser.ConfigParser()

    # Look for config.ini in the script directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.ini')

    if not os.path.exists(config_path):
        raise IOError("Configuration file not found at {}".format(config_path))

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


def make_request(url, api_token, method='GET', data=None, params=None):
    """Make an HTTP request with proper headers and error handling."""
    headers = {
        'Authorization': 'Bearer {}'.format(api_token),
        'Content-Type': 'application/json'
    }

    # Add query parameters to URL if provided
    if params:
        param_list = []
        for key, value in params.items():
            param_list.append('{}={}'.format(key, urllib2.quote(str(value))))
        url = '{}?{}'.format(url, '&'.join(param_list))

    # Prepare the request
    if data:
        data = json.dumps(data).encode('utf-8')

    try:
        req = urllib2.Request(url, data=data, headers=headers)
        if method != 'GET':
            req.get_method = lambda: method

        response = urllib2.urlopen(req)
        return json.loads(response.read())
    except urllib2.URLError as e:
        if hasattr(e, 'code'):
            logging.error("Request failed with status code {}: {}".format(e.code, e.reason))
            if e.code == 403:
                logging.error("This might be due to an invalid API token or insufficient permissions")
        else:
            logging.error("Request failed: {}".format(e))
        if hasattr(e, 'read'):
            error_details = e.read()
            logging.error("Error details: {}".format(error_details))
        return None


def get_public_ip():
    """Get the current public IP address."""
    try:
        response = urllib2.urlopen('https://api.ipify.org?format=json', timeout=10)
        return json.loads(response.read())['ip']
    except (urllib2.URLError, ValueError) as e:
        logging.error("Failed to get public IP: {}".format(e))
        return None


def get_dns_record(zone_id, domain_name, record_type, api_token):
    """Get the current DNS record from Cloudflare."""
    url = 'https://api.cloudflare.com/client/v4/zones/{}/dns_records'.format(zone_id)
    params = {
        'name': domain_name,
        'type': record_type
    }

    response = make_request(url, api_token, params=params)
    if response and response.get('result'):
        return response['result'][0]
    return None


def update_dns_record(zone_id, record_id, domain_name, record_type, ip_address, proxied, api_token):
    """Update the DNS record with the new IP address."""
    url = 'https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}'.format(zone_id, record_id)
    data = {
        'type': record_type,
        'name': domain_name,
        'content': ip_address,
        'proxied': proxied
    }

    response = make_request(url, api_token, method='PUT', data=data)
    return response and response.get('success', False)


def get_domain_configs():
    """Get list of domain configurations from config file."""
    domains = []
    for section in config.sections():
        if section.startswith('domain:'):
            domain_config = {
                'name': config.get(section, 'domain_name'),
                'zone_id': config.get(section, 'zone_id'),
                'record_type': config.get(section, 'record_type'),
                'proxied': config.getboolean(section, 'proxied') if config.has_option(section, 'proxied') else False
            }
            domains.append(domain_config)
    return domains


def main():
    """Main function to update DNS if IP has changed."""
    logging.info("Starting Cloudflare DDNS update check")

    # Get API token
    try:
        api_token = config.get('cloudflare', 'api_token')
    except (configparser.NoSectionError, configparser.NoOptionError):
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
                logging.error("Could not get existing DNS record for {}".format(domain['name']))
                success = False
                continue

            # Check if IP needs to be updated
            if dns_record['content'] == current_ip:
                logging.info("IP address hasn't changed for {}, no update needed".format(domain['name']))
                continue

            # Update DNS record
            logging.info("Updating DNS record for {} from {} to {}".format(
                domain['name'], dns_record['content'], current_ip))
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
                logging.info("Successfully updated DNS record for {}".format(domain['name']))
            else:
                logging.error("Failed to update DNS record for {}".format(domain['name']))
                success = False

        except Exception as e:
            logging.error("Error processing domain {}: {}".format(domain['name'], str(e)))
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
        logging.error("Unexpected error: {}".format(e))
        sys.exit(1)