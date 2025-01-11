# cloudflare_dns_updater
A simple script to update Cloudflare dyndns record

## Python 2
- update_cloudflare_dns.py

## Python 3
- update_cloudflare_dns3.py

## Update config.ini
```
[cloudflare]
api_token = your_api_token_here
zone_id = your_zone_id_here
domain_name = your.domain.com
record_type = A
proxied = true

[settings]
check_interval = 300
log_file = cloudflare_ddns.log
log_level = INFO
```

The script runs once and writes to config file specified in the config.ini

Run it with crontab.