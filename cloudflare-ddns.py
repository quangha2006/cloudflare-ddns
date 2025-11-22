import requests, json, sys, signal, os, time, threading, argparse, logging
import socket
import dns.resolver
import ipaddress
import urllib3

# We call Cloudflare's trace endpoint by IP (1.1.1.1). TLS certificate
# verification will fail for IP literals in some environments, so we
# suppress the InsecureRequestWarning and disable verification only for
# these trace requests below. This is a pragmatic choice for IP-based
# detection; consider switching to a hostname-based endpoint if you
# require strict TLS verification.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class GracefulExit:
  def __init__(self):
    self.kill_now = threading.Event()
    signal.signal(signal.SIGINT, self.exit_gracefully)
    signal.signal(signal.SIGTERM, self.exit_gracefully)

  def exit_gracefully(self, signum, frame):
        logger.info("Stopping main thread...")
        self.kill_now.set()

# module-level logger (configured in __main__)
logger = logging.getLogger(__name__)

def custom_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    # If host is already an IP literal, return it directly (no DNS lookup)
    try:
        ip_obj = ipaddress.ip_address(host)
        if isinstance(ip_obj, ipaddress.IPv6Address):
            # For IPv6 return AF_INET6 tuple (addr, port, flowinfo, scopeid)
            return [(socket.AF_INET6, socket.SOCK_STREAM, proto, '', (host, port, 0, 0))]
        else:
            return [(socket.AF_INET, socket.SOCK_STREAM, proto, '', (host, port))]
    except ValueError:
        # print("Resolving DNS for host: {0}".format(host))
        # not an IP literal, proceed to DNS resolution
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['1.1.1.1']
        # Short lifetime so we don't block too long when DNS server is unreachable
        resolver.lifetime = 5
        try:
            if family == socket.AF_INET6:
                answer = resolver.resolve(host, 'AAAA')
            else:
                answer = resolver.resolve(host, 'A')

            ip = answer[0].to_text()
            return [(socket.AF_INET, socket.SOCK_STREAM, proto, '', (ip, port))]
        except Exception:
            # Per request: do NOT fallback — raise standard getaddrinfo error
            raise socket.gaierror(socket.EAI_NONAME, 'Name or service not known')

def wait_with_interrupt(total_seconds, event, interval=1):
    """Wait up to total_seconds but return earlier if event is set.

    Uses short intervals to remain responsive to signals that set the event.
    Returns True if the event was set during the wait, otherwise False.
    """
    waited = 0.0
    while waited < total_seconds:
        to_wait = min(interval, total_seconds - waited)
        if event.wait(to_wait):
            return True
        waited += to_wait
    return event.is_set()

def deleteEntries(type):
    # Helper function for deleting A or AAAA records
    # in the case of no IPv4 or IPv6 connection, yet
    # existing A or AAAA records are found.
    for option in config["cloudflare"]:
        answer = cf_api(
            "zones/" + option['zone_id'] + "/dns_records?per_page=100&type=" + type,
            "GET", option)
    if answer is None or answer["result"] is None:
        time.sleep(5)
        return
    for record in answer["result"]:
        identifier = str(record["id"])
        cf_api(
            "zones/" + option['zone_id'] + "/dns_records/" + identifier, 
            "DELETE", option)
        logger.info("Deleted stale record {0}".format(identifier))

def getIPs():
    a = None
    aaaa = None
    response = None
    global ipv4_enabled
    global ipv6_enabled
    global killer
    retryTime = 5
    if ipv4_enabled:
        #Check ip
        loopcount = 0
        while True:
            if loopcount > 0:
                logger.info("Will retry after {0} seconds".format(retryTime))
                if wait_with_interrupt(retryTime, killer.kill_now, interval=1):
                    return None
                logger.warning("Now let me continue... {0}".format(loopcount))
            loopcount += 1
            try:
                # Use verify=False because we're connecting to an IP literal
                # which can cause TLS certificate verification to fail.
                response = requests.get("https://1.1.1.1/cdn-cgi/trace", verify=False)
                if response.ok:
                    a = response.text.split("\n")
                    break
                else:
                    logger.error("Error sending Get request to {0} with ErrorCode: {1}".format(response.url, response.status_code))
                    continue
            except requests.exceptions.RequestException as err:
                logger.error("OOps: Something Else {0}".format(err))
                continue
            except requests.exceptions.HTTPError as errh:
                logger.error("Http Error: {0}".format(errh))
                continue
            except requests.exceptions.ConnectionError as errc:
                logger.error("Error Connecting: {0}".format(errc))
                continue
            except requests.exceptions.Timeout as errt:
                logger.error("Timeout Error: {0}".format(errt))
                continue

        try:
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
        except Exception as e:
            global shown_ipv4_warning
            if not shown_ipv4_warning:
                shown_ipv4_warning = True
                logger.warning("🧩 IPv4 not detected")
            # Always use IPv4,
            # deleteEntries("A")

    if ipv6_enabled:
        try:
            # IPv6 literal; similarly disable cert verification for this probe
            aaaa = requests.get("https://[2606:4700:4700::1111]/cdn-cgi/trace", verify=False).text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception as e:
            global shown_ipv6_warning
            if not shown_ipv6_warning:
                shown_ipv6_warning = True
                logger.warning("IPv6 not detected")
            deleteEntries("AAAA")
    ips = {}
    if(a is not None):
        ips["ipv4"] = {
            "type": "A",
            "ip": a
        }
    if(aaaa is not None):
        ips["ipv6"] = {
            "type": "AAAA",
            "ip": aaaa
        }
    return ips

def commitRecord(ip):
    for option in config["cloudflare"]:
        subdomains = option["subdomains"]
        getZoneResponse = cf_api("zones/" + option['zone_id'], "GET", option)
        if getZoneResponse is None:
            return
        
        base_domain_name = getZoneResponse.json().get("result", {}).get("name")
        if not base_domain_name:
            return
        
        ttl = 300 # default Cloudflare TTL
        for subdomain in subdomains:
            subdomain = subdomain.lower().strip()
            proxi = option["proxied"]["default"]
            if subdomain != '' and subdomain in option["proxied"]:
                proxi = option["proxied"][subdomain]
            record = {
                "type": ip["type"],
                "name": subdomain,
                "content": ip["ip"],
                "proxied": proxi,
                "ttl": ttl
            }
            dnsRecordsResponse = cf_api(
                "zones/" + option['zone_id'] + "/dns_records?per_page=100&type=" + ip["type"], 
                "GET", option)
            
            dns_records = dnsRecordsResponse.json() if dnsRecordsResponse else None
            fqdn = base_domain_name
            if subdomain:
                fqdn = subdomain + "." + base_domain_name
            identifier = None
            modified = False
            duplicate_ids = []
            old_record_content = None
            if dns_records is not None:
                for r in dns_records["result"]:
                    if (r["name"] == fqdn):
                        if identifier:
                            if r["content"] == ip["ip"]:
                                duplicate_ids.append(identifier)
                                identifier = r["id"]
                            else:
                                duplicate_ids.append(r["id"])
                        else:
                            identifier = r["id"]
                            if r['content'] != record['content'] or r['proxied'] != record['proxied']:
                                modified = True
                                old_record_content = r['content']
            if identifier:
                if modified:
                    if record['name'] is None or record['name'] == '':
                        record['name'] = '@'
                    logger.info("Current record content {0}".format(old_record_content))
                    response = cf_api(
                        "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                        "PUT", option, {}, record)
                    logger.info("Update Record Response: {0}".format(response.json()))
                else:
                    logger.info("Record {0} is up to date!".format(record))
            else:
                logger.info("Adding new record {0}".format(record))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records", "POST", option, {}, record)
                logger.info("Add Record Response: {0}".format(response.json()))
            for identifier in duplicate_ids:
                identifier = str(identifier)
                logger.info("Deleting stale record {0}".format(identifier))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                    "DELETE", option)
                logger.info("Delete Record Response: {0}".format(response.json()))
    return True

def cf_api(endpoint, method, config, headers={}, data=False):

    api_token = config['authentication']['api_token']
    if api_token != '' and api_token != 'api_token_here':
        headers = {
            "Authorization": "Bearer " + api_token,
            **headers
        }
    else:
        headers = {
            "X-Auth-Email": config['authentication']['api_key']['account_email'],
            "X-Auth-Key": config['authentication']['api_key']['api_key'],
        }

    try:
        response = None
        if(data == False):
            response = requests.request(method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers)
        else:
            response = requests.request(method, "https://api.cloudflare.com/client/v4/" + endpoint, headers=headers, json=data)
        if response.ok:
            return response
        else:
            logger.error("Error sending {0} request to {1} with ErrorCode: {2}".format(method, response.url, response.status_code))
            return None
    except requests.exceptions.RequestException as err:
        logger.error("OOps: Something Else {0}".format(err))
    except requests.exceptions.HTTPError as errh:
        logger.error("Http Error: {0}".format(errh))
    except requests.exceptions.ConnectionError as errc:
        logger.error("Error Connecting: {0}".format(errc))
    except requests.exceptions.Timeout as errt:
        logger.error("Timeout Error: {0}".format(errt))

    return None

def updateIPs(ips):
    if ips is not None:
        for ip in ips.values():
            logger.info("Updating record for IP: {0}".format(ip))
            commitRecord(ip)
    else:
        logger.error("OOps: Something wrong, No ip detected, waiting for the next time")

def readConfigFile(pathConfig):
    try:
        with open(pathConfig) as config_file:
            configLoaded = json.loads(config_file.read())
    except Exception as e:
        logger.error("Error reading {0!s}, Exception: {1!s}".format(pathConfig, e))
        return None
    return configLoaded

if __name__ == '__main__':
    configFilePath = "config.json"
    # CLI parsing: allow overriding config path and running in repeat mode
    parser = argparse.ArgumentParser()
    parser.add_argument('--repeat', action='store_true', help='Run in repeat mode using repeattime from config')
    parser.add_argument('--config', '-c', default=configFilePath, help='Path to config.json')
    parser.add_argument('--log-level', default='INFO', choices=['DEBUG','INFO','WARNING','ERROR'], help='Set log level')
    args, _ = parser.parse_known_args()
    configFilePath = args.config

    # Configure logging from CLI option
    numeric_level = getattr(logging, args.log_level.upper(), logging.INFO)
    logging.basicConfig(level=numeric_level, format='%(asctime)s %(levelname)s %(message)s', datefmt='%m/%d/%Y, %H:%M:%S')
    logger.setLevel(numeric_level)
    version_major = int(str(sys.version_info[0]))
    version_minor = int(str(sys.version_info[1]))
    version_micro = int(str(sys.version_info[2]))
    shown_ipv4_warning = True
    shown_ipv6_warning = False
    ipv4_enabled = True
    ipv6_enabled = False
    delaytime = 15
    killer = GracefulExit()

    if(version_major < 3 or (version_major == 3 and version_minor < 5) ):
        raise Exception("🐍 This script requires Python 3.5+, Current Version = {0}".format(str(sys.version_info)))

    config = readConfigFile(configFilePath)
    if config is None:
        if args.repeat:
            logger.info("Exit after 10s")
            time.sleep(10) # wait 30 seconds to prevent excessive logging on docker auto restart

    if config is not None:
        try:
            ipv4_enabled = config["a"]
            ipv6_enabled = config["aaaa"]
            delaytime = config["repeattime"]
        except:
            ipv4_enabled = True
            ipv6_enabled = True
            logger.error("⚙️ Individually disable IPv4 or IPv6 with new config.json options. Read more about it here: https://github.com/quangha2006/cloudflare-ddns/README.md")
        socket.getaddrinfo = custom_getaddrinfo
        if args.repeat:
                delay = delaytime * 60
                if ipv4_enabled and ipv6_enabled:
                    logger.info("Updating IPv4 (A) & IPv6 (AAAA) records every {0} minutes".format(delaytime))
                elif ipv4_enabled and not ipv6_enabled:
                    logger.info("Updating IPv4 (A) records every {0} minutes".format(delaytime))
                elif ipv6_enabled and not ipv4_enabled:
                    logger.info("Updating IPv6 (AAAA) records every {0} minutes".format(delaytime))
                next_time = time.time()
                prev_ips = None
                while True:
                    # Update config
                    config = readConfigFile(configFilePath)

                    if config is not None:
                        ipv4_enabled = config["a"]
                        ipv6_enabled = config["aaaa"]
                        delay = config["repeattime"] * 60
                        updateIPs(getIPs())
                    else: # if any problem with the config file
                        delay = 300
                    # Wait until next time, or exit if signaled
                    if wait_with_interrupt(delay, killer.kill_now, interval=1):
                        break
        else:
            updateIPs(getIPs())