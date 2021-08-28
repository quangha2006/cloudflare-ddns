import requests, json, sys, signal, os, time, threading
from datetime import datetime, timezone
import pytz

class GracefulExit:
  def __init__(self):
    self.kill_now = threading.Event()
    signal.signal(signal.SIGINT, self.exit_gracefully)
    signal.signal(signal.SIGTERM, self.exit_gracefully)

  def exit_gracefully(self, signum, frame):
    print("🛑 Stopping main thread...")
    self.kill_now.set()

def getDateTime():
    now = datetime.now()
    timezone = pytz.timezone("asia/ho_chi_minh")
    date_time = now.astimezone(timezone)
    return date_time.strftime("%m/%d/%Y, %H:%M:%S")

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
        print("{0} 🗑️ Deleted stale record {1}".format(getDateTime(), identifier))

def getIPs():
    a = None
    aaaa = None
    response = None
    global ipv4_enabled
    global ipv6_enabled
    if ipv4_enabled:
        #Check ip
        loopcount = 0
        while True:
            date_time = getDateTime()
            if loopcount > 6:
                break
            if loopcount > 0:
                time.sleep(120)
                print("{0} Now let me continue... {1}".format(date_time, loopcount))
            loopcount += 1
            try:
                response = requests.get("https://1.1.1.1/cdn-cgi/trace")
                if response.ok:
                    a = response.text.split("\n")
                    break
                else:
                    print("{0} 📈 Error sending Get request to {1} with ErrorCode: {2}".format(date_time, response.url, response.status_code))
                    continue
            except requests.exceptions.RequestException as err:
                print("{0} OOps: Something Else {1}".format(date_time, err))
                continue
            except requests.exceptions.HTTPError as errh:
                print("{0} Http Error: {1}".format(date_time,errh))
                continue
            except requests.exceptions.ConnectionError as errc:
                print("{0} Error Connecting: {1}".format(date_time, errc))
                continue
            except requests.exceptions.Timeout as errt:
                print("{0} Timeout Error: {1}".format(date_time, errt))
                continue

        try:
            a.pop()
            a = dict(s.split("=") for s in a)["ip"]
        except Exception as e:
            global shown_ipv4_warning
            if not shown_ipv4_warning:
                shown_ipv4_warning = True
                print("🧩 IPv4 not detected")
            # Always use IPv4,
            # deleteEntries("A")

    if ipv6_enabled:
        try:
            aaaa = requests.get("https://[2606:4700:4700::1111]/cdn-cgi/trace").text.split("\n")
            aaaa.pop()
            aaaa = dict(s.split("=") for s in aaaa)["ip"]
        except Exception as e:
            global shown_ipv6_warning
            if not shown_ipv6_warning:
                shown_ipv6_warning = True
                print("🧩 IPv6 not detected")
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
    date_time = getDateTime()
    for option in config["cloudflare"]:
        subdomains = option["subdomains"]
        response = cf_api("zones/" + option['zone_id'], "GET", option)
        if response is None or response["result"]["name"] is None:
            time.sleep(5)
            return
        base_domain_name = response["result"]["name"]
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
            dns_records = cf_api(
                "zones/" + option['zone_id'] + "/dns_records?per_page=100&type=" + ip["type"], 
                "GET", option)
            fqdn = base_domain_name
            if subdomain:
                fqdn = subdomain + "." + base_domain_name
            identifier = None
            modified = False
            duplicate_ids = []
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
            if identifier:
                if modified:
                    print("{0} 📡 Updating record {1}".format(date_time,record))
                    response = cf_api(
                        "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                        "PUT", option, {}, record)
            else:
                print("{0} ➕ Adding new record {1}".format(date_time,record))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records", "POST", option, {}, record)
            for identifier in duplicate_ids:
                identifier = str(identifier)
                print("{0} 🗑️ Deleting stale record {1}".format(date_time, identifier))
                response = cf_api(
                    "zones/" + option['zone_id'] + "/dns_records/" + identifier,
                    "DELETE", option)
    return True

def cf_api(endpoint, method, config, headers={}, data=False):

    date_time = getDateTime()

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
            return response.json()
        else:
            print("{0} 📈 Error sending {1} request to {2} with ErrorCode: {3}".format(date_time, method, response.url, response.status_code))
            return None
    except requests.exceptions.RequestException as err:
        print("{0} OOps: Something Else {1}".format(date_time, err))
    except requests.exceptions.HTTPError as errh:
        print("{0} Http Error: {1}".format(date_time,errh))
    except requests.exceptions.ConnectionError as errc:
        print("{0} Error Connecting: {1}".format(date_time, errc))
    except requests.exceptions.Timeout as errt:
        print("{0} Timeout Error: {1}".format(date_time, errt))

    return None

def updateIPs(ips):
    if ips is not None:
        for ip in ips.values():
            commitRecord(ip)
    else:
        date_time = getDateTime()
        print("{0} OOps: Something wrong, No ip detected, waiting for the next time".format(date_time))

if __name__ == '__main__':
    PATH = os.getcwd() + "/"
    version = float(str(sys.version_info[0]) + "." + str(sys.version_info[1]))
    shown_ipv4_warning = False
    shown_ipv6_warning = False
    ipv4_enabled = True
    ipv6_enabled = True
    delaytime = 15

    if(version < 3.5):
        raise Exception("🐍 This script requires Python 3.5+")

    config = None
    try:
        with open(PATH + "config.json") as config_file:
            config = json.loads(config_file.read())
    except Exception as e:
        print("😡 Error reading config.json, Exception: {0}".format(e))
        time.sleep(60) # wait 60 seconds to prevent excessive logging on docker auto restart

    if config is not None:
        try:
            ipv4_enabled = config["a"]
            ipv6_enabled = config["aaaa"]
            delaytime = config["repeattime"]
        except:
            ipv4_enabled = True
            ipv6_enabled = True
            print("⚙️ Individually disable IPv4 or IPv6 with new config.json options. Read more about it here: https://github.com/timothymiller/cloudflare-ddns/blob/master/README.md")
        if(len(sys.argv) > 1):
            if(sys.argv[1] == "--repeat"):
                delay = delaytime * 60
                date_time = getDateTime()
                if ipv4_enabled and ipv6_enabled:
                    print("{0} 🕰️ Updating IPv4 (A) & IPv6 (AAAA) records every {1} minutes".format(date_time, delaytime))
                elif ipv4_enabled and not ipv6_enabled:
                    print("{0} 🕰️ Updating IPv4 (A) records every {1} minutes".format(date_time, delaytime))
                elif ipv6_enabled and not ipv4_enabled:
                    print("{0} 🕰️ Updating IPv6 (AAAA) records every {1} minutes".format(date_time, delaytime))
                next_time = time.time()
                killer = GracefulExit()
                prev_ips = None
                while True:
                    if killer.kill_now.wait(delay):
                        break
                    updateIPs(getIPs())
            else:
                print("❓ Unrecognized parameter '" + sys.argv[1] + "'. Stopping now.")
        else:
            updateIPs(getIPs())