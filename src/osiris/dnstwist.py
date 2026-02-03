import subprocess
import json
import sys

def run_dnstwist(domain):
    try:
        cmd = [sys.executable, "-m", "dnstwist", "--format", "json", domain]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        data = json.loads(result.stdout)

        if not data:
            return None  # No results

        processed = []
        for entry in data:
            domain_name = entry.get("domain")
            if not domain_name:
                continue

            dns_a_raw = entry.get("dns_a", [])
            # Normalize dns_a: exclude entries like "!ServFail"
            dns_a = [ip for ip in dns_a_raw if not ip.startswith("!")] if dns_a_raw else []

            processed.append({
                "domain": domain_name,
                "fuzzer": entry.get("fuzzer"),
                "dns_a": dns_a,
                "dns_ns": entry.get("dns_ns", []),
                "dns_mx": entry.get("dns_mx", []),
                "whois_created": entry.get("whois_created"),
                "whois_updated": entry.get("whois_updated"),
                "whois_expires": entry.get("whois_expires"),
            })

        return processed if processed else None

    except subprocess.CalledProcessError as e:
        print(f"[!] Error running dnstwist: {e.stderr.strip()}")
        return None
    except FileNotFoundError:
        print("[!] Python executable not found for dnstwist execution.")
        return None
    except json.JSONDecodeError:
        print("[!] Failed to parse JSON output from dnstwist.")
        return None
