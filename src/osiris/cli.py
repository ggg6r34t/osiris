import argparse
import json
import os
import sys
from datetime import datetime

from rich.console import Console
from rich.table import Table

from osiris.clone_detector import detect_clones
from osiris.data.platforms import PLATFORM_TEMPLATES
from osiris.domain_matcher import find_similar_domains
from osiris.enrichment import enrich, is_valid_domain
from osiris.dnstwist import run_dnstwist
from osiris.exporter import export_data
from osiris.input_handler import parse_input
from osiris.link_opener import open_links_in_browser, list_available_browsers
from osiris.logger import log_search_history, log_event
from osiris.platform_functions import add_custom_platform, remove_custom_platform, list_custom_platforms, \
    load_platform_templates
from osiris.run_phishing_dorks import run_phishing_dorks
from osiris.search_links import generate_search_links
from osiris.text_clone_search import text_clone_search
from osiris.utils import print_banner, fuzzy_match_platforms, check_link_status, group_links_by_category, \
    print_enrichment_result, print_search_links
from osiris.utils import dedupe_links
from osiris.threat_scoring import score_threat
from osiris.variant_generator import generate_typosquatting_domains
from osiris.config import load_config, apply_proxy_env

console = Console()

def parse_args():

    categories = list(PLATFORM_TEMPLATES.keys())
    all_platforms = []
    for platforms in PLATFORM_TEMPLATES.values():
        all_platforms.extend(platforms.keys())

    platform_help = (
        "List of platforms or categories to search. "
        f"Categories: {', '.join(categories)}. "
    )

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
                Examples:
                    ./osiris Tesla --platforms social_networks --open
                    ./osiris "Elon Musk" -p reddit github --export csv
                    ./osiris --text-detect "We never ask for your password"
                    ./osiris --clone-detect paypal.com
                    ./osiris paypal.com --enrich
                    ./osiris "Elon Musk" -p reddit github --enrich spacex.com
        """
        ,
    )
    parser.add_argument("target", nargs="?", help="Target name, company, or username")
    parser.add_argument(
        "-p", "--platforms", nargs="+", help=platform_help
    )
    parser.add_argument(
        "--config", type=str, default=None, help="Path to a JSON config file"
    )
    parser.add_argument(
        "--json", action="store_true", help="Output machine-readable JSON to stdout"
    )
    parser.add_argument(
        "--targets-file", type=str, default=None,
        help="Path to a file containing one target per line"
    )
    parser.add_argument(
        "--tag", type=str, default=None,
        help="Tag to include in logs/exports for investigations"
    )
    parser.add_argument(
        "-f", "--fuzzy", action="store_true", help="Enable fuzzy matching for platforms"
    )
    parser.add_argument(
        "-d", "--dnstwist",
        nargs="?", const=True,
        help="Run dnstwist on a domain (e.g., google.com)"
    )
    parser.add_argument(
        "-e", "--enrich",
        nargs="?",               # Optional value
        const=True,
        help="Enrich a domain with WHOIS, DNS, hosting, and abuse info (e.g., paypal.com)."
    )
    parser.add_argument(
        "-x", "--export", choices=["csv", "json", "txt"], help="Export format for results"
    )
    parser.add_argument(
        "-o", "--output", default="results", help="Output file base name (no extension)"
    )
    parser.add_argument(
        "-O", "--open", action="store_true", help="Open links in browser"
    )
    parser.add_argument(
        "-b", "--browser", type=str,
        help="Browser to use for opening links (e.g., 'firefox', 'chrome'). Defaults to system browser."
    )
    parser.add_argument(
        "-l", "--list-browsers", action="store_true", help="List all available browsers on the system "
                                                     "(Windows only; others may require manual setup)."
    )
    parser.add_argument("-s", "--save-dir", type=str, default="exports",
                        help="Directory to save exported files (default: exports)")
    parser.add_argument(
        "-r", "--randomize", action="store_true", help="Randomize link opening order"
    )
    parser.add_argument(
        "--open-delay", type=float, default=0.5,
        help="Delay (seconds) between opening browser tabs (default: 0.5)"
    )
    parser.add_argument(
        "--max-open", type=int, default=0,
        help="Maximum number of links to open (0 = no limit)"
    )
    parser.add_argument(
        "-c", "--check", action="store_true", help="Check link status before opening"
    )
    parser.add_argument(
        "--check-timeout", type=int, default=None,
        help="Timeout (seconds) for link status checks (default: 5)"
    )
    parser.add_argument(
        "--check-retries", type=int, default=None,
        help="Retry count for link status checks (default: 2)"
    )
    parser.add_argument(
        "--user-agent", type=str, default=None,
        help="Custom User-Agent for HTTP requests (overrides OSIRIS_USER_AGENT)"
    )
    parser.add_argument(
        "--insecure", action="store_true",
        help="Disable TLS verification for link status checks"
    )
    parser.add_argument(
        "--request-timeout", type=float, default=None,
        help="Default HTTP timeout for enrichment and network requests"
    )
    parser.add_argument(
        "--rate-limit", type=float, default=None,
        help="Max HTTP requests per second for link checks (0 = no limit)"
    )
    parser.add_argument(
        "--max-links", type=int, default=None,
        help="Maximum number of links to return after filtering (0 = no limit)"
    )
    parser.add_argument(
        "--dedupe", action="store_true",
        help="Remove duplicate URLs from results"
    )
    parser.add_argument(
        "--exclude-platforms", nargs="+", default=None,
        help="Platforms to exclude from results"
    )
    parser.add_argument(
        "--exclude-categories", nargs="+", default=None,
        help="Categories to exclude from results"
    )
    parser.add_argument(
        "--score", action="store_true",
        help="Annotate results with threat score labels"
    )
    parser.add_argument(
        "--sort-score", action="store_true",
        help="Sort results by threat score (requires --score)"
    )
    parser.add_argument(
        "--proxy", type=str, default=None,
        help="Proxy URL for HTTP/HTTPS requests (e.g., http://127.0.0.1:8080)"
    )
    parser.add_argument(
        "--tor", action="store_true",
        help="Route HTTP(S) requests through Tor (socks5h://127.0.0.1:9050)"
    )
    parser.add_argument("-C", "--clone-detect", metavar="DOMAIN", type=str,
                        help='Detect cloned websites for a given domain')
    parser.add_argument(
        "-t", "--text-detect",
        type=str,
        help="Provide a block of legitimate site text to detect copycat phishing/clones"
    )
    parser.add_argument("-D", "--deep-search", action="store_true", help="Perform an extensive deep OSINT scan")
    parser.add_argument("-m", "--domain-match", help="Detect similar or suspicious domains (e.g., paypal.com)")
    parser.add_argument("-a", "--add-custom-platform", nargs=3, metavar=("CATEGORY", "NAME", "URL"),
                        help="Add a custom platform: CATEGORY NAME URL")
    parser.add_argument("-R", "--remove-custom-platform", nargs=2, metavar=("CATEGORY", "NAME"),
                        help="Remove a user-added custom platform")
    parser.add_argument("-L", "--list-custom-platforms", action="store_true",
                        help="List all user-added custom platforms")
    parser.add_argument(
        "-T", "--load-custom-template",
        type=str,
        help='Load custom platform templates (overrides defaults unless --platforms is used).'
    )
    parser.add_argument(
        "-g", "--log", action="store_true", help="Log search history"
    )
    parser.add_argument("-P", "--list-platforms", action="store_true",
                        help="List all supported platforms and categories")
    parser.add_argument("-n", "--no-banner", action="store_true", help="Suppress ASCII banner output")

    args = parser.parse_args()

    # Optional: Print all platforms and categories
    if args.list_platforms:
        print("\n🧠 Available Categories and Platforms:\n")
        for category, platforms in PLATFORM_TEMPLATES.items():
            print(f"[{category}]")
            for name in platforms:
                print(f"  • {name}")
        sys.exit(0)

    return args, parser

def main():
    args, parser = parse_args()

    config = load_config(args.config)
    if args.json:
        config["json_output"] = True
    if args.user_agent:
        config["user_agent"] = args.user_agent
    if args.request_timeout is not None:
        config["request_timeout"] = args.request_timeout
    if args.rate_limit is not None:
        config["rate_limit_per_sec"] = args.rate_limit
    if args.proxy:
        config["http_proxy"] = args.proxy
        config["https_proxy"] = args.proxy
    if args.tor:
        config["http_proxy"] = "socks5h://127.0.0.1:9050"
        config["https_proxy"] = "socks5h://127.0.0.1:9050"
    if args.insecure:
        config["verify_tls"] = False

    apply_proxy_env(config)
    os.environ["OSIRIS_REQUEST_TIMEOUT"] = str(config.get("request_timeout", 10))
    os.environ["OSIRIS_USER_AGENT"] = str(config.get("user_agent", "Osiris/1.0"))
    os.environ["OSIRIS_VERIFY_TLS"] = "true" if config.get("verify_tls", True) else "false"
    if config.get("http_proxy"):
        os.environ["OSIRIS_HTTP_PROXY"] = config["http_proxy"]
    if config.get("https_proxy"):
        os.environ["OSIRIS_HTTPS_PROXY"] = config["https_proxy"]

    json_mode = bool(config.get("json_output"))
    check_timeout = args.check_timeout if args.check_timeout is not None else int(
        config.get("check_timeout", config.get("request_timeout", 5))
    )
    check_retries = args.check_retries if args.check_retries is not None else int(config.get("check_retries", 2))
    rate_limit = float(config.get("rate_limit_per_sec", 0))
    max_links = args.max_links if args.max_links is not None else int(config.get("max_links", 0))

    def output_json(payload):
        print(json.dumps(payload, ensure_ascii=False, indent=2))

    if len(sys.argv) == 1:
        print_banner()
        parser.print_help()
        sys.exit(0)

    if args.targets_file and any([
        args.deep_search, args.clone_detect, args.text_detect, args.dnstwist, args.enrich, args.domain_match
    ]):
        console.print("[bold red]Error:[/bold red] --targets-file is only supported for standard searches.")
        sys.exit(1)

    if args.sort_score and not args.score:
        console.print("[bold red]Error:[/bold red] --sort-score requires --score.")
        sys.exit(1)

    if args.enrich:
        # If --enrich has a domain, use it; otherwise, fall back to target
        enrich_domain = args.enrich if isinstance(args.enrich, str) else args.target

        if not is_valid_domain(enrich_domain):
            console.print("[bold red]❌ Error:[/bold red] Please provide a valid domain to enrich (e.g., paypal.com).")
            sys.exit(1)

        result = enrich(f"http://{enrich_domain}")

        if json_mode:
            output_json({"target": enrich_domain, "result": result})
        else:
            console.rule(f"[bold green]Running Enrichment on {enrich_domain}")
            print_enrichment_result(result)

        if args.log:
            log_event("enrichment_complete", {"target": enrich_domain})

        # from rich.syntax import Syntax
        # import json
        # console.print(Syntax(json.dumps(result, indent=2), "json", theme="monokai", line_numbers=False))

        if not json_mode:
            console.rule("[bold green]Enrichment Complete")
        sys.exit(0)

    if not args.no_banner and not json_mode:
        print_banner()

    if args.domain_match:
        matches = find_similar_domains(args.domain_match)

        if json_mode:
            output_json({"target": args.domain_match, "matches": matches})
            sys.exit(0)

        if matches:
            print("\n🛑 Suspicious domain matches found:\n")
            for m in matches:
                print(f"→ {m['domain']}  (Matched Variant: {m['matched_variant']})")
                if m['whois']:
                    print(
                        f"   WHOIS: Registrar: {m['whois'].get('registrar')}, Created: {m['whois'].get('creation_date')}")
        else:
            print("✅ No suspicious domains found.")

    if args.deep_search:
        if not args.target:
            console.print("[bold red]Error:[/] --deep-search requires either a --target or --domain to be specified.")
            sys.exit(1)

        target = args.target

        if not json_mode:
            console.print(f"[cyan bold]🕵️ Running Deep Search on:[/] {target}\n")

        results = {}

        if "." in target:
            enriched = enrich(target, is_url=True)
            results["enrichment"] = enriched

            typo_domains = find_similar_domains(target)
            results["typo_domains"] = typo_domains

            clones = detect_clones(target, [d['domain'] for d in typo_domains])
            results["clone_sites"] = clones

        text_clones = text_clone_search(
            [target],
            open_browser=False,
            browser_name=args.browser,
            randomize=args.randomize,
            quiet=json_mode,
        )
        results["text_clones"] = text_clones

        platforms = ["all"]
        platform_templates = load_platform_templates(custom_path=args.load_custom_template, use_default=True)
        platform_links = generate_search_links(target, platforms, platform_templates)
        results["platform_links"] = platform_links

        dork_results = run_phishing_dorks([target], quiet=json_mode)
        results["phishing_dorks"] = dork_results

        # Normalize domain-based results into link dictionaries
        typo_links = [
            {"platform": "Lookalike Domain", "category": "domain", "url": f"http://{d['domain']}"}
            for d in results.get("typo_domains", []) if isinstance(d, dict) and d.get("domain")
        ]
        clone_links = [
            {"platform": "Clone Candidate", "category": "domain", "url": f"http://{d}"}
            for d in results.get("clone_sites", []) if isinstance(d, str)
        ]

        # Combine all links to open in browser
        all_links = (
            typo_links +
            clone_links +
            results.get("text_clones", []) +
            results.get("platform_links", []) +
            results.get("phishing_dorks", [])
        )

        if args.score:
            for link in all_links:
                threat = score_threat(link.get("url", ""), target)
                link.update({
                    "score": threat.get("score"),
                    "label": threat.get("label"),
                    "reasons": threat.get("reasons"),
                })

        # Open all links
        if args.open:
            open_links_in_browser(
                all_links,
                randomize=args.randomize,
                browser_name=args.browser,
                delay=args.open_delay,
                max_open=args.max_open if args.max_open > 0 else None
            )

        if args.dedupe:
            all_links = dedupe_links(all_links, key_fields=("url",))

        if args.check:
            proxies = {}
            if config.get("http_proxy"):
                proxies["http"] = config["http_proxy"]
            if config.get("https_proxy"):
                proxies["https"] = config["https_proxy"]
            all_links = check_link_status(
                all_links,
                timeout=check_timeout,
                retries=check_retries,
                user_agent=config.get("user_agent"),
                verify_tls=config.get("verify_tls", True),
                rate_limit_per_sec=rate_limit,
                proxies=proxies or None,
            )

        if args.score and args.sort_score:
            all_links = sorted(all_links, key=lambda l: l.get("score", 0), reverse=True)

        if max_links and max_links > 0:
            all_links = all_links[:max_links]

        # Save results only if --export is specified
        if args.export:
            export_name = args.output if args.output and args.output != "results" else f"{target}_deep_search_results"
            export_data(
                data=all_links,
                fmt=args.export,
                output=export_name,
                save_dir=args.save_dir
            )
            if not json_mode:
                console.print(f"[bold green]✅ Deep Search completed. Results saved to "
                              f"{args.save_dir}/{export_name}.{args.export}[/bold green]")
        else:
            if not json_mode:
                console.print("[bold yellow]ℹ️ Deep Search results not saved (use --export to save output).[/bold yellow]")

        if json_mode:
            output_json({"target": target, "results": results, "links": all_links})
        if args.log:
            log_event("deep_search_complete", {"target": target, "links": len(all_links)})

        sys.exit(0)

    if args.clone_detect:
        clone_base = args.clone_detect.strip()
        if not json_mode:
            console.rule(f"[bold blue]Running Clone Detection for: {clone_base}[/bold blue]")

        # Step 1: Generate typo/variant domains
        variants = generate_typosquatting_domains(clone_base)
        if not json_mode:
            console.print(f"→ [yellow]Generated {len(variants)} typo variants.[/yellow]")

        # Step 2: Detect clones from those domains
        detected = detect_clones(clone_base, variants)

        if json_mode:
            output_json({"target": clone_base, "clones": detected})
        else:
            if detected:
                console.print(f"\n[bold green]✅ Clones Detected:[/bold green]")
                for domain in detected:
                    console.print(f"[green]→ {domain}[/green]")
            else:
                console.print("\n[bold cyan]No clones detected among active typo variants.[/bold cyan]")

            console.rule("[bold green]Clone Detection Complete")
        return


    clone_links = []

    if args.text_detect:
        if not json_mode:
            console.rule("[bold yellow]Clone Detection via Search Engine Dorks")
        clone_links = text_clone_search(
            [args.text_detect],
            open_browser=args.open,
            browser_name=args.browser,  # from --browser flag
            randomize=args.randomize,  # from --randomize flag
            quiet=json_mode,
        )
        if json_mode:
            output_json({"target": args.text_detect, "links": clone_links})
        return

    if args.dnstwist:
        if not json_mode:
            console.rule("[bold blue]Running dnstwist scan...")
        dnstwist_domain = args.dnstwist if isinstance(args.dnstwist, str) else args.target
        dnstwist_results = run_dnstwist(dnstwist_domain)

        if json_mode:
            output_json({"target": dnstwist_domain, "results": dnstwist_results or []})
            return

        if dnstwist_results:
            table = Table(title="DNSTwist Results")
            table.add_column("Domain", style="cyan")
            table.add_column("DNS A Records", style="green")

            for entry in dnstwist_results:
                domain = entry.get("domain")
                a_records = entry.get("dns_a", [])
                if a_records:
                    dns_display = ", ".join(a_records)
                else:
                    dns_display = "[red]No A record[/red]"
                table.add_row(domain or "[italic]N/A[/italic]", dns_display)

            console.print(table)
        else:
            console.print("[bold yellow]⚠️ No dnstwist results found for the domain.[/bold yellow]")
        return

    if args.add_custom_platform:
        category, name, url = args.add_custom_platform
        add_custom_platform(category, name, url)
        return

    if args.remove_custom_platform:
        category, name = args.remove_custom_platform
        remove_custom_platform(category, name)
        return

    if args.list_custom_platforms:
        list_custom_platforms()
        return

    if args.list_platforms:
        console.print("[bold cyan]Available Platforms by Category:[/bold cyan]")
        for category, platforms in PLATFORM_TEMPLATES.items():
            console.print(f"\n[bold green]{category}[/bold green]")
            for name in platforms:
                console.print(f"  • {name}")
        return  # Exit after listing

    if args.list_browsers:
        list_available_browsers()
        return

    targets = []
    if args.targets_file:
        try:
            with open(args.targets_file, "r", encoding="utf-8") as f:
                targets = [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            console.print(f"[bold red]Error:[/bold red] Failed to read targets file: {e}")
            sys.exit(1)
    elif args.target:
        targets = [args.target]

    if not targets:
        console.print("[bold red]Error:[/bold red] Target is required unless using --clone-detect or --text-detect or --list-platforms.")
        return

    if args.log:
        log_event("search_start", {"targets": targets, "platforms": args.platforms or ["all"], "tag": args.tag})
    if not json_mode:
        console.rule("[bold green]OSINT CLI Tool Started")

    # Decides if default templates should be used
    use_default_templates = bool(args.platforms) or not args.load_custom_template

    # Loads templates accordingly
    platform_templates = load_platform_templates(
        custom_path=args.load_custom_template,
        use_default=use_default_templates
    )

    # Parse platforms - if none provided, default to "all"
    platforms = parse_input(args.platforms)
    if args.fuzzy:
        platforms = fuzzy_match_platforms(platforms, platform_templates)

    exclude_platforms = {p.strip().lower() for p in (args.exclude_platforms or [])}
    exclude_categories = {c.strip().lower() for c in (args.exclude_categories or [])}

    proxies = {}
    if config.get("http_proxy"):
        proxies["http"] = config["http_proxy"]
    if config.get("https_proxy"):
        proxies["https"] = config["https_proxy"]

    all_results = []
    json_results = []

    for target in targets:
        if not json_mode:
            console.print(f"Target: [bold yellow]{target}[/bold yellow]")

        links = generate_search_links(target, platforms, platform_templates)

        if exclude_platforms or exclude_categories:
            links = [
                l for l in links
                if l.get("platform", "").lower() not in exclude_platforms
                and l.get("category", "").lower() not in exclude_categories
            ]

        if args.score:
            for link in links:
                threat = score_threat(link.get("url", ""), target)
                link.update({
                    "score": threat.get("score"),
                    "label": threat.get("label"),
                    "reasons": threat.get("reasons"),
                })

        if args.score and args.sort_score:
            links = sorted(links, key=lambda l: l.get("score", 0), reverse=True)

        if args.dedupe:
            links = dedupe_links(links, key_fields=("url",))

        if args.check:
            links = check_link_status(
                links,
                timeout=check_timeout,
                retries=check_retries,
                user_agent=config.get("user_agent"),
                verify_tls=config.get("verify_tls", True),
                rate_limit_per_sec=rate_limit,
                proxies=proxies or None,
            )

        if max_links and max_links > 0:
            links = links[:max_links]

        grouped = group_links_by_category(links)
        for link in grouped:
            link["target"] = target
            if args.tag:
                link["tag"] = args.tag

        if json_mode:
            json_results.append({"target": target, "links": grouped})
        else:
            print_search_links(grouped)

        if args.open:
            open_links_in_browser(
                links,
                randomize=args.randomize,
                browser_name=args.browser,
                delay=args.open_delay,
                max_open=args.max_open if args.max_open > 0 else None
            )

        all_results.extend(grouped)

    # table = Table(title="Search Links")
    # table.add_column("Platform", style="cyan")
    # table.add_column("Category", style="magenta")
    # table.add_column("URL", style="green")
    #
    # for link in grouped:
    #     table.add_row(link['platform'], link['category'], link['url'])
    #
    # console.print(table)

    if json_mode:
        output_json({"results": json_results, "tag": args.tag})

    all_links = all_results + clone_links if clone_links else all_results

    if args.export:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if args.output and args.output != "results":
            output_name = args.output
        elif len(targets) == 1 and not args.targets_file:
            output_name = f"{targets[0]}_{timestamp}".replace(" ", "_")
        else:
            output_name = f"batch_{timestamp}".replace(" ", "_")
        export_data(all_links, fmt=args.export, output=output_name, save_dir=args.save_dir)

    if args.log:
        for target in targets:
            target_links = [l for l in all_results if isinstance(l, dict) and l.get("target") == target]
            log_search_history(target, target_links)
        log_event("search_complete", {"targets": targets, "links": len(all_results), "tag": args.tag})

    if not json_mode:
        console.rule("[bold green]Done")

if __name__ == "__main__":
    main()
