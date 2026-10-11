#!/usr/bin/env python3
"""Authorized subdomain discovery using certificate transparency and DNS."""

from __future__ import annotations

import argparse
import csv
import html
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DEFAULT_PREFIXES = """
www api app admin portal mail web vpn remote dev staging test beta alpha
autodiscover autodiscover-old mx smtp imap pop ftp sftp files cdn static assets
img images media upload uploads download docs documentation wiki help support
status health monitor monitoring metrics grafana kibana elastic search
git gitlab github ci cd jenkins build deploy registry docker container
auth login signin sso id oauth identity accounts account dashboard
cloud aws azure gcp storage backup backups db database mysql postgres redis
internal intranet corp office hr finance billing payment shop store checkout
mobile m api-dev dev-api api-staging staging-api test-api qa uat preview
webmail exchange outlook owa ldap ad dc ns ns1 ns2 dns
proxy gateway ingress edge origin waf firewall bastion jump server
old legacy archive beta2 sandbox demo lab labs research analytics data
report reports helpdesk ticket tickets crm erp cms blog news forum community
calendar meet chat app1 app2 web1 web2 server1 server2 node1 node2
""".split()

LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
TITLE_RE = re.compile(r"<title\b[^>]*>(.*?)</title\s*>", re.IGNORECASE | re.DOTALL)
MAX_CT_RESPONSE_BYTES = 20 * 1024 * 1024


@dataclass
class HttpProbe:
	url: str
	status: int
	server: str = ""
	title: str = ""


@dataclass
class ScanResult:
	hostname: str
	addresses: list[str] = field(default_factory=list)
	sources: list[str] = field(default_factory=list)
	http: list[HttpProbe] = field(default_factory=list)


def normalize_domain(value: str) -> str:
	"""Validate and return a normalized DNS domain (not an IP address)."""
	domain = value.strip().rstrip(".")
	if domain.startswith("*."):
		domain = domain[2:]
	if not domain or any(char in domain for char in "/:@?#"):
		raise ValueError("Enter a DNS domain, for example example.com.")
	try:
		ipaddress.ip_address(domain)
	except ValueError:
		pass
	else:
		raise ValueError("An IP address is not a domain; provide a DNS name.")

	try:
		ascii_domain = domain.encode("idna").decode("ascii").lower()
	except UnicodeError as error:
		raise ValueError("The domain name is not valid.") from error

	labels = ascii_domain.split(".")
	if len(labels) < 2 or len(ascii_domain) > 253 or any(
		not LABEL_RE.fullmatch(label) for label in labels
	):
		raise ValueError("Enter a fully qualified DNS domain, for example example.com.")
	return ascii_domain


def normalize_candidate(value: str, domain: str) -> str | None:
	candidate = value.strip().lower().rstrip(".")
	if not candidate or candidate.startswith("*"):
		return None
	try:
		candidate = candidate.encode("idna").decode("ascii")
	except UnicodeError:
		return None

	if candidate == domain or candidate.endswith("." + domain):
		fqdn = candidate
	else:
		fqdn = candidate + "." + domain

	if len(fqdn) > 253 or any(not LABEL_RE.fullmatch(label) for label in fqdn.split(".")):
		return None
	return fqdn


def fetch_certificate_names(domain: str, timeout: float, user_agent: str) -> set[str]:
	query = urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
	request = urllib.request.Request(
		f"https://crt.sh/?{query}", headers={"User-Agent": user_agent}
	)
	with urllib.request.urlopen(request, timeout=timeout) as response:
		payload = response.read(MAX_CT_RESPONSE_BYTES + 1)
	if len(payload) > MAX_CT_RESPONSE_BYTES:
		raise ValueError("Certificate transparency response exceeded the size limit.")

	records = json.loads(payload.decode("utf-8"))
	names: set[str] = set()
	for record in records:
		for name in str(record.get("name_value", "")).splitlines():
			normalized = normalize_candidate(name, domain)
			if normalized:
				names.add(normalized)
	return names


def load_wordlist(path: Path, domain: str) -> set[str]:
	names: set[str] = set()
	with path.open("r", encoding="utf-8", errors="replace") as wordlist:
		for line in wordlist:
			entry = line.split("#", 1)[0].strip()
			normalized = normalize_candidate(entry, domain)
			if normalized:
				names.add(normalized)
	return names


def resolve_hostname(hostname: str) -> list[str]:
	try:
		records = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
	except (socket.gaierror, OSError):
		return []
	addresses = {record[4][0].split("%", 1)[0] for record in records}
	return sorted(addresses, key=lambda address: (":" in address, address))


def extract_title(content: bytes) -> str:
	decoded = content.decode("utf-8", errors="replace")
	match = TITLE_RE.search(decoded)
	if not match:
		return ""
	title = re.sub(r"<[^>]+>", " ", match.group(1))
	return re.sub(r"\s+", " ", html.unescape(title)).strip()[:200]


def request_probe(url: str, timeout: float, user_agent: str) -> HttpProbe | None:
	request = urllib.request.Request(
		url,
		headers={
			"User-Agent": user_agent,
			"Range": "bytes=0-8191",
			"Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
		},
	)
	try:
		response = urllib.request.urlopen(request, timeout=timeout)
	except urllib.error.HTTPError as error:
		response = error
	except (urllib.error.URLError, TimeoutError, ssl.SSLError, OSError, ValueError):
		return None

	try:
		content = response.read(8192)
		return HttpProbe(
			url=url,
			status=response.code,
			server=response.headers.get("Server", "")[:200],
			title=extract_title(content),
		)
	except (OSError, http.client.HTTPException):
		return HttpProbe(url=url, status=response.code)
	finally:
		response.close()


def probe_hostname(hostname: str, timeout: float, user_agent: str) -> list[HttpProbe]:
	probes: list[HttpProbe] = []
	for scheme in ("https", "http"):
		probe = request_probe(f"{scheme}://{hostname}/", timeout, user_agent)
		if probe:
			probes.append(probe)
	return probes


def build_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(
		description=(
			"Discover subdomains through certificate transparency and DNS, "
			"then optionally check HTTP(S) response headers."
		),
		epilog="Run scans only for domains you own or are authorized to assess.",
	)
	parser.add_argument("domain", nargs="?", help="Root domain, such as example.com")
	parser.add_argument("-d", "--domain", dest="domain_option", help="Root domain")
	parser.add_argument("-w", "--wordlist", type=Path, help="Additional newline-separated names")
	parser.add_argument("--passive-only", action="store_true", help="Skip built-in and wordlist DNS candidates")
	parser.add_argument("--no-ct", action="store_true", help="Skip the crt.sh certificate transparency lookup")
	parser.add_argument("--no-http", action="store_true", help="Skip HTTP and HTTPS checks")
	parser.add_argument("--timeout", type=float, default=5.0, help="Network timeout in seconds (default: 5)")
	parser.add_argument("--workers", type=int, default=20, help="Concurrent DNS/HTTP workers, 1-50 (default: 20)")
	parser.add_argument("--max-candidates", type=int, default=5000, help="Maximum unique names to resolve (default: 5000)")
	parser.add_argument("-o", "--output", type=Path, help="Write results to a file")
	parser.add_argument("--format", choices=("json", "csv", "txt"), default="json", help="Output file format (default: json)")
	parser.add_argument("--user-agent", default="SubSeven-SubdomainScanner/1.0", help="HTTP User-Agent")
	return parser


def collect_candidates(args: argparse.Namespace, domain: str) -> tuple[dict[str, set[str]], list[str]]:
	sources: dict[str, set[str]] = {}
	warnings: list[str] = []

	if not args.no_ct:
		try:
			sources["crt.sh"] = fetch_certificate_names(domain, args.timeout, args.user_agent)
		except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError) as error:
			warnings.append(f"crt.sh lookup failed: {error}")

	if not args.passive_only:
		sources["built-in"] = {
			hostname
			for prefix in DEFAULT_PREFIXES
			if (hostname := normalize_candidate(prefix, domain)) is not None
		}
		if args.wordlist:
			try:
				sources["wordlist"] = load_wordlist(args.wordlist, domain)
			except OSError as error:
				warnings.append(f"Could not read wordlist: {error}")

	return sources, warnings


def scan(domain: str, args: argparse.Namespace) -> tuple[list[ScanResult], list[str], int]:
	source_names, warnings = collect_candidates(args, domain)
	candidates: dict[str, set[str]] = {domain: {"root"}}
	for source, names in source_names.items():
		for hostname in names:
			candidates.setdefault(hostname, set()).add(source)

	ordered_names = sorted(candidates)
	if len(ordered_names) > args.max_candidates:
		warnings.append(
			f"Candidate limit reached; resolving the first {args.max_candidates} of {len(ordered_names)} names."
		)
		ordered_names = ordered_names[: args.max_candidates]

	addresses: dict[str, list[str]] = {}
	with ThreadPoolExecutor(max_workers=args.workers) as executor:
		futures = {executor.submit(resolve_hostname, name): name for name in ordered_names}
		for future in as_completed(futures):
			hostname = futures[future]
			addresses[hostname] = future.result()

	results = [
		ScanResult(hostname=name, addresses=addresses.get(name, []), sources=sorted(candidates[name]))
		for name in ordered_names
		if addresses.get(name)
	]

	if not args.no_http and results:
		with ThreadPoolExecutor(max_workers=args.workers) as executor:
			futures = {
				executor.submit(probe_hostname, result.hostname, args.timeout, args.user_agent): result
				for result in results
			}
			for future in as_completed(futures):
				futures[future].http = future.result()

	return results, warnings, len(ordered_names)


def render_table(results: list[ScanResult]) -> str:
	if not results:
		return "No DNS-resolving names found."
	rows = [("HOSTNAME", "ADDRESSES", "HTTP(S)", "TITLE")]
	for result in results:
		endpoints = ", ".join(f"{probe.status} {probe.url.split(':', 1)[0]}" for probe in result.http)
		title = next((probe.title for probe in result.http if probe.title), "")
		rows.append((result.hostname, ", ".join(result.addresses), endpoints or "-", title or "-"))
	widths = [min(60, max(len(row[index]) for row in rows)) for index in range(4)]
	lines = ["  ".join(value[: widths[index]].ljust(widths[index]) for index, value in enumerate(rows[0]))]
	lines.append("  ".join("-" * width for width in widths))
	for row in rows[1:]:
		lines.append("  ".join(value[: widths[index]].ljust(widths[index]) for index, value in enumerate(row)))
	return "\n".join(lines)


def write_report(path: Path, output_format: str, domain: str, results: list[ScanResult]) -> None:
	if output_format == "json":
		report: dict[str, Any] = {
			"domain": domain,
			"scanned_at": datetime.now(timezone.utc).isoformat(),
			"count": len(results),
			"results": [asdict(result) for result in results],
		}
		path.write_text(json.dumps(report, indent=2), encoding="utf-8")
	elif output_format == "csv":
		with path.open("w", newline="", encoding="utf-8") as output:
			writer = csv.writer(output)
			writer.writerow(("hostname", "addresses", "sources", "http_statuses", "titles"))
			for result in results:
				writer.writerow(
					(
						result.hostname,
						";".join(result.addresses),
						";".join(result.sources),
						";".join(f"{probe.url}={probe.status}" for probe in result.http),
						";".join(probe.title for probe in result.http if probe.title),
					)
				)
	else:
		lines = [result.hostname for result in results]
		path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def main(argv: Iterable[str] | None = None) -> int:
	parser = build_parser()
	args = parser.parse_args(argv)
	raw_domain = args.domain_option or args.domain
	if not raw_domain:
		parser.error("a domain is required (positional or --domain)")
	if args.domain_option and args.domain and args.domain_option != args.domain:
		parser.error("provide the domain either positionally or with --domain, not both")
	if not 1 <= args.workers <= 50:
		parser.error("--workers must be between 1 and 50")
	if not 1 <= args.max_candidates <= 100000:
		parser.error("--max-candidates must be between 1 and 100000")
	if not 0.5 <= args.timeout <= 120:
		parser.error("--timeout must be between 0.5 and 120 seconds")
	if not args.user_agent.strip():
		parser.error("--user-agent cannot be empty")
	try:
		domain = normalize_domain(raw_domain)
	except ValueError as error:
		parser.error(str(error))

	print(f"[*] Domain: {domain}")
	print("[*] Gathering names and resolving DNS...")
	results, warnings, candidate_count = scan(domain, args)
	for warning in warnings:
		print(f"[!] {warning}", file=sys.stderr)
	print(f"[*] Resolved {len(results)} of {candidate_count} candidate names.")
	print(render_table(results))

	if args.output:
		try:
			write_report(args.output, args.format, domain, results)
		except OSError as error:
			print(f"[!] Could not write report: {error}", file=sys.stderr)
			return 1
		print(f"[*] Report written to {args.output}")
	return 0


if __name__ == "__main__":
	try:
		raise SystemExit(main())
	except KeyboardInterrupt:
		print("\n[!] Scan interrupted.", file=sys.stderr)
		raise SystemExit(130)
