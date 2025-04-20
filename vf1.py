#!/usr/bin/env python3

import requests
import socket
import json
import os
import time
from datetime import datetime
from urllib.parse import urlparse, quote_plus
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
import subprocess

console = Console()

ASCII_ART = r"""
  ███        ▄████████ ▄██   ▄      ▄█    █▄     ▄█  ████████▄   ▄█  ███▄▄▄▄      ▄██████▄  
▀█████████▄   ███    ███ ███   ██▄   ███    ███   ███  ███   ▀███ ███  ███▀▀▀██▄   ███    ███ 
   ▀███▀▀██   ███    ███ ███▄▄▄███   ███    ███   ███▌ ███    ███ ███▌ ███   ███   ███    █▀  
    ███   ▀  ▄███▄▄▄▄██▀ ▀▀▀▀▀▀███  ▄███▄▄▄▄███▄▄ ███▌ ███    ███ ███▌ ███   ███  ▄███        
    ███     ▀▀███▀▀▀▀▀   ▄██   ███ ▀▀███▀▀▀▀███▀  ███▌ ███    ███ ███▌ ███   ███ ▀▀███ ████▄  
    ███     ▀███████████ ███   ███   ███    ███   ███  ███    ███ ███  ███   ███   ███    ███ 
    ███       ███    ███ ███   ███   ███    ███   ███  ███   ▄███ ███  ███   ███   ███    ███ 
   ▄████▀     ███    ███  ▀█████▀    ███    █▀    █▀   ████████▀  █▀    ▀█   █▀    ████████▀  
              ███    ███                                       

                              Red Team Recon Toolkit - TryHidding
                          By Alejandor rodriguez && Eduardo Menendez 

"""

def show_banner():
    console.print(Panel(Text(ASCII_ART, justify="center"), style="bold red"))

def clean_domain(domain):
    parsed = urlparse(domain)
    return parsed.netloc or parsed.path

def log_output(header, content):
    with open("recon_log.txt", "a") as log:
        log.write(f"\n===== {header} =====\n")
        log.write(content + "\n")

def domain_info(domain):
    try:
        console.print("[bold cyan]Looking up WHOIS info...[/bold cyan]")
        result = subprocess.run(["whois", domain], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode == 0:
            table = Table(title="WHOIS Info (via subprocess)", box=box.SIMPLE)
            table.add_column("Line", style="white")
            for line in result.stdout.splitlines():
                table.add_row(line)
            console.print(table)
            log_output("WHOIS", result.stdout)
        else:
            console.print(f"[red]WHOIS lookup failed:[/red] {result.stderr.strip()}")
    except Exception as e:
        console.print(f"[red]WHOIS lookup failed:[/red] {e}")

def dns_lookup(domain):
    try:
        console.print("[bold cyan]Performing DNS lookup...[/bold cyan]")
        ip = socket.gethostbyname(domain)
        console.print(f"[green]IP Address:[/green] {ip}")
        log_output("DNS Lookup", f"{domain} resolved to {ip}")
    except Exception as e:
        console.print(f"[red]DNS lookup failed:[/red] {e}")

def crtsh_enum(domain):
    try:
        console.print("[bold cyan]Enumerating subdomains via crt.sh...[/bold cyan]")
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, timeout=10)
        subdomains = set()
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                sub = entry['name_value'].split('\n')
                for s in sub:
                    if domain in s:
                        subdomains.add(s.strip())
            table = Table(title="crt.sh Subdomains", box=box.MINIMAL_DOUBLE_HEAD)
            table.add_column("Subdomain", style="magenta")
            for sub in sorted(subdomains):
                table.add_row(sub)
            console.print(table)
            log_output("crt.sh Subdomains", "\n".join(sorted(subdomains)))
        else:
            console.print("[red]crt.sh failed to return data.[/red]")
    except Exception as e:
        console.print(f"[red]crt.sh enumeration failed:[/red] {e}")

def github_dorks(domain):
    try:
        console.print("[bold cyan]Searching GitHub for potential leaks...[/bold cyan]")
        use_token = console.input("[yellow]Do you want to use a GitHub token to avoid rate limits? (y/n): [/yellow]").lower()
        headers = {}
        if use_token == 'y':
            token = console.input("[bold yellow]Enter your GitHub personal access token: [/bold yellow]")
            headers = {"Authorization": f"token {token}"}

        url = f"https://api.github.com/search/code?q={domain}&per_page=5"
        r = requests.get(url, headers=headers)
        if r.status_code == 200:
            data = r.json()
            table = Table(title="GitHub Leak Search", box=box.SIMPLE)
            table.add_column("Repository", style="green")
            table.add_column("File", style="white", justify="left", no_wrap=True)
            results = []
            for item in data.get("items", []):
                repo = item['repository']['full_name']
                file_url = item['html_url']
                results.append(f"{repo} -> {file_url}")
                table.add_row(repo, f"[link={file_url}]{file_url}[/link]")
            console.print(table)
            log_output("GitHub Dorks", " ".join(results))
        else:
            console.print("[yellow]GitHub search may be rate-limited or failed.[/yellow]")
    except Exception as e:
        console.print(f"[red]GitHub search failed:[/red] {e}")

def wayback_urls(domain):
    try:
        console.print("[bold cyan]Fetching archived URLs from Wayback Machine...[/bold cyan]")
        url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&fl=original&collapse=urlkey"
        r = requests.get(url)
        if r.status_code == 200:
            data = r.json()[1:]
            table = Table(title="Wayback URLs", box=box.SIMPLE_HEAVY)
            table.add_column("Archived URL", style="blue")
            entries = []
            for entry in data[:10]:
                table.add_row(entry[0])
                entries.append(entry[0])
            console.print(table)
            log_output("Wayback Machine URLs", "\n".join(entries))
        else:
            console.print("[red]Failed to retrieve Wayback Machine data.[/red]")
    except Exception as e:
        console.print("[red]Wayback Machine lookup failed:[/red]")
        log_output("Wayback Machine Error", str(e))

def google_dorks(domain):
    try:
        console.print("[bold cyan]Generating Google Dorks for reconnaissance...[/bold cyan]")
        dorks = [
            f"site:{domain} intitle:index.of",
            f"site:{domain} ext:sql | ext:xml | ext:conf",
            f"site:{domain} inurl:admin",
            f"site:{domain} inurl:login",
            f"site:{domain} password",
            f"site:pastebin.com {domain}"
        ]
        table = Table(title="Google Dork Queries", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("Query", style="yellow")
        for dork in dorks:
            table.add_row(dork)
        console.print(table)
        log_output("Google Dorks", "\n".join(dorks))
    except Exception as e:
        console.print(f"[red]Google Dorks generation failed:[/red] {e}")

def main():
    show_banner()
    if os.path.exists("recon_log.txt"):
        os.remove("recon_log.txt")

    try:
        target = console.input(" [bold yellow]Enter target domain (e.g. example.com): [/bold yellow]")
    except KeyboardInterrupt:
        console.print(" [bold red] [!] Input cancelled by user. Exiting...[/bold red]")
        return
    domain = clean_domain(target)
    console.print("\n[bold green]Starting Recon...[/bold green]\n")
    time.sleep(1)

    dns_lookup(domain)
    time.sleep(0.5)

    domain_info(domain)
    time.sleep(0.5)

    crtsh_enum(domain)
    time.sleep(0.5)

    github_dorks(domain)
    time.sleep(0.5)

    wayback_urls(domain)
    time.sleep(0.5)

    google_dorks(domain)

    console.print("\n[bold green]Recon Complete! Output saved to recon_log.txt[/bold green]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print(" [bold red] [!] Execution interrupted by user. Exiting...[/bold red]")
