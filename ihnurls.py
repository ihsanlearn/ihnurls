#!/usr/bin/env python3
"""
ihnurls - Async URL gathering + filtering tool (Python port of your bash pipeline)

Features:
 - Async gatherers (wraps external tools if available: waybackurls, gau, katana, hakrawler)
 - Optional use of httpx-created host list if provided (or live-hosts.txt)
 - Cache per-domain for wayback/gau results (~/.cache/urls-cache)
 - Merge, dedupe, filter, GF-like pattern extraction (uses gf if available else regex fallbacks)
 - New flags:
    -lraw FILE   : accept raw lines like:
                   https://example.com [404] [Title] [Server,Vendors]
    -sc CODES    : comma-separated status codes to filter when using -lraw (e.g. 200,301,404)
 - Verbose, colored output using rich and a cyberpunk graffiti banner
 - Output directory default: ./urls
 - Async mode for crawling/external tool invocation
"""

from __future__ import annotations
import argparse
import asyncio
import os
import re
import shutil
import sys
from pathlib import Path
from typing import List, Optional, Set, Tuple, Dict

# third-party
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
except Exception:
    print("Missing dependency: rich. Install with `pip install rich`", file=sys.stderr)
    raise

console = Console()
BANNER = r"""
.__.__                        .__          
|__|  |__   ____  __ _________|  |   ______
|  |  |  \ /    \|  |  \_  __ \  |  /  ___/
|  |   Y  \   |  \  |  /|  | \/  |__\___ \ 
|__|___|  /___|  /____/ |__|  |____/____  >
        \/     \/                       \/ 
   ihnurls  v1.0.0
"""

# Regexes & patterns (parity with your bash fallback)
FALLBACK = {
    "debug_logic": r"debug|trace|stack|dump|error|exception",
    "idor": r"([?&](id|user|uid|user_id|account|account_id|profile)=)",
    "img-traversal": r"(\.\./|\.\.\\/)",
    "interestingEXT": r"\.(php|asp|aspx|jsp|jspx|action|do)(\?|$)",
    "interestingparams": r"([?&](redirect|next|url|return|callback|file|path|page|view)=)",
    "interestingsubs": r"(^|/)(admin|portal|dashboard|api|beta|dev|staging|stage|test|secure|private)",
    "jsvar": r"(\.js($|\?)|[?&][^=]*=(.*function|.*callback|.*eval|.*JSON))",
    "lfi": r"(\.\./|\.\.\\/)",
    "rce": r"\b(eval\(|system\(|exec\(|passthru\(|popen\()",
    "redirect": r"([?&](redirect|next|return|url|callback|goto|continue)=)",
    "sqli": r"('|%27|\\b(or|and)\\b.+?=|\\bunion\\b.+?select|\\bselect\\b.+?from)",
    "ssrf": r"([?&](url|uri|target|redirect|next|dest|destination|callback)=)",
    "ssti": r"(\{\{.*\}\}|\%\{.*\}|<%|<\$|render\(|template)",
    "xss": r"(<script|%3Cscript|<img|onerror=|onload=|javascript:)",
}

EXT_FILTER_RE = re.compile(
    r"\.(woff2?|css|png|jpe?g|gif|ico|pdf|zip|tar.gz|tgz|svg)(\?|$)", re.IGNORECASE
)

# Helpers
def cmd_exists(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def ensure_dir(p: Path):
    p.mkdir(parents=True, exist_ok=True)

# Parsing -lraw lines like:
# https://example.com [404] [Title] [Server,Vendor]
RAW_LINE_RE = re.compile(r"(?P<url>https?://\S+)\s*\[(?P<code>\d{3})\]", re.IGNORECASE)

def parse_lraw_line(line: str) -> Optional[Tuple[str, int]]:
    m = RAW_LINE_RE.search(line)
    if not m:
        # maybe just URL w/o brackets
        url_match = re.search(r"(https?://\S+)", line)
        if url_match:
            return (url_match.group(1).rstrip(".,;\"'"), 0)
        return None
    url = m.group("url").rstrip(".,;\"'")
    code = int(m.group("code"))
    return (url, code)

# Async wrappers to run external tools (if available)
async def run_tool_collect(cmd: List[str], input_data: Optional[List[str]] = None, timeout: int = 300) -> List[str]:
    """Run external command and collect stdout lines (async)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        if input_data:
            stdin_data = "\n".join(input_data).encode()
            await proc.communicate(stdin_data)
        else:
            await proc.wait()
        out = await proc.stdout.read()
        text = out.decode(errors="ignore")
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        return lines
    except Exception as e:
        return []

# Normalization helpers
def normalize_url(u: str) -> str:
    u = re.sub(r"^https?://", "", u, flags=re.IGNORECASE)
    return u.rstrip("/")

def strip_query(u: str) -> str:
    return u.split("?", 1)[0]

# Main class
class IHNUrls:
    def __init__(self, args):
        self.args = args
        self.outdir = Path(args.outdir)
        ensure_dir(self.outdir)
        self.cache_dir = Path(args.cache_dir).expanduser()
        ensure_dir(self.cache_dir)
        self.gf_dir = self.outdir / "gf"
        ensure_dir(self.gf_dir)
        self.hosts_file: Optional[Path] = Path(args.hosts_file) if args.hosts_file else None
        self.domains = args.domains or []
        self.tmp_hosts_created = False
        self.httpx_hosts: Optional[Path] = None
        self.patterns = list(FALLBACK.keys())
        self.verbose = args.verbose
        # internal sets
        self.all_raw: Set[str] = set()
        self.all_urls: Set[str] = set()

    def log(self, *a, **kw):
        if self.verbose:
            console.log(*a, **kw)

    async def detect_hosts(self):
        # Prefer given hosts file, else domains => create temporary hosts file
        if self.hosts_file and self.hosts_file.exists():
            self.httpx_hosts = self.hosts_file
            self.log(f"Using hosts file: {self.httpx_hosts}")
            return
        # check live-hosts.txt in cwd
        live = Path("live-hosts.txt")
        if not self.hosts_file and live.exists():
            self.httpx_hosts = live
            self.log("Detected local live-hosts.txt -> using as hosts file")
            return
        # otherwise create a tmp hosts file from domains
        if not self.domains:
            raise SystemExit("No domains or hosts file provided.")
        tmp = Path(".ihn_tmp_hosts.txt")
        with tmp.open("w") as fh:
            for d in self.domains:
                fh.write(normalize_url(d) + "\n")
        self.httpx_hosts = tmp
        self.tmp_hosts_created = True
        self.log(f"Created temp hosts file: {tmp}")

    async def collect_cached_or_tool(self, domain: str, which: str) -> List[str]:
        """which: 'wayback' or 'gau'"""
        safe = re.sub(r"[/:]", "_", domain)
        cachefile = self.cache_dir / f"{which}-{safe}.txt"
        if cachefile.exists():
            self.log(f"Using cached {which} for {domain}")
            return [ln.strip() for ln in cachefile.read_text().splitlines() if ln.strip()]
        tool = "waybackurls" if which == "wayback" else "gau"
        if cmd_exists(tool) and not getattr(self.args, f"skip_{which}"):
            self.log(f"Running {tool} for {domain}")
            # external tool expects domain (no scheme)
            try:
                lines = await run_tool_collect([tool, domain])
                # normalize output: remove scheme
                cleaned = [re.sub(r"^https?://", "", ln).rstrip("/") for ln in lines if ln.strip()]
                cachefile.write_text("\n".join(cleaned))
                return cleaned
            except Exception:
                return []
        else:
            return []

    async def run_katana(self, host: str) -> List[str]:
        if not cmd_exists("katana") or self.args.skip_katana:
            return []
        self.log(f"Starting katana for {host}")
        lines = await run_tool_collect(["katana", "-u", f"https://{host}", "-d", "5", "-ps", "-pss", "waybackarchive,commoncrawl,alienvault", "-kf", "-jc", "-fx", "-ef", "woff,css,png,svg,jpg,woff2,jpeg,gif"])
        cleaned = [re.sub(r"^https?://", "", ln).rstrip("/") for ln in lines if ln.strip()]
        return cleaned

    async def run_hakrawler(self, host: str) -> List[str]:
        if not cmd_exists("hakrawler") or self.args.skip_hakrawler:
            return []
        self.log(f"Starting hakrawler for {host}")
        lines = await run_tool_collect(["hakrawler", "-url", f"https://{host}", "-depth", "2", "-plain"])
        cleaned = [re.sub(r"^https?://", "", ln).rstrip("/") for ln in lines if ln.strip()]
        return cleaned

    async def gather_crawls(self):
        # read hosts
        if not self.httpx_hosts or not self.httpx_hosts.exists():
            raise SystemExit("Hosts file not available for crawling.")
        hosts = [ln.strip() for ln in self.httpx_hosts.read_text().splitlines() if ln.strip()]
        # run wayback/gau per-host with concurrency
        tasks = []
        semaphore = asyncio.Semaphore(self.args.concurrency)
        async def worker_h(d):
            async with semaphore:
                out = []
                if not self.args.skip_wayback:
                    wb = await self.collect_cached_or_tool(d, "wayback")
                    out.extend(wb)
                if not self.args.skip_gau:
                    g = await self.collect_cached_or_tool(d, "gau")
                    out.extend(g)
                if not self.args.skip_katana:
                    k = await self.run_katana(d)
                    out.extend(k)
                if not self.args.skip_hakrawler:
                    h = await self.run_hakrawler(d)
                    out.extend(h)
                return out
        for h in hosts:
            tasks.append(worker_h(h))
        results = []
        # progress bar
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), TimeElapsedColumn()) as prog:
            task = prog.add_task("Crawling hosts...", total=len(tasks))
            for fut in asyncio.as_completed(tasks):
                res = await fut
                results.extend(res)
                prog.advance(task)
        # add to all_raw
        for ln in results:
            if ln and not EXT_FILTER_RE.search(ln):
                self.all_raw.add(ln)
        self.log(f"Gathered {len(self.all_raw)} raw urls from crawlers (pre-dedupe)")

    def ingest_lraw(self, path: Path, sc_filter: Optional[Set[int]] = None):
        self.log(f"Parsing raw-lines file: {path}")
        lines = path.read_text().splitlines()
        for ln in lines:
            parsed = parse_lraw_line(ln)
            if not parsed:
                continue
            url, code = parsed
            # If sc_filter supplied, only add lines with matching codes (code==0 means unknown)
            if sc_filter and code != 0 and code not in sc_filter:
                continue
            clean = normalize_url(url)
            if not EXT_FILTER_RE.search(clean):
                self.all_raw.add(clean)

    def merge_and_dedupe(self):
        # add existing all_raw -> all_urls (dedupe)
        self.all_urls = set(self.all_raw)
        self.log(f"Merged into {len(self.all_urls)} unique URLs")

    def normalize_with_uro(self):
        # If uro available, run it to normalize (best-effort) - uses subprocess sync
        if cmd_exists("uro"):
            self.log("Normalizing with uro (external tool)")
            try:
                proc = shutil.which("uro")
                p = asyncio.run(run_tool_collect([proc], input_data=list(self.all_urls)))
                # uro outputs full URLs maybe; strip scheme
                normalized = [re.sub(r"^https?://", "", ln).rstrip("/") for ln in p]
                self.all_urls = set(normalized)
            except Exception:
                pass

    def write_outputs(self):
        # Prepare output filenames (parity with your bash)
        files = {
            "all_raw": self.outdir / "all-raw.txt",
            "all": self.outdir / "all.txt",
            "all_clean": self.outdir / "all-clean.txt",
            "with_query": self.outdir / "with-query.txt",
            "no_query": self.outdir / "no-query.txt",
            "js": self.outdir / "js.txt",
            "sensitive_path": self.outdir / "sensitive-path.txt",
            "sensitive_params": self.outdir / "sensitive-params.txt",
            "api": self.outdir / "api.txt",
            "upload": self.outdir / "upload-endpoints.txt",
            "cloud": self.outdir / "cloud.txt",
            "backup": self.outdir / "backup-files.txt",
            "debug": self.outdir / "debug.txt",
            "auth": self.outdir / "auth.txt",
            "final_params": self.outdir / "final-params.txt",
        }
        # ensure outdir exists
        ensure_dir(self.outdir)
        # write raw
        (self.outdir / "all-raw.txt").write_text("\n".join(sorted(self.all_raw)))
        (self.outdir / "all.txt").write_text("\n".join(sorted(self.all_urls)))
        # cleaned = copy for now (uro optional)
        (self.outdir / "all-clean.txt").write_text("\n".join(sorted(self.all_urls)))
        # splits
        with_query = sorted([u for u in self.all_urls if "?" in u])
        no_query = sorted([strip_query(u) for u in self.all_urls])
        (self.outdir / "with-query.txt").write_text("\n".join(with_query))
        (self.outdir / "no-query.txt").write_text("\n".join(sorted(set(no_query))))
        (self.outdir / "js.txt").write_text("\n".join(sorted([u for u in self.all_urls if re.search(r"\.js($|\?)", u, re.IGNORECASE)])))
        # sensitive
        (self.outdir / "sensitive-path.txt").write_text("\n".join(sorted([u for u in self.all_urls if re.search(r'/(admin|login|signin|dashboard|manage|wp-admin|cpanel|backend|console|portal|auth|account|user|member|secure|private|studio|admin-panel|administrator)/', u, re.IGNORECASE)])))
        (self.outdir / "sensitive-params.txt").write_text("\n".join(sorted([u for u in self.all_urls if re.search(r'(\?|&)(token|access_token|auth|session|jwt|id|uid|user_id|signature|sig|password|pwd|secret|api_key|apikey|key|sso)=', u, re.IGNORECASE)])))
        (self.outdir / "api.txt").write_text("\n".join(sorted([u for u in self.all_urls if re.search(r'/api/|/v[0-9]+/|/graphql', u, re.IGNORECASE)])))
        (self.outdir / "upload-endpoints.txt").write_text("\n".join(sorted([u for u in self.all_urls if re.search(r'upload|file|attachment', u, re.IGNORECASE)])))
        (self.outdir / "cloud.txt").write_text("\n".join(sorted([u for u in self.all_urls if re.search(r'amazonaws|s3|blob.core.windows.net|herokuapp|github.io|netlify|azurewebsites', u, re.IGNORECASE)])))
        (self.outdir / "backup-files.txt").write_text("\n".join(sorted([u for u in self.all_urls if re.search(r'\.(bak|backup|old|zip|tar|sql|gz|tgz)$', u, re.IGNORECASE)])))
        (self.outdir / "debug.txt").write_text("\n".join(sorted([u for u in self.all_urls if re.search(r'debug|error|trace|dump|env|stack', u, re.IGNORECASE)])))
        (self.outdir / "auth.txt").write_text("\n".join(sorted([u for u in self.all_urls if re.search(r'/(login|logout|register|reset|forgot|activate|verify|confirm|signup|signin)/', u, re.IGNORECASE)])))
        # params
        params = set()
        for u in self.all_urls:
            if "?" in u:
                part = u.split("?", 1)[1]
                for kv in part.split("&"):
                    if "=" in kv:
                        k = kv.split("=", 1)[0]
                        params.add(k)
        (self.outdir / "param-names.txt").write_text("\n".join(sorted(params)))
        # final param patterns
        final_params = set()
        for u in self.all_urls:
            if "=" in u:
                final_params.add(re.sub(r"=[^&]*", "=", u))
        (self.outdir / "final-params.txt").write_text("\n".join(sorted(final_params)))

        console.print(f"[green]Saved outputs to {self.outdir}/[/green]")

    async def gf_extract(self):
        """Async GF extraction using asyncio.gather and async subprocess runner."""
        
        tasks = []

        if cmd_exists("gf"):
            self.log("Using gf (external) to extract patterns")

            all_urls_list = list(self.all_urls)

            async def run_gf(pattern, urls_list):
                try:
                    out = await run_tool_collect(["gf", pattern], input_data=urls_list)
                    cleaned = [ln.strip() for ln in out if ln.strip()]
                    outfile = self.gf_dir / f"{pattern}.txt"
                    outfile.write_text("\n".join(sorted(cleaned)))
                    self.log(f"gf {pattern} -> {outfile} ({len(cleaned)})")
                except Exception as e:
                    self.log(f"Error running gf {pattern}: {e}")

            for p in self.patterns:
                tasks.append(run_gf(p, all_urls_list))

        else:
            self.log("gf not found — using regex fallback (async)")

            async def run_fallback(pattern):
                rx = FALLBACK.get(pattern, ".")
                matches = [ln for ln in self.all_urls if re.search(rx, ln, re.IGNORECASE)]
                matches = sorted(set(matches))
                outfile = self.gf_dir / f"{pattern}.txt"
                outfile.write_text("\n".join(matches))
                self.log(f"fallback {pattern} -> {outfile} ({len(matches)})")

            for p in self.patterns:
                tasks.append(run_fallback(p))

        # Execute all GF/regex jobs concurrently
        await asyncio.gather(*tasks)

    def print_summary(self):
        t = Table(title="Summary", show_lines=False)
        t.add_column("Metric", style="cyan", no_wrap=True)
        t.add_column("Count", style="magenta")
        def c(fn):
            p = self.outdir / fn
            return len(p.read_text().splitlines()) if p.exists() and p.read_text().strip() else 0
        t.add_row("Total unique URLs", str(c("all.txt")))
        t.add_row("Cleaned URLs", str(c("all-clean.txt")))
        t.add_row("With params", str(c("with-query.txt")))
        t.add_row("JS files", str(c("js.txt")))
        t.add_row("Sensitive paths", str(c("sensitive-path.txt")))
        t.add_row("API endpoints", str(c("api.txt")))
        t.add_row("Cloud indicators", str(c("cloud.txt")))
        t.add_row("Backup files", str(c("backup-files.txt")))
        t.add_row("Auth endpoints", str(c("auth.txt")))
        console.print(t)

    async def run(self):
        console.print(Text(BANNER, style="bold magenta"))
        # Setup hosts source
        await self.detect_hosts()

        # If -lraw provided, parse that first (filtering by status codes if requested)
        if self.args.lraw:
            sc_set = None
            if self.args.sc:
                sc_set = {int(s) for s in str(self.args.sc).split(",") if s.strip().isdigit()}
            self.ingest_lraw(Path(self.args.lraw), sc_filter=sc_set)
            self.log(f"Ingested -lraw -> {len(self.all_raw)} lines")

        # If not skipping crawl and external tools exist, run async gatherers
        if not self.args.skip_crawl:
            await self.gather_crawls()

        # Merge & dedupe
        self.merge_and_dedupe()

        # Normalize with uro if requested/available
        if cmd_exists("uro") and not self.args.skip_normalize:
            self.normalize_with_uro()

        # Optionally run gf extraction
        await self.gf_extract()

        # Write outputs
        self.write_outputs()

        # Summary
        self.print_summary()

        # Cleanup tmp hosts file if created
        if self.tmp_hosts_created and self.httpx_hosts and self.httpx_hosts.exists():
            try:
                self.httpx_hosts.unlink()
                self.log("Removed temporary hosts file")
            except Exception:
                pass

# CLI
def build_argparser():
    p = argparse.ArgumentParser(prog="ihnurls", description="Async URL gathering & filtering pipeline (Python)")
    p.add_argument("domains", nargs="*", help="domains (if not using -f or -lraw)")
    p.add_argument("-l", "--list", dest="listfile", help="file with domains (one per line)")
    p.add_argument("-f", "--hosts-file", dest="hosts_file", help="use existing hosts file directly")
    p.add_argument("-o", "--outdir", default="urls", help="output directory (default: urls)")
    p.add_argument("--cache-dir", default=str(Path.home() / ".cache" / "urls-cache"), help="cache directory")
    p.add_argument("-p", "--parallel", dest="concurrency", type=int, default=10, help="concurrency (default 10)")
    p.add_argument("--skip-crawl", action="store_true", dest="skip_crawl", help="skip crawling (wayback/gau/katana/hakrawler)")
    p.add_argument("--skip-wayback", action="store_true", dest="skip_wayback", help="skip waybackurls step")
    p.add_argument("--skip-gau", action="store_true", dest="skip_gau", help="skip gau step")
    p.add_argument("--skip-katana", action="store_true", dest="skip_katana", help="skip katana step")
    p.add_argument("--skip-hakrawler", action="store_true", dest="skip_hakrawler", help="skip hakrawler step")
    p.add_argument("--skip-normalize", action="store_true", dest="skip_normalize", help="skip uro normalization")
    p.add_argument("--keep-temp", action="store_true", dest="keep_temp", help="keep intermediate files (temp hosts)")
    p.add_argument("-lraw", dest="lraw", help="file containing raw lines like: 'https://x [404] [Title] [Server]'")
    p.add_argument("-sc", dest="sc", help="comma-separated status codes to filter when using -lraw (e.g. 200,404)")
    p.add_argument("-v", "--verbose", action="store_true", help="verbose mode")
    return p

def main():
    ap = build_argparser()
    args = ap.parse_args()
    # If listfile provided, extend domains
    if getattr(args, "listfile", None):
        lf = Path(args.listfile)
        if not lf.exists():
            console.print(f"[red]List file not found: {lf}[/red]")
            sys.exit(1)
        lines = [ln.strip() for ln in lf.read_text().splitlines() if ln.strip()]
        args.domains = (getattr(args, "domains", []) or []) + lines
    # create object and run
    ihm = IHNUrls(args)
    try:
        asyncio.run(ihm.run())
    except KeyboardInterrupt:
        console.print("[red]Interrupted by user[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()
