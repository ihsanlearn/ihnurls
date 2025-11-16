<pre align="left">
.__.__                        .__          
|__|  |__   ____  __ _________|  |   ______
|  |  |  \ /    \|  |  \_  __ \  |  /  ___/
|  |   Y  \   |  \  |  /|  | \/  |__\___ \ 
|__|___|  /___|  /____/ |__|  |____/____  >
        \/     \/                       \/ 
</pre>
Advanced Asynchronous URL Extraction, Filtering & Recon Toolkit  
<br>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge">
  <img src="https://img.shields.io/badge/Asyncio-Enabled-brightgreen?style=for-the-badge">
  <img src="https://img.shields.io/badge/Rich-Colored%20CLI-orange?style=for-the-badge">
  <img src="https://img.shields.io/badge/Status-Active-success?style=for-the-badge">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey?style=for-the-badge">
</p>

---

## Overview

`ihnurls` is a **high-performance, asynchronous reconnaissance utility** designed for modern bug bounty, penetration testing, and web application mapping workflows.

It provides **URL harvesting, filtering, classification, parameter discovery, GF-pattern extraction, cloud indicator detection, sensitive path matching**, and more — all wrapped in a clean, colored terminal interface built with **Rich**.

This tool replaces large shell pipelines by providing a **single, powerful Python-based engine** capable of processing hundreds of thousands of URLs efficiently.

---

## Key Features

### **Core Capabilities**
- Fully **async** pipeline (async subprocess + async GF extraction)
- Fast URL filtering & extraction
- Clean colored CLI output (Rich)
- Status-code based filtering (`-sc`)
- Normal & raw input mode (`-i` and `-lraw`)
- Sensitive endpoint detection (auth URLs, admin panels, debug endpoints, etc.)
- JS file extraction
- Parameter extraction (normal + unfurl-style)
- Cloud detection (AWS, Azure, Cloudflare, Netlify, GitHub Pages, etc.)
- Backup file detection (`.bak`, `.zip`, `.sql`, `.tar.gz`, etc.)
- GF integration (if installed)
- Async fallback regex engine if GF is not installed
- Verbose mode (`-v`)
- Modern directory output structure (`urls/<domain>/`)

---

## Raw Mode (`-lraw`)

When using raw mode, `ihnurls` accepts inputs that include:

- URL  
- HTTP status code  
- Comment / technology tags  

Example:

```
https://example.com [200] [Cloudflare,HSTS]
https://app.example.com [404] [Not Found]
https://cdn.example.com [301] [Redirect]
```

### Filter by status-code:

```
ihnurls -lraw lyst-raw.txt -sc 200,404
```

---

## Installation

### **1. Clone the Repository**
```bash
git clone https://github.com/ihsanlearn/ihnurls.git
cd ihnurls
```

### **2. Install Dependencies**
```
pip install -r requirements.txt
```

### **3. Run**
```
python3 ihnurls.py -i urls.txt
```

---

## Usage

### **Basic URLs file**
```
ihnurls -i urls.txt
```

### **Raw file (with status codes)**
```
ihnurls -lraw urls_raw.txt
```

### **Raw mode + status-code filtering**
```
ihnurls -lraw hosts.txt -sc 200,302,404
```

### **Verbose mode**
```
ihnurls -i urls.txt -v
```

### **Specify output directory**
```
ihnurls -i urls.txt -o urls
```

---

## Output Structure

```
urls/
 ├── all-urls.txt
 ├── all-clean.txt
 ├── js-files.txt
 ├── api-urls.txt
 ├── cloud-urls.txt
 ├── backup-files.txt
 ├── auth-urls.txt
 ├── params-final.txt
 └── gf/
      ├── debug_logic.txt
      ├── xss.txt
      ├── sqli.txt
      ├── ...
```

---

## Flags

| Flag | Description |
|------|------------|
| `-i <file>` | Input file (clean URLs) |
| `-lraw <file>` | Raw input (URL + status code + tech tags) |
| `-sc <codes>` | Filter by HTTP status code list |
| `-o <dir>` | Output directory (default: `urls`) |
| `-v` | Verbose mode |
| `--banner` | Always show ASCII cyberpunk banner |

---

## Built-In GF Patterns

The tool supports all common GF patterns:

- `debug_logic`
- `idor`
- `img-traversal`
- `interestingEXT`
- `interestingparams`
- `interestingsubs`
- `jsvar`
- `lfi`
- `rce`
- `redirect`
- `sqli`
- `ssrf`
- `ssti`
- `xss`

If `gf` is installed, patterns are extracted using GF directly.  
If not, async regex fallbacks are used.

---

## Performance

The tool uses:

- **asyncio.create_subprocess_exec**
- **async parallel GF extraction**
- **automatic batching**
- **non-blocking file processing**

Result:  
Capable of processing > **1,000,000 URLs** in minutes depending on hardware.

---

## Requirements

- Python **3.8+**
- `rich`
- `tldextract` (if domain parsing is enabled)
- Optional:
  - `gf` (pattern extraction)
  - `unfurl` (parameter extraction)

---

## Example Banner (Cyberpunk Graffiti)

Displayed automatically unless disabled:

```
.__.__                        .__          
|__|  |__   ____  __ _________|  |   ______
|  |  |  \ /    \|  |  \_  __ \  |  /  ___/
|  |   Y  \   |  \  |  /|  | \/  |__\___ \ 
|__|___|  /___|  /____/ |__|  |____/____  >
        \/     \/                       \/ 
```

---

## Disclaimer

This tool is intended **solely for legal & authorized security research**.

Use responsibly and only on systems where you have explicit permission.

---

## License

MIT License  
Copyright (c) 2025



## Author

Developed by iihhn
Focused on penetration testing, automation, and modern recon tooling.