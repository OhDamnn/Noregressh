
Originally I wanted to build a regreSHHion scanner and exploiter.
I then added additional CVEs to it. 
If anyone can help me expand parts of the project, please get in touch.




WELCOME TO NOREGRESSH 

Norregressh is a penetration-testing framework focused on OpenSSH regressions and multiple CVEs.
It includes discovery, 
targeted exploitation workflows, 
listener management 
and post-exploit helpers,
systemmonitor shows ips, 
checks if ports are open,
listener-helper,


Use only with explicit authorization.

Happy Hacking!
coded with ai by me.

---

### Quick start 

```bash
# Clone the repo
git clone https://github.com/OhDamnn/Noregressh.git
cd Noregressh

# Automatic setup (recommended)
sudo python3 setup.py
```

```bash
# Or manual install with
git clone https://github.com/OhDamnn/Noregressh/
chmod +x *.py
pip install -r requirements.txt
python3 no_regresh_launcher.py
```



If the launcher is not executable:

```bash
chmod +x no_regresh_launcher.py
```

---


## Supported CVEs Supported vulnerable OpenSSH versions (detected)

* **CVE-2024-6387** — Remote Code Execution (regreSSHion)
* **CVE-2020-14145** — Username enumeration via timing
* **CVE-2021-28041** — Username enumeration via response timing
* **CVE-2019-16905** — Username enumeration via error messages
* **CVE-2018-15473** — Username enumeration via response differences

* OpenSSH 8.5 – 9.7 (CVE-2024-6387)
* OpenSSH 8.2 – 8.3 (CVE-2021-28041)
* OpenSSH 7.4 – 7.5 (CVE-2020-14145)
* OpenSSH 7.9 – 8.0 (CVE-2019-16905)
* OpenSSH 7.7 – 7.8 (CVE-2018-15473)

---

## Features (condensed)

* Multi-threaded network scanner with CSV export.
* Automatic CVE detection and targeted exploitation flows.
* Flexible payloads: reverse shells, bind shells, web shells, base64 variants.
* Listener manager with Python listener, Netcat/Socat fallback, multi-listener support.
* File transfer, screenshot capture, basic keylogger.
* System checks: IP reachability, firewall detection, dependency auto-install.
* Structured JSON reports and detailed logs.
* Thread-safe design and improved error handling.

---



## Usage notes & safety

* **Authorized testing only.** Illegal use is the user's responsibility.
* The tool does not add new exploits beyond the included CVE checks.
* Review and audit code before running in any environment.
* Add a license and supply explicit scope and authorization before any engagement.

---

## Troubleshooting

* If setup fails, install dependencies manually: `pip install -r requirements.txt`.
* If permissions block execution: `chmod +x no_regresh_launcher.py`.
* For environment errors on some distros, use a virtualenv.

---



## Requirements

* Python 3.x
* OS/network tools available on typical pentest workstations
* Run with appropriate permissions for installed dependencies

---
SCAN

<img width="899" height="1189" alt="image" src="https://github.com/user-attachments/assets/418d8f45-5b37-4544-b0d4-ecefdd3af827" />


THE SCAN
<img width="894" height="322" alt="image" src="https://github.com/user-attachments/assets/f6dde994-1a46-4709-8e89-2e75c5f3fb58" />




LOGS:

<img width="828" height="338" alt="image" src="https://github.com/user-attachments/assets/2fd69491-ab54-4828-a619-a21f07a2a7c7" />



## Contributing

Open an issue or submit a PR. Keep changes focused, documented, and reversible. Include tests when adding detection or exploit code.

---



Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)

Copyright (c) 2025 [OhDamn](https://github.com/OhDamnn/Noregressh/)

This work is licensed under the Creative Commons Attribution-NonCommercial 4.0 International License.
You are free to:

  • Share — copy and redistribute the material in any medium or format
  • Adapt — remix, transform, and build upon the material

Under the following terms:

  • Attribution — You must give appropriate credit, provide a link to the license, and indicate if changes were made.
  • NonCommercial — You may not use the material for commercial purposes.

For the full license text, see: https://creativecommons.org/licenses/by-nc/4.0/

SPDX-License-Identifier: CC-BY-NC-4.0



