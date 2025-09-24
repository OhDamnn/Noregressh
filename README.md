
Originally I wanted to build a regreSHHion scanner and exploiter; I then added additional CVEs to it. If anyone can help me expand parts of the project, please get in touch.

WELCOME TO NOREGRESSH 

norregressh is a penetration-testing framework focused on OpenSSH regressions and multiple CVEs.
It includes discovery, targeted exploitation workflows, listener management and post-exploit helpers.

Use only with explicit authorization.


Happy Hacking!


---

## Quick start (GitHub-ready)

```bash
# Clone the repo
git clone https://github.com/OhDamnn/Noregressh.git
cd Noregressh

# Automatic setup (recommended)
sudo python3 setup.py

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

## Requirements

* Python 3.x
* OS/network tools available on typical pentest workstations
* Run with appropriate permissions for installed dependencies

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

## Contributing

Open an issue or submit a PR. Keep changes focused, documented, and reversible. Include tests when adding detection or exploit code.

---

## License

Add a LICENSE file to this repository. Recommended: choose an appropriate open-source license (MIT/Apache/BSD) and state permitted use.

---

## Contact

Use GitHub Issues or Pull Requests for feedback, bugs, or questions. Any ai vibecoders wanna collab? PM
