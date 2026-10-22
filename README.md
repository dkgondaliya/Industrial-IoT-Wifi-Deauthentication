# IIoT Wi-Fi Deauthentication Resilience — Attack Simulation & Detection

A security-research tool developed for my BSc (Hons) Cyber Security and Networks dissertation at the **University of East London**, investigating the resilience of **Industrial IoT (IIoT) Wi-Fi** networks to IEEE 802.11 **deauthentication attacks**, and the effectiveness of **Protected Management Frames (PMF / 802.11w)** as a countermeasure.

The tool has two components:

- an **attack-simulation module** that forges and transmits deauthentication frames to test the resilience of access points and stations in a controlled laboratory; and
- a **passive detector** that monitors for deauthentication floods, fingerprints nearby networks (WPA2 / WPA3 / transition mode), and reports whether each network is protected by PMF.

---

## ⚠️ Legal and ethical use — read before running

This project is published **strictly for education and authorised security research.** Transmitting deauthentication frames disrupts wireless connectivity and is an **active attack**.

Running the attack-simulation component against any network, access point or device that you **do not own**, or **do not have explicit written authorisation to test**, is **illegal in most jurisdictions** — in the United Kingdom under the **Computer Misuse Act 1990** and the **Wireless Telegraphy Act 2006**, and elsewhere under equivalent computer-misuse and radio-interference laws.

- Use the attack component **only** inside an **isolated lab** or on infrastructure you are explicitly authorised to assess.
- The **detection component is passive** and transmits nothing.
- The author accepts **no liability** for any misuse of this software.

---

## Background

Deauthentication frames are unauthenticated 802.11 management frames, which historically allowed an attacker within radio range to disconnect clients from a network — a well-known wireless denial-of-service technique. This is a particular concern for Industrial IoT deployments, where loss of connectivity can disrupt monitoring and control. The **802.11w** amendment introduced Protected Management Frames (PMF) to authenticate management frames and mitigate this class of attack; it is mandatory in WPA3 and optional in WPA2. This project examines, in a controlled setting, how legacy and modern IIoT configurations withstand deauthentication attacks and how reliably PMF defeats them.

## Features

- Passive **deauth-flood detection** with configurable rate thresholds and time windows
- **WPA2 / WPA3 / transition-mode** fingerprinting via RSN information-element parsing
- **PMF (802.11w) detection** — distinguishes *PMF-required*, *PMF-capable*, and *no PMF*
- Per-network **vulnerability assessment** based on the above
- **Attack-simulation module** for authorised resilience testing (single-interface channel hopping and targeted/broadcast frames)
- Live status reporting and optional alert **logging**
- **Unit-tested** RSN/PMF parser and flood detector (`--test`)

## Requirements

- Linux and Python 3.x
- A wireless adapter that supports **monitor mode** and **packet injection**
- [**scapy**](https://scapy.net/) — `pip install scapy`
- **Root privileges** (raw 802.11 frames)
- Any local helper modules included in this repository (e.g. `pull.py`)

## Installation

```bash
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
pip install -r requirements.txt
```

Put your adapter into monitor mode first (for example with `airmon-ng start wlan0`), which exposes an interface such as `wlan0mon`.

## Usage

Run the **passive detector** (transmits nothing):

```bash
sudo python wifijammer.py -i wlan0mon
```

See all options — detection threshold, time window, alert cooldown, logging:

```bash
python wifijammer.py --help
```

Run the unit tests:

```bash
python wifijammer.py --test
```

> The attack-simulation component must only ever be used against devices and networks you own or are explicitly authorised to test. See **Legal and ethical use** above.

## Results

<!-- Summarise your dissertation findings here, e.g.: which IIoT configurations were
disconnected by deauth frames, and how WPA3 / PMF-Required networks resisted the attack. -->
*(Add a short summary of your dissertation's findings here.)*

## Project context

Developed as part of my BSc (Hons) Cyber Security and Networks dissertation, University of East London.

## Author

**Zeel Gondaliya** — [LinkedIn](https://www.linkedin.com/in/zeel-gondaliya-9b48a2191) · <!-- add ORCID once created -->

## License

Released under the MIT License — see [`LICENSE`](LICENSE).
