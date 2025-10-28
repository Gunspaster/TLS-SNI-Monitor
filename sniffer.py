from scapy.all import sniff, IP, IPv6, TCP, Raw
from rich.console import Console
from rich.table import Table
from rich import box
from rich.text import Text
from datetime import datetime
import argparse
import socket
import struct

console = Console()

DISCORD_KEYWORDS = ["discord", "discordapp", "discord.gg", "gateway.discord"]

def utcnow():
    return datetime.utcnow().isoformat() + "Z"

def extract_sni_from_client_hello(payload: bytes) -> str | None:
    try:
        if len(payload) < 5 or payload[0] != 0x16:
            return None
        rec_len = struct.unpack("!H", payload[3:5])[0]
        if len(payload) < 5 + rec_len:
            pass
        hs_offset = 5
        if payload[hs_offset] != 0x01:
            return None
        ptr = hs_offset + 4
        ptr += 2
        ptr += 32
        if ptr >= len(payload):
            return None
        sid_len = payload[ptr]
        ptr += 1 + sid_len
        if ptr + 2 > len(payload):
            return None
        cs_len = struct.unpack("!H", payload[ptr:ptr+2])[0]
        ptr += 2 + cs_len
        if ptr + 1 > len(payload):
            return None
        comp_len = payload[ptr]
        ptr += 1 + comp_len
        if ptr + 2 > len(payload):
            return None
        ext_len = struct.unpack("!H", payload[ptr:ptr+2])[0]
        ptr += 2
        end_ext = ptr + ext_len
        while ptr + 4 <= end_ext and ptr + 4 <= len(payload):
            ext_type = struct.unpack("!H", payload[ptr:ptr+2])[0]
            extlen = struct.unpack("!H", payload[ptr+2:ptr+4])[0]
            ptr += 4
            if ext_type == 0x00:
                if ptr + 2 > len(payload): return None
                list_len = struct.unpack("!H", payload[ptr:ptr+2])[0]
                ptr += 2
                end_list = ptr + list_len
                while ptr + 3 <= end_list and ptr + 3 <= len(payload):
                    name_type = payload[ptr]
                    name_len = struct.unpack("!H", payload[ptr+1:ptr+3])[0]
                    ptr += 3
                    if ptr + name_len > len(payload):
                        return None
                    server_name = payload[ptr:ptr+name_len].decode(errors="ignore")
                    return server_name
            else:
                ptr += extlen
        return None
    except Exception:
        return None

def ip_to_str(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    elif IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    return None, None

RECENT = []

def pretty_print_event(ts, kind, sni, dst_ip, dst_port, verdict):
    """Print colored single-line event and append to RECENT"""
    t = Text()
    t.append(f"[{ts}] ", style="dim")
    if kind == "discord":
        t.append("CONNECTING TO A TLS (Discord) ", style="bold green")
    else:
        t.append("TLS CONNECT ", style="bold cyan")
    if sni:
        t.append(f"{sni} ", style="magenta")
    t.append(f"→ {dst_ip}:{dst_port} ", style="yellow")
    t.append(f"({verdict})", style="bold")
    console.print(t)

def packet_handler(pkt):
    try:
        if not (TCP in pkt):
            return
        tcp = pkt[TCP]
        if not pkt.haslayer(Raw):
            return
        payload = bytes(pkt[Raw].load)
        dst_port = tcp.dport
        src_ip, dst_ip = ip_to_str(pkt)
        sni = extract_sni_from_client_hello(payload)
        is_discord = False
        if sni:
            lower = sni.lower()
            for kw in DISCORD_KEYWORDS:
                if kw in lower:
                    is_discord = True
                    break
        kind = "discord" if is_discord else "tls"
        verdict = "discord" if is_discord else "other"
        pretty_print_event(utcnow(), kind, sni, dst_ip, dst_port, verdict)
    except Exception as e:
        console.log(f"[error parsing pkt] {e}", style="red")

def main():
    p = argparse.ArgumentParser(description="Local TLS sniffer — detect ClientHello SNI and highlight Discord connections")
    p.add_argument("--iface", "-i", help="interface to sniff (default: first non-loopback) ", default=None)
    p.add_argument("--only-discord", action="store_true", help="only show events where SNI contains discord")
    p.add_argument("--all-tls", action="store_true", help="show all TLS events (default shows TLS but highlight discord)")
    args = p.parse_args()

    iface = args.iface
    if iface is None:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = None
        console.print(f"[bold]Starting TLS sniffer on interface[/bold] {iface or '(auto)'} — run as root/sudo if required", style="cyan")
    else:
        console.print(f"[bold]Starting TLS sniffer on interface[/bold] {iface}", style="cyan")

    bpf = "tcp port 443"
    console.print(f"[dim]BPF filter:[/dim] {bpf}")

    def callback(pkt):
        try:
            if not pkt.haslayer(Raw):
                return
            payload = bytes(pkt[Raw].load)
            sni = extract_sni_from_client_hello(payload)
            if args.only_discord:
                if not sni:
                    return
                if "discord" not in sni.lower():
                    return
            packet_handler(pkt)
        except Exception as e:
            console.log(f"callback error: {e}", style="red")

    sniff(filter=bpf, prn=callback, store=False, iface=iface)

if __name__ == "__main__":
    import argparse
    main()

