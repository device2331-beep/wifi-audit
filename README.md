# WiFi Network Security Audit Tool

Nijer WiFi network-er security check korar jonno ekta simple Python tool. Termux-e run kora jay, kono external dependency lage na (shudhu standard library).

## Clone

```bash
git clone https://github.com/device2331-beep/wifi-audit.git
cd wifi-audit
```

## ⚠️ Important Disclaimer

**Ei tool shudhu nijer own network-e, ba jei network audit korar jonno explicit permission ache, sheikhane use korar jonno banano.**

- Onno kono network scan kora, port scan kora, ba router-e login try kora — jekhane tomar permission nei — sheta ain-bohirbhuto (illegal) hote pare, desh bhede.
- Ei tool-e ekta "default credentials check" feature ache (common admin/admin type password diye router login try kore). Eta **shudhu nijer router-er security weakness check korar jonno**, kono onno device-e brute-force korar jonno na.
- Developer (repo owner) ei tool-er misuse-er jonno kono dায়bhar nibe na. Use at your own risk and responsibility.

Nijer network audit kora completely legal ebong recommended practice — kintu onno karo network-e eki kaj kora sompurno alada ain-gato bishoy.

## Features

- Local subnet auto-detect
- Parallel host discovery (ping sweep)
- Common risky port scanning (FTP, Telnet, SMB, RDP, etc.)
- Router/gateway admin panel detection
- Default credentials check (shudhu nijer router-er jonno)
- Color-coded terminal output
- Risk score calculation
- JSON report export

## Requirements

- Python 3
- Termux (Android) othoba any Linux/Unix system
- `ping`, `ip route` command available thakte hobe

## Installation

```bash
pkg update
pkg install python
pkg install iproute2
pkg install inetutils
```

`iproute2` diye `ip route` command ashe (gateway ber korar jonno). `inetutils` diye `ping` command ashe, na thakle kichu Termux setup-e ping kaj nao korte pare.

## Usage

```bash
python wifi_audit.py
```

Script automatically:
1. Tomar local subnet detect korbe
2. Shei subnet-e alive host gula khuje ber korbe
3. Risky port gula check korbe
4. Router-er admin panel check korbe (shudhu tomar nijer gateway)
5. Ekta full report dekhabe, JSON e save korar option debe

## License

MIT License — free to use, modify, ebong share korte paro, kintu upore deya disclaimer mene cholte hobe.

## Repository

https://github.com/device2331-beep/wifi-audit
