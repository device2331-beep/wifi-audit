# WiFi Network Security Audit Tool

Nijer WiFi network-er security check korar jonno ekta simple Python tool. Termux-e run kora jay, kono external dependency lage na (shudhu standard library).

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

## Usage

```bash
python mehidi62.py
