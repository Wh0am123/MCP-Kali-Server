# MCP Kali Server

**MCP Kali Server** is a lightweight API bridge that connects [MCP clients](https://modelcontextprotocol.io/clients) (e.g: [Claude Desktop](https://code.claude.com/docs/en/desktop) or [5ire](https://github.com/nanbingxyz/5ire)) to the [API server](https://modelcontextprotocol.io/examples) which allows executing commands on a Linux terminal.

This MCP is able to run terminal commands as well as interacting with web applications using:

- `Dirb`
- `enum4linux`
- `gobuster`
- `Hydra`
- `John the Ripper`
- `Metasploit-Framework`
- `Nikto`
- `Nmap`
- `sqlmap`
- `WPScan`
- As well as being able to execute raw commands.

As a result, this is able to perform **AI-assisted penetration testing** and solving **CTF challenges** in real time.

## Articles Using This Tool

[![How MCP is Revolutionizing Offensive Security](https://miro.medium.com/v2/resize:fit:828/format:webp/1*g4h-mIpPEHpq_H63W7Emsg.png)](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

👉 [**How MCP is Revolutionizing Offensive Security**](https://yousofnahya.medium.com/how-mcp-is-revolutionizing-offensive-security-93b2442a5096)

---

## 🔍 Use Case

The goal is to enable AI-driven offensive security testing by:

- Letting the MCP interact with AI endpoints like [OpenAI](https://openai.com/), [Claude](https://claude.ai/), [DeepSeek](https://www.deepseek.com/), [Ollama](https://docs.ollama.com/) or any other models.
- Exposing an API to execute commands on a [Kali](https://www.kali.org/) machine.
- Using AI to suggest and run terminal commands to [solve CTF challenges](#example-solving-my-web-ctf-challenge-in-ramadanctf) or automate recon/exploitation tasks.
- Allowing MCP apps to send custom requests (e.g. `curl`, `nmap`, `ffuf`, etc.) and receive structured outputs.

Here are some example (using Google's AI `gemini 2.0 flash`):

### Example solving my web CTF challenge in RamadanCTF

https://github.com/user-attachments/assets/dc93b71d-9a4a-4ad5-8079-2c26c04e5397

### Trying to solve machine "code" from HTB

https://github.com/user-attachments/assets/3ec06ff8-0bdf-4ad5-be71-2ec490b7ee27

---

## 🚀 Features

- 🧠 **AI Endpoint Integration**: Connect your Kali to any MCP of your liking such as Claude Desktop or 5ier.
- 🖥️ **Command Execution API**: Exposes a controlled API to execute terminal commands on your Kali Linux machine.
- 🕸️ **Web Challenge Support**: AI can interact with websites and APIs, capture flags via `curl` and any other tool AI the needs.
- 🔐 **Designed for Offensive Security Professionals**: Ideal for red teamers, bug bounty hunters, or CTF players automating common tasks.

---

## 🛠️ Installation and Running

### On your Kali Machine

```bash
sudo apt install mcp-kali-server
kali-server
```

Otherwise for **bleeding edge**:

```bash
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 kali_server.py
```

**Command Line Options**:

- `--ip <address>`: Specify the IP address to bind the server to (default: `127.0.0.1` for localhost only)
  - Use `127.0.0.1` for local connections only (secure, recommended)
  - Use `0.0.0.0` to allow connections from any network interface (very dangerous; use with caution)
  - Use a specific IP address to bind to a particular network interface
- `--port <port>`: Specify the port number (default: `5000`)
- `--debug`: Enable debug mode for verbose logging

**Examples**:

```bash
# Run on localhost only (secure, default)
python3 kali_server.py

# Run on all interfaces (less secure, useful for remote access)
python3 kali_server.py --ip 0.0.0.0

# Run on a specific IP and custom port
python3 kali_server.py --ip 192.168.1.100 --port 8080

# Run with debug mode
python3 kali_server.py --debug
```

### On your MCP client machine

This can be local (on the same Kali machine) or remote (another Linux machine, Windows or macOS).

If you're running the client and server on the same _Kali_ machine (aka local), run either:

```bash
## OS package
mcp-server --server http://127.0.0.1:5000

# ...OR...

## Bleeding edge
./mcp_server.py --server http://127.0.0.1:5000
```

---

If separate machines (aka remote), create an SSH tunnel to your MCP server, then launch the client:

```bash
## Terminal 1 - Replace `LINUX_IP` with Kali's IP
ssh -L 5000:localhost:5000 user@LINUX_IP

## Terminal 2
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./mcp_server.py --server http://127.0.0.1:5000
```

---

If you're openly hosting the MCP Kali server on your network (`kali_server.py --IP...`), you don't need the SSH tunnel (but we do recommend it!)
NOTE: ⚠️(THIS IS STRONGLY DISCOURAGED. WE RECOMMEND SSH)⚠️.

```bash
./mcp_server.py --server http://LINUX_IP:5000
```

#### Configuration for Claude Desktop:

Edit:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

[Example MCP-Kali-Server.json](mcp-kali-server.json)

#### Configuration for 5ire Desktop Application:

- Simply add an MCP with the command `python3 /absolute/path/to/mcp_server.py http://LINUX_IP:5000` and it will automatically generate the needed configuration files.

## 🔮 Other Possibilities

There are more possibilities than described since the AI model can now execute commands on the terminal. Here are some examples:

- Memory forensics using Volatility
  - Automating memory analysis tasks such as process enumeration, DLL injection checks, and registry extraction from memory dumps.

- Disk forensics with SleuthKit
  - Automating analysis from disk images, timeline generation, file carving, and hash comparisons.

## ⚠️ Disclaimer:

This project is intended solely for educational and ethical testing purposes. Any misuse of the information or tools provided — including unauthorized access, exploitation, or malicious activity — is strictly prohibited.

The author assumes no responsibility for misuse.
