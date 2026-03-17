# MCP Kali Server

**MCP Kali Server (MKS)** is a lightweight API bridge that connects [MCP clients](https://modelcontextprotocol.io/clients) (e.g: [Claude Desktop](https://code.claude.com/docs/en/desktop) or [5ire](https://github.com/nanbingxyz/5ire)) to the [API server](https://modelcontextprotocol.io/examples) which allows executing commands on a Linux terminal.

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
- Using AI to suggest and run terminal commands to [solve CTF challenges](#example-solving-a-web-ctf-challenge-from-ramadanctf) or automate recon/exploitation tasks.
- Allowing MCP apps to send custom requests (e.g. `curl`, `nmap`, `ffuf`, etc.) and receive structured outputs.

Here are some example (using Google's AI `gemini 2.0 flash`):

### Example solving a web CTF challenge from RamadanCTF

https://github.com/user-attachments/assets/dc93b71d-9a4a-4ad5-8079-2c26c04e5397

### Trying to solve machine "code" from HTB

https://github.com/user-attachments/assets/3ec06ff8-0bdf-4ad5-be71-2ec490b7ee27

---

## 🚀 Features

- 🧠 **AI Endpoint Integration**: Connect your Kali to any MCP of your liking such as Claude Desktop or 5ier.
- 🖥️ **Command Execution API**: Exposes a controlled API to execute terminal commands on your Kali Linux machine.
- 🕸️ **Web Challenge Support**: AI can interact with websites and APIs, capture flags via `curl` and any other tool AI the needs.
- 🔐 **Designed for Offensive Security Professionals**: Ideal for red teamers, bug bounty hunters, or CTF players automating common tasks.
- 🔑 **API Key Authentication**: Mandatory API key to prevent unauthorized access. Auto-generated if not provided.

---

## 🛠️ Installation and Running

### On your Kali Machine

```bash
sudo apt install mcp-kali-server
kali-server-mcp
```

Otherwise for **bleeding edge**:

```bash
git clone https://github.com/Wh0am123/MCP-Kali-Server.git
cd MCP-Kali-Server
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
./server.py
```

**Command Line Options**:

- `--ip <address>`: Specify the IP address to bind the server to (default: `127.0.0.1` for localhost only)
  - Use `127.0.0.1` for local connections only (secure, recommended)
  - Use `0.0.0.0` to allow connections from any network interface (very dangerous; use with caution)
  - Use a specific IP address to bind to a particular network interface
- `--port <port>`: Specify the port number (default: `5000`)
- `--api-key <key>`: Set the API key for authentication. If not provided (and `MKS_API_KEY` env var is not set), a secure random key is generated and printed at startup.
- `--debug`: Enable debug mode for verbose logging

The server **always requires an API key**. You can provide one via `--api-key`, the `MKS_API_KEY` environment variable, or let the server auto-generate one at startup. The generated key is printed to the console — copy it and configure your MCP client with it.

**Examples**:

```bash
# Run with auto-generated API key (printed to console at startup)
./server.py

# Run with a specific API key
./server.py --api-key YOUR_SECRET_KEY

# Or use an environment variable
export MKS_API_KEY="YOUR_SECRET_KEY"
./server.py

# Run on all interfaces (less secure, useful for remote access)
./server.py --ip 0.0.0.0 --api-key YOUR_SECRET_KEY

# Run on a specific IP and custom port
./server.py --ip 192.168.1.100 --port 8080

# Run with debug mode
./server.py --debug
```

### On your MCP client machine

This can be local (on the same Kali machine) or remote (another Linux machine, Windows or macOS).

If you're running the client and server on the same _Kali_ machine (aka local), run either:

```bash
## OS package
kali-server-mcp --server http://127.0.0.1:5000 --api-key YOUR_SECRET_KEY

# ...OR...

## Bleeding edge
./client.py --server http://127.0.0.1:5000 --api-key YOUR_SECRET_KEY
```

The `--api-key` must match the key configured on the server. If you let the server auto-generate a key, copy it from the server's startup output. You can also set `MKS_API_KEY` as an environment variable instead of passing it as a flag.

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
./client.py --server http://127.0.0.1:5000 --api-key YOUR_SECRET_KEY
```

---

If you're openly hosting the MCP Kali server on your network (`server.py --IP...`), you don't need the SSH tunnel (but we do recommend it!)
NOTE: ⚠️(THIS IS STRONGLY DISCOURAGED. WE RECOMMEND SSH)⚠️.

```bash
./client.py --server http://LINUX_IP:5000 --api-key YOUR_SECRET_KEY
```

#### Configuration for Claude Desktop:

Edit:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`

[Example MCP-Kali-Server.json](mcp-kali-server.json)

#### Configuration for 5ire Desktop Application:

- Simply add an MCP with the command `python3 /absolute/path/to/client.py --server http://LINUX_IP:5000 --api-key YOUR_SECRET_KEY` and it will automatically generate the needed configuration files.

## 🔮 Other Possibilities

There are more possibilities than described since the AI model can now execute commands on the terminal. Here are some examples:

- Memory forensics using Volatility
  - Automating memory analysis tasks such as process enumeration, DLL injection checks, and registry extraction from memory dumps.

- Disk forensics with SleuthKit
  - Automating analysis from disk images, timeline generation, file carving, and hash comparisons.

## ⚠️ Disclaimer:

This project is intended solely for educational and ethical testing purposes. Any misuse of the information or tools provided — including unauthorized access, exploitation, or malicious activity — is strictly prohibited.

The author assumes no responsibility for misuse.
