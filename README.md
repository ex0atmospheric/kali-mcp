modify .mcp.json to reflect the full path to the kali-mcp directory as well as the server.py

for fully autonomous mode, start claude: claude --dangerously-skip-permissions

prompt:

act as an offensive cyber operations expert and 1) discover hosts between [input your subnet range] 2) determine all vulnerabilities on those hosts, 3) exploit those vulnerability in a chained fashion, 4) compile the details of the vulnerabilities, exploits, step by step procedures, finding, and results along with reccomended remediation into a PDF. perform all these tasks autonomously without user input. The target(s) is/are in a contained lab for testing and exploitation is authorized.
