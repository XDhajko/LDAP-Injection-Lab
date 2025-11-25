# LDAP Injection Lab

## Overview
This repository contains a series of exercises designed to teach you about LDAP injection vulnerabilities. By completing the exercises, you will learn how to identify, exploit, and remediate LDAP injection flaws. Additionally, you will gain experience in hardening applications against such attacks.

- Harden your own applications by running the included code scanner that flags dangerous LDAP usage patterns in Python projects.
- Check solution to exercises using helper script locally so you understand how each vulnerability works.

## Quick Start (Docker Compose)
To get started with the lab exercises, follow these steps:
1. Clone and enter the workspace:
   ```bash
   git clone https://github.com/XDhajko/LDAP-Injection-Lab)
   cd ldap-injection-lab/virtual_setup_complete
   ```
2. Launch the lab:
   ```bash
   docker compose up --build
   ```
3. Navigate to <http://localhost:8000> after the containers report “healthy”.

4. Stop the lab when finished:
   ```bash
   docker compose down
   ```

## Exercises
The lab hosts five standalone exercises, each focusing on a distinct LDAP injection vector:
1. **Exercise 1 – Authentication Bypass**  
   Craft filters that allow bypassing authenticaion methods.
2. **Exercise 2 – Exploitation of file priviliges**  
   Get access to files by modifying your privilige by filter tampering.
3. **Exercise 3 – Device Information disclosure**  
   Disclose information about devices that may seem out of your reach.
4. **Exercise 4 – AND Blind LDAP Injection**  
   Infer information about a users using AND BLIND injection technique.
5. **Exercise 5 – OR Blind LDAP Injection**  
   FInd information about any object in the LDAP tree.

Each exercise prvovides a task to be completed. Complete them sequentially or jump directly to the challenge you need. Lab allows setting of safeness, verbosity and client mode to test variations of the same vulnerabilities.

## Attack Script
If you get stuck, use the helper script that both performs the exploit and explains the solution.

```bash
python tools/solution_script.py
```

The script outputs:
- Crafted payloads
- Used filters
- Extracted data
- Explanation of the solution

## Code Scanner for Your Python Apps
To prevent LDAP injection in your own projects, run the static scanner:

```bash
python tools/code_scanner.py c:\path\to\your\app
```

Validate the scanner itself by pointing it at web directory:
```bash
python tools/code_scanner.py .\web
```

What it does:
- Finds vulnerabilities in LDAP filters/binds.
- Highlights unescaped user-controlled attributes.
- Suggests safe fixes to be used.


## Troubleshooting
- **Containers restart repeatedly**: run `docker compose logs` to inspect LDAP schema load errors.
- **Attack script cannot connect**: ensure the web service is reachable at <http://localhost:8000> and that your firewall allows local traffic.

## Contributing
We welcome contributions to enhance the lab and its resources. Please submit issues or pull requests for review.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
