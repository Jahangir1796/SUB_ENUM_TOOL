# BlackByt3 Subdomain Enumeration – SecurityTrails Module

This is a Python module for **subdomain enumeration tool** using the SecurityTrails API.  
It is part of the internship project **Subdomain Enumeration Tool** at *Black Byt3* by Team *NEXUS*.  

## Features
- Integrates with SecurityTrails API
- Two methods supported:
  - `list` → Simple subdomain listing
  - `search` → Advanced search with pagination
- Saves results to a file
- Handles rate limiting and retries automatically

## Usage
```bash
python sub_enum.py <domain> --method <list|search> --api-key <YOUR_API_KEY> --out results.txt
