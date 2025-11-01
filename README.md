
# Threat Forge

<pre>
$$$$$$$$\ $$\                                      $$\           $$$$$$$$\                                      
\__$$  __|$$ |                                     $$ |          $$  _____|                                     
   $$ |   $$$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\ $$$$$$\         $$ |    $$$$$$\   $$$$$$\   $$$$$$\   $$$$$$\  
   $$ |   $$  __$$\ $$  __$$\ $$  __$$\  \____$$\\_$$  _|        $$$$$\ $$  __$$\ $$  __$$\ $$  __$$\ $$  __$$\ 
   $$ |   $$ |  $$ |$$ |  \__|$$$$$$$$ | $$$$$$$ | $$ |          $$  __|$$ /  $$ |$$ |  \__|$$ /  $$ |$$$$$$$$ |
   $$ |   $$ |  $$ |$$ |      $$   ____|$$  __$$ | $$ |$$\       $$ |   $$ |  $$ |$$ |      $$ |  $$ |$$   ____|
   $$ |   $$ |  $$ |$$ |      \$$$$$$$\ \$$$$$$$ | \$$$$  |      $$ |   \$$$$$$  |$$ |      \$$$$$$$ |\$$$$$$$\ 
   \__|   \__|  \__|\__|       \_______| \_______|  \____/       \__|    \______/ \__|       \____$$ | \_______|
                                                                                            $$\   $$ |          
                                                                                            \$$$$$$  |          
                                                                                             \______/           

==================================================================================================================
                                  Malicious File Scanner v1.0 - @dev xghost
==================================================================================================================
</pre>

A lightweight C-based command-line tool for scanning files against the VirusTotal v3 API.


---

### ⚡ Overview

**Threat Forge** reads a file, computes its **SHA-256 hash** (a fixed-length fingerprint), asks **VirusTotal** whether that fingerprint is known, then prints how many antivirus engines marked it `malicious`, `suspicious`, or `undetected`.
---

### 🧩 Features

- 🔒 Calculates **SHA-256 hash** using OpenSSL.  
- 🌐 Connects securely to VirusTotal with **libcurl** over HTTPS.  
- 🧠 Parses JSON data using **cJSON**.  
- 🧾 Displays clean and color-coded scan results.

---

### 🔧 Requirements

You must keep the following files in the same directory as `ThreatForge.exe`:

| File | Purpose |
|------|----------|
| `ThreatForge.exe` | The main program |
| `libcurl.dll`,  | Networking libraries |
| `curl-ca-bundle.crt` | Trusted certificate authorities list for SSL |

These are essential dependencies that enable the tool to communicate securely with VirusTotal’s API.

### Why are these files needed?

* **`libcurl.dll` (and its dependencies):** It's the library that does all the complex internet networking and handles the secure `https://` connection.
* **`curl-ca-bundle.crt`:** This is the "ID card list." It's a file containing trusted Certificate Authorities. Our program uses this to verify that it is *really* talking to VirusTotal and not a "man-in-the-middle" attacker.
  
---

### 🧰 Compile It Yourself

If you’re using **MinGW (Windows)** and have CURL installed, run:

```bash
gcc ThreatForge.c cJSON.c -o ThreatForge.exe -I[PATH_TO_LIBCURL_INCLUDE] -L[PATH_TO_LIBCURL_LIB] -lcurl -lssl -lcrypto -lws2_32 -lm
```
if not please install the CURL using this link: https://curl.se/windows/

## ⚙️ How to Use

This is a command-line tool. You'll need to use flags to provide the file you want to scan and your personal API key.


| Flag | Purpose |
|------|----------|
| `-f`,`--file` | Path to the file to scan. |
| `-k`, `--key` | Your VirusTotal API key. |
| `-h`, `--help` | Show this help menu. |



### Usage:
```bash
.\ThreatForge.exe -f <filename> -k <your_api_key>
```

<img width="1649" height="780" alt="threatforge" src="https://github.com/user-attachments/assets/4ba8f4a9-d3bf-4d7e-bdce-2bb8f925dada" />
