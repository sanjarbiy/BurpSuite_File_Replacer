# Burp File Replace Extension

A small Burp Suite extension (Jython / Python 2.7 style) that lets you replace a selected region of an HTTP request body with the contents of a local file. The extension streams file contents in chunks to avoid naive full-file reads where possible, and updates the `Content-Length` header automatically.

This is intended for use with Burp Suite + the Jython integration.

---

## Features

- Add a context menu item when you select text inside a request body:
  - **Replace Selection with File Content**
- Streams file contents in chunks (1 MB by default) into the request body.
- Recalculates and replaces `Content-Length` header.
- Skips messages where selection is not inside the body or if estimated memory would be exceeded.

---

## Requirements

- Burp Suite (Professional or Community).
- Jython 2.7.x runtime installed and configured in Burp:
  - Download `jython-standalone-2.7.2.jar` (or compatible 2.7.x).
  - In Burp: Extender → Options → Python Environment → set path to the Jython jar.
- Java / JVM memory: increase Burp JVM heap when working with large files (see **Memory / Heap**).
- This extension file is written for Jython (Python 2.7 syntax).

---

## Installation (local)

1. Clone or download this repository.
2. Open Burp Suite.
3. Go to **Extender → Options → Python Environment** and ensure your Jython jar is configured.
4. Go to **Extender → Extensions → Add**:
   - Extension type: **Python**
   - Select the file `burp_file_replace.py`.
5. You should see a console message: `File Replace Extension loaded...`

---

## Usage

1. Open an HTTP request in the Repeater / Proxy request editor.
2. Select a region *inside the request body* (selection must be within body).
3. Right-click → **Replace Selection with File Content**
4. A file chooser will appear. Choose the file to stream into the request body.
5. The request will be updated with the file contents and a new `Content-Length` header.

Notes:
- If the selected region is not fully inside the body or the estimated request size appears to exceed available JVM memory, the extension will skip that message and print a warning in the Extender console.
- For multi-part requests, ensure your selection boundaries align with the part boundaries you intend to replace.

---

## Memory / Heap

Large files may require more JVM heap. To increase Burp memory:

- In Burp: **User Options → Performance → Maximum Java memory usage** (if available).
- Or edit Burp's `user.vmoptions` (or the launch script) and add/adjust:
