# -*- coding: utf-8 -*-
from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JFileChooser
from java.io import ByteArrayOutputStream, File, FileOutputStream
from java.lang import Runtime
import os

CHUNK_SIZE = 1024 * 1024  # 1MB

class BurpExtender(IBurpExtender, IContextMenuFactory):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Replace & View Selection")
        callbacks.registerContextMenuFactory(self)
        print("[+] Extension loaded – works in Proxy, Repeater, Intruder, Scanner, everywhere!")

    def bytes_startswith(self, data, prefix):
        if len(data) < len(prefix):
            return False
        for i in range(len(prefix)):
            if data[i] != ord(prefix[i]):
                return False
        return True

    def detect_suffix(self, data):
        if len(data) == 0:
            return ".bin"
        sigs = {
            b"%PDF": ".pdf",
            b"\xff\xd8\xff": ".jpg",
            b"\x89PNG\r\n\x1a\n": ".png",
            b"GIF87a": ".gif",
            b"GIF89a": ".gif",
            b"\x50\x4b\x03\x04": ".zip",
            b"MZ": ".exe",
            b"\x7fELF": ".elf",
        }
        for magic, ext in sigs.items():
            if self.bytes_startswith(data, magic):
                return ext
        return ".bin"

    def try_decode(self, selected):
        # Raw check
        suffix = self.detect_suffix(selected)
        if suffix != ".bin":
            return selected, suffix

        # Base64 decode
        try:
            text = self.helpers.bytesToString(selected).strip()
            if all(c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in text):
                decoded = self.helpers.base64Decode(text)
                suffix = self.detect_suffix(decoded)
                if suffix != ".bin":
                    return decoded, suffix
        except:
            pass

        # URL decode
        try:
            decoded = self.helpers.urlDecode(selected)
            suffix = self.detect_suffix(decoded)
            if suffix != ".bin":
                return decoded, suffix
        except:
            pass

        # Default
        return selected, ".bin"

    def createMenuItems(self, invocation):
        bounds = invocation.getSelectionBounds()
        if bounds and bounds[0] != bounds[1]:
            menu = []
            item1 = JMenuItem("Replace selection with file from disk")
            item1.actionPerformed = lambda e: self.replaceWithFile(invocation)
            menu.append(item1)
            item2 = JMenuItem("View selection as file (open in default app)")
            item2.actionPerformed = lambda e: self.viewSelectionAsFile(invocation)
            menu.append(item2)
            return menu
        return None

    def replaceWithFile(self, invocation):
        chooser = JFileChooser()
        chooser.setDialogTitle("Select file to insert")
        if chooser.showOpenDialog(None) != JFileChooser.APPROVE_OPTION:
            return
        file_path = chooser.getSelectedFile().getAbsolutePath()
        messages = invocation.getSelectedMessages()
        for msg in messages:
            try:
                bounds = invocation.getSelectionBounds()
                request = msg.getRequest()
                response = msg.getResponse()
                if request is not None and bounds[0] < len(request):
                    data = request
                    is_request = True
                elif response is not None:
                    data = response
                    is_request = False
                else:
                    continue
                analyzer = self.helpers.analyzeRequest if is_request else self.helpers.analyzeResponse
                analyzed = analyzer(data)
                headers = analyzed.getHeaders()
                body_offset = analyzed.getBodyOffset()
                if bounds[0] < body_offset:
                    print("[!] Selection is in headers, not supported")
                    continue
                body = data[body_offset:]
                start = bounds[0] - body_offset
                end = bounds[1] - body_offset
                baos = ByteArrayOutputStream()
                if start > 0:
                    baos.write(body, 0, start)
                f = open(file_path, "rb")
                try:
                    chunk = f.read(CHUNK_SIZE)
                    while chunk:
                        baos.write(chunk)
                        chunk = f.read(CHUNK_SIZE)
                finally:
                    f.close()
                if end < len(body):
                    baos.write(body, end, len(body) - end)
                new_body = baos.toByteArray()
                new_headers = [h for h in headers if not h.lower().startswith("content-length:")]
                if new_body:
                    new_headers.append("Content-Length: %d" % len(new_body))
                new_message = self.helpers.buildHttpMessage(new_headers, new_body)
                if is_request:
                    msg.setRequest(new_message)
                else:
                    msg.setResponse(new_message)
                print("[+] Replaced with:", file_path)
            except Exception as e:
                print("[-] Replace error:", str(e))

    def viewSelectionAsFile(self, invocation):
        messages = invocation.getSelectedMessages()
        for msg in messages:
            try:
                bounds = invocation.getSelectionBounds()
                request = msg.getRequest()
                response = msg.getResponse()
                if request is not None and bounds[0] < len(request):
                    data = request
                    is_request = True
                elif response is not None:
                    data = response
                    is_request = False
                else:
                    continue
                analyzer = self.helpers.analyzeRequest if is_request else self.helpers.analyzeResponse
                analyzed = analyzer(data)
                body_offset = analyzed.getBodyOffset()
                if bounds[0] < body_offset:
                    continue
                body = data[body_offset:]
                start = bounds[0] - body_offset
                end = bounds[1] - body_offset
                selected = body[start:end]
                if not selected:
                    continue
                decoded, suffix = self.try_decode(selected)
                temp = File.createTempFile("burp_view_", suffix)
                temp.deleteOnExit()
                fos = FileOutputStream(temp)
                try:
                    fos.write(decoded)
                finally:
                    fos.close()
                try:
                    Runtime.getRuntime().exec(["xdg-open", temp.getAbsolutePath()])
                    print("[+] Opened file:", temp.getName())
                except Exception as e:
                    print("[-] Open failed:", str(e))
                    try:
                        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
                        clipboard.setContents(StringSelection(temp.getAbsolutePath()), None)
                        print("[+] Yo'l clipboardga ko'chirildi – Ctrl+V bosib oching!")
                    except:
                        pass
            except Exception as e:
                print("[-] View error:", str(e))
