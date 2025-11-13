# burp_file_replace.py
# Burp extension (Jython / Python 2.7 style)
# Replaces a selected region of the request body with file contents (streamed in chunks).
# Author: (@sanjarbiiy)
# License: MIT

from burp import IBurpExtender, IContextMenuFactory
from javax.swing import JMenuItem, JFileChooser
from java.io import ByteArrayOutputStream
from java.lang import Runtime
import os

CHUNK_SIZE = 1024 * 1024  # 1MB chunks

class BurpExtender(IBurpExtender, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("File Replace Extension")
        callbacks.registerContextMenuFactory(self)
        print "File Replace Extension loaded. Right-click on selection to replace with file content."

    def createMenuItems(self, invocation):
        context = invocation.getInvocationContext()
        # only show for request editor / viewer
        if context in [invocation.CONTEXT_MESSAGE_EDITOR_REQUEST, invocation.CONTEXT_MESSAGE_VIEWER_REQUEST]:
            bounds = invocation.getSelectionBounds()
            if bounds and bounds[0] != bounds[1]:
                menu = []
                item = JMenuItem("Replace Selection with File Content")
                item.actionPerformed = lambda e: self.replaceWithFile(invocation)
                menu.append(item)
                return menu
        return None

    def replaceWithFile(self, invocation):
        chooser = JFileChooser()
        if chooser.showOpenDialog(None) != JFileChooser.APPROVE_OPTION:
            return

        file_path = chooser.getSelectedFile().getAbsolutePath()
        try:
            file_size = os.path.getsize(file_path)
        except Exception, e:
            print "Failed to stat file: %s" % str(e)
            return

        messages = invocation.getSelectedMessages()
        if not messages:
            return

        # memory check
        runtime = Runtime.getRuntime()
        max_mem = runtime.maxMemory()
        free_mem = max_mem - runtime.totalMemory() + runtime.freeMemory()

        for message in messages:
            try:
                request = message.getRequest()
                bounds = invocation.getSelectionBounds()
                if not bounds or bounds[0] == bounds[1]:
                    continue

                analyzed = self.helpers.analyzeRequest(request)
                headers = analyzed.getHeaders()
                body_offset = analyzed.getBodyOffset()

                # ensure selection is inside body
                if bounds[0] < body_offset or bounds[1] > len(request):
                    print "Selection not fully inside body; skipping message."
                    continue

                selection_length = bounds[1] - bounds[0]
                estimated_size = len(request) - selection_length + file_size
                if estimated_size > free_mem * 0.8:
                    print "Warning: Estimated request size (%.2f MB) may exceed available memory (%.2f MB). Skipping." % (estimated_size/(1024.0*1024), free_mem/(1024.0*1024))
                    continue

                # original body bytes
                original_body = request[body_offset:]

                body_start = bounds[0] - body_offset
                body_end = bounds[1] - body_offset

                baos = ByteArrayOutputStream(max(estimated_size, 1024))

                # write part before selection
                if body_start > 0:
                    baos.write(original_body, 0, body_start)

                # stream file into baos
                f = open(file_path, "rb")
                try:
                    while True:
                        chunk = f.read(CHUNK_SIZE)
                        if not chunk:
                            break
                        baos.write(chunk)
                finally:
                    f.close()

                # write remaining body
                if body_end < len(original_body):
                    baos.write(original_body, body_end, len(original_body) - body_end)

                new_body = baos.toByteArray()
                baos.close()

                # rebuild headers without Content-Length
                new_headers = [h for h in headers if not h.lower().startswith("content-length:")]
                new_headers.append("Content-Length: %d" % len(new_body))

                updated_request = self.helpers.buildHttpMessage(new_headers, new_body)
                message.setRequest(updated_request)

                print "Replaced selection with file: %s" % file_path

            except Exception, e:
                print "Error replacing file in message: %s" % str(e)
                if "OutOfMemory" in str(e) or "Java heap" in str(e):
                    print "Out of memory error. Increase Burp's Java heap (-Xmx)."
