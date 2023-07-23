from burp import IBurpExtender
from burp import IHttpListener, IProxyListener
from burp import ITab
from burp import IRequestInfo
from java.io import PrintWriter
from javax.swing import JPanel, JCheckBox, JLabel, JTextField, BoxLayout, Box, BorderFactory
from java.awt import GridLayout, Dimension
from java.awt.event import FocusAdapter
import re

# WAF Bypadd
# Burp extension to bypass WAFs by padding requests with a dummy field.
# Author: Julian J. M.
# Email: julianjm@gmail.com
# Twitter: @julianjm512
# Github: https://github.com/julianjm


class BurpExtender(IBurpExtender, IHttpListener, ITab, IProxyListener):

    # constructor
    def __init__(self):
        self.intercept_proxy = False
        self.intercept_scanner = False
        self.intercept_repeater = False
        self.padding_size = 8192

        self.NAME = "WAF Bypadd"
        self.AUTHOR = "Julian J. M."
        self.EMAIL = "julianjm@gmail.com"
        self.TWITTER = "@julianjm512"
        self.GITHUB = "https://github.com/julianjm"
        self.VERSION = "0.9"
        return

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)

        callbacks.setExtensionName(self.NAME)
        callbacks.registerHttpListener(self)
        callbacks.registerProxyListener(self)

        self.setupGUI()

        return

    def setupGUI(self):
        self.panel = JPanel()
        self.panel.setLayout(BoxLayout(self.panel, BoxLayout.Y_AXIS))
        self.panel.setBorder(BorderFactory.createEmptyBorder(
            10, 10, 10, 10))  # Add padding

        # Extension info
        infoPanel = JPanel(GridLayout(0, 1))
        # Set maximum width and height
        infoPanel.setMaximumSize(Dimension(500, 120))
        infoPanel.setBorder(BorderFactory.createTitledBorder("About"))
        infoPanel.add(JLabel(self.NAME + ' v' + self.VERSION))
        infoPanel.add(JLabel("Author: " + self.AUTHOR))
        infoPanel.add(JLabel("Email: " + self.EMAIL))
        infoPanel.add(JLabel("Twitter: " + self.TWITTER))
        infoPanel.add(JLabel("Github: " + self.GITHUB))

        # Configuration options
        configPanel = JPanel(GridLayout(0, 1))
        # Set maximum width and height
        configPanel.setMaximumSize(Dimension(500, 120))
        configPanel.setBorder(
            BorderFactory.createTitledBorder("Configuration"))
        self.proxy_check = JCheckBox(
            "Intercept Proxy Requests", actionPerformed=self.toggle_proxy)
        self.scanner_check = JCheckBox(
            "Intercept Scanner Requests", actionPerformed=self.toggle_scanner)
        self.repeater_check = JCheckBox(
            "Intercept Repeater Requests", actionPerformed=self.toggle_repeater)
        self.padding_size_label = JLabel("Padding Size:")
        self.padding_size_textfield = JTextField(
            str(self.padding_size), 6)  # Default padding size is 8192

        configPanel.add(self.proxy_check)
        configPanel.add(self.scanner_check)
        configPanel.add(self.repeater_check)
        configPanel.add(self.padding_size_label)
        configPanel.add(self.padding_size_textfield)

        # Add FocusListener to the textfield
        self.padding_size_textfield.addFocusListener(
            self.TextFieldFocusListener(self))

        # Add info and config panels to main panel
        self.panel.add(configPanel)
        self.panel.add(Box.createRigidArea(Dimension(0, 10)))
        self.panel.add(infoPanel)

        self._callbacks.customizeUiComponent(self.panel)
        self._callbacks.addSuiteTab(self)

        return

    class TextFieldFocusListener(FocusAdapter):
        def __init__(self, extender):
            self.extender = extender

        def focusLost(self, e):
            try:
                padding_size = int(e.getSource().getText())
                self.extender.set_padding_size(padding_size)
                print("Padding size updated to " + str(padding_size))
            except ValueError:
                print("Invalid padding size!")

    def set_padding_size(self, padding_size):
        self.padding_size = padding_size

    def getTabCaption(self):
        return self.NAME

    def getUiComponent(self):
        return self.panel

    def toggle_proxy(self, event):
        self.intercept_proxy = self.proxy_check.isSelected()
        print("Intercept proxy: " + str(self.intercept_proxy))

    def toggle_scanner(self, event):
        self.intercept_scanner = self.scanner_check.isSelected()
        print("Intercept scanner: " + str(self.intercept_scanner))

    def toggle_repeater(self, event):
        self.intercept_repeater = self.repeater_check.isSelected()
        print("Intercept repeater: " + str(self.intercept_repeater))

    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            return

        if not self.intercept_proxy:
            return

        try:
            self.handleMessage(message.getMessageInfo())
        except Exception as e:
            self.stderr.println("Error: " + str(e))
            return

    def processHttpMessage(self, toolFlag, messageIsRequest, currentRequest):
        if not messageIsRequest:  # we process only requests
            return

        # Proxy messages are handled by processProxyMessage. We don't want to process them twice.
        # Only check if the tool is Scanner or Repeater
        if toolFlag not in [self._callbacks.TOOL_SCANNER, self._callbacks.TOOL_REPEATER]:
            return
        if (toolFlag == self._callbacks.TOOL_SCANNER) and not self.intercept_scanner:
            return
        if (toolFlag == self._callbacks.TOOL_REPEATER) and not self.intercept_repeater:
            return

        try:
            self.handleMessage(currentRequest)
        except Exception as e:
            self.stderr.println("Error: " + str(e))
            return

    def handleMessage(self, currentRequest):
        # Ignore requests that are not in scope
        if not self._callbacks.isInScope(currentRequest.getUrl()):
            return

        request_info = self._helpers.analyzeRequest(currentRequest)
        if request_info.getMethod() != 'POST':  # process only POST requests
            return

        req = currentRequest.getRequest()
        body_bytes = req[request_info.getBodyOffset():]
        body_bytes = bytes(bytearray(body_bytes))

        content_type = request_info.getContentType()

        if content_type == IRequestInfo.CONTENT_TYPE_URL_ENCODED:
            new_body = b'dummy123=' + \
                (b'A'*self.padding_size) + b'&' + body_bytes
            new_message = self._helpers.buildHttpMessage(
                request_info.getHeaders(), new_body)
            currentRequest.setRequest(new_message)

        elif content_type == IRequestInfo.CONTENT_TYPE_MULTIPART:
            # get the content-type header value
            content_type_header = None
            headers = request_info.getHeaders()
            for header in headers:
                if header.lower().startswith("content-type:"):
                    content_type_header = header
                    break

            if content_type_header is None:
                print("Content-Type header not found!")
                return

            # get the boundary string
            boundary = None
            for param in content_type_header.split(";"):
                param = param.strip()
                if param.lower().startswith("boundary="):
                    boundary = param[9:]
                    break

            if boundary is None:
                print("Boundary not found!")
                return

            new_body = b'--' + boundary + b'\r\n' + b'Content-Disposition: form-data; name="dummy123"' + \
                b'\r\n\r\n' + b'A'*self.padding_size + b'\r\n' + body_bytes
            new_message = self._helpers.buildHttpMessage(
                request_info.getHeaders(), new_body)
            currentRequest.setRequest(new_message)

        elif content_type == IRequestInfo.CONTENT_TYPE_JSON:
            if body_bytes[0] == b'{':
                new_body = b'{"dummy123":"' + \
                    (b'A'*self.padding_size) + b'",' + body_bytes[1:]
                new_message = self._helpers.buildHttpMessage(
                    request_info.getHeaders(), new_body)
                currentRequest.setRequest(new_message)

        elif content_type == IRequestInfo.CONTENT_TYPE_XML:
            m = re.match(b'^(\\s*<\\?xml[^>]*\\?>)', body_bytes)
            xml_prolog = b''
            if m is not None:
                body_bytes = body_bytes[m.end():]
                xml_prolog = m.group(1)

            new_body = xml_prolog + b'<!-- ' + \
                (b'A'*self.padding_size) + b' -->' + body_bytes

            new_message = self._helpers.buildHttpMessage(
                request_info.getHeaders(), new_body)
            currentRequest.setRequest(new_message)

        # End of handleMessage
        return
