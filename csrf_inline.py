from burp import IBurpExtender
from burp import IHttpListener
from burp import IParameter
from java.net import URL

import re
import urlparse
import ssl

# Find reg ex: <meta name="csrf-token" content=".*?" />
# Replace reg ex: authenticity_token= POST param

csrfregex = re.compile(r'<input name="__RequestVerificationToken" type="hidden" value="(.*?)" />')
 
class BurpExtender(IBurpExtender, IHttpListener, IParameter):
    # Variable to hold the token found so that it can be inserted in the next request
    discoveredToken = ''

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RobB CSRF Token Inline")
        callbacks.registerHttpListener(self)
        print "Extension registered successfully."
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        if toolFlag != self._callbacks.TOOL_EXTENDER:
            if messageIsRequest:
                self.processRequest(toolFlag, currentMessage)
            else:
                self.getToken(currentMessage)

    def getToken(self, currentMessage):
        print "Gonna get response from body"
        responseBody = currentMessage.getResponse()

        print len(responseBody)

        token = csrfregex.search(responseBody)
        if token is None:
            print "No token found in response."
        else:
            BurpExtender.discoveredToken = token.group(1)
            print "Found a token. Fricken sweet: " + BurpExtender.discoveredToken

    def processRequest(self, toolFlag, currentMessage):
        request = currentMessage.getRequest()

        parsedRequest = self._helpers.analyzeRequest(request)

        if parsedRequest.getMethod() != 'POST':
            return

        if BurpExtender.discoveredToken != '' and toolFlag != self._callbacks.TOOL_PROXY:
            headers = parsedRequest.getHeaders()
            header_name = "__RequestVerificationToken:"
            
            if any(header.startswith(header_name) for header in headers):
                
                print "Header found"
                
                new_headers = []
            
                for i in range(0, len(headers)):
                    if headers[i].startswith(header_name):
                        print "Found header to replace"
                        
                        new_headers.append(header_name + " " + BurpExtender.discoveredToken)
                    else:
                        new_headers.append(headers[i])
                        
                currentMessage.request = self._helpers.buildHttpMessage(new_headers, request[parsedRequest.getBodyOffset():])
                print "Replaced the token."
            else:
                print "No token to replace."
