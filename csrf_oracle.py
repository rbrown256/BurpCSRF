from burp import IBurpExtender
from burp import IHttpListener
from burp import IParameter
from java.net import URL

import re
import urlparse
import ssl

# Find reg ex: <meta name="csrf-token" content=".*?" />
# Replaec reg ex: authenticity_token= POST param

csrfregex = re.compile(r'<meta name=\"csrf-token\" content=\"(.*?)\" />')
 
class BurpExtender(IBurpExtender, IHttpListener, IParameter):
    # Variable to hold the token found so that it can be inserted in the next request
    discoveredToken = ''

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RobB CSRF")
        callbacks.registerHttpListener(self)
        print "Extension registered successfully."
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
        # Operate on all tools other than the proxy
        if toolFlag != self._callbacks.TOOL_PROXY and toolFlag != self._callbacks.TOOL_EXTENDER:
            if messageIsRequest:
                self.processRequest(currentMessage)

    def getToken(self):
        print "Gonna get response from token endpoint"
        responseBody = self.connect_to_untrusted_host("example.com", "/account/edit")

        print len(responseBody)

        token = csrfregex.search(responseBody)
        if token is None:
            print "No token found in response."
        else:
            BurpExtender.discoveredToken = token.group(1)
            print "Found a token."

    def processRequest(self, currentMessage):
        print "Gonna get token"
        self.getToken()
        request = currentMessage.getRequest()

        if BurpExtender.discoveredToken != '':
            currentMessage.setRequest(self._helpers.updateParameter(request, self._helpers.buildParameter("authenticity_token", self._helpers.urlEncode(BurpExtender.discoveredToken), self.PARAM_BODY)))
            print "Replaced the token."
        else:
            print "No token to replace."


    def connect_to_untrusted_host(self, host, page):
    
        print "Gonna connect here"
        print host
        print page
        
        myUrl = URL("https", host, 443, page)
        req = self._helpers.buildHttpRequest(myUrl);
        rawResponse = self._callbacks.makeHttpRequest(host, 443, True, req);
        
        response = self._helpers.analyzeResponse(rawResponse)
        
        print response.getStatusCode()
        
        body = self._helpers.bytesToString(rawResponse[response.getBodyOffset():])
        
        print len(body)
        
        return body
