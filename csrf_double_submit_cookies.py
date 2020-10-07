from burp import IBurpExtender
from burp import IHttpListener
from burp import IParameter
from java.net import URL

import re
import urlparse
import ssl

# This is for if we have another form field we need to submit as well as the double submit cookie
# Related code can be taken out if not required, although it shouldn't do any harm if the regexp is never found, it'll just slow things down a bit
csrfregex = re.compile(r'<input name="token_login" type="hidden" value="(.*?)">')
 
class BurpExtender(IBurpExtender, IHttpListener, IParameter):
    # Variable to hold the token found so that it can be inserted in the next request
    discoveredToken = ''

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("RobB CSRF Double Submit Cookies")
        callbacks.registerHttpListener(self)
        print "Extension registered successfully."
        return

    def processHttpMessage(self, toolFlag, messageIsRequest, currentMessage):
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
        rawRequest = currentMessage.getRequest()

        request = self._helpers.analyzeRequest(rawRequest)

        params = request.getParameters()

        sParam = next((x for x in params if x.getType() == self.PARAM_BODY and x.getName() == "token_login"), None)

        if sParam is None:
            print "Param not found"
        else:
            print "Param found"
            print "Updating it with value " + BurpExtender.discoveredToken 

            currentMessage.setRequest(self._helpers.updateParameter(rawRequest, self._helpers.buildParameter("token_login", BurpExtender.discoveredToken, self.PARAM_BODY)))

            rawRequest = currentMessage.getRequest()

        sParam = next((x for x in params if x.getType() == self.PARAM_COOKIE and x.getName() == "CSRFP-Token"), None)

        if sParam is None:
            print "Cookie not found in cookie header"
        else:
            print "Cookie found in cookie header"

            cookie = sParam.getValue()

            print "Cookie was set to " + cookie

            sParam = next((x for x in params if x.getType() == self.PARAM_BODY and x.getName() == "CSRFP-Token"), None)

            if sParam is None:
                print "Cookie not found in body"
            else:
                print "Cookie found in body"

                if not cookie is None:

                    currentMessage.setRequest(self._helpers.updateParameter(rawRequest, self._helpers.buildParameter("CSRFP-Token", cookie, self.PARAM_BODY)))

                    print "Cookie set to " + cookie + " in body"
                    
