from adobepass.globals import *
from providers.twc import *
from providers.charter import CHARTER
from providers.comcast import COMCAST
from providers.dish import DISH
from providers.direct_tv import DIRECT_TV
from providers.twc import TWC
from providers.verizon import VERIZON
from providers.cable_one import CABLE_ONE
from providers.optimum import OPTIMUM



class Adobe(): 

    def __init__(self,requestor,provider,username,password,signed_requestor_id,resource_id):
        self.REQUESTOR = requestor
        self.PROVIDER = provider
        self.USERNAME = username
        self.PASSWORD = password
        self.SIGNED_REQ_ID = signed_requestor_id        
        self.SAML_REQUEST_URL = 'https://sp.auth.adobe.com/adobe-services/1.0/authenticate/saml?domain_name=adobe.com&noflash=true&mso_id='+provider+'&requestor_id='+requestor+'&no_iframe=true&client_type=iOS&client_version=1.9&redirect_url=http://adobepass.ios.app/ '
        self.RESOURCE_ID = resource_id

        self.CREATE_PROVIDER_FILE()
        #Set global variables so the providers files can read them        

        print requestor
        print provider
        print username
        print password



    def CREATE_PROVIDER_FILE(self):
        #Create a file for storing Provider info
        fname = os.path.join(ADDON_PATH_PROFILE, 'provider.info')
        if os.path.isfile(fname):    
            provider_file = open(fname,'r')
            last_provider = provider_file.readline()
            provider_file.close()
            if self.PROVIDER != last_provider:
                CLEAR_SAVED_DATA()

        provider_file = open(fname,'w')   
        provider_file.write(self.PROVIDER)
        provider_file.close()



    def LOGIN(self):       
        expired_cookies = True
        try:
            cj = cookielib.LWPCookieJar()
            cj.load(os.path.join(ADDON_PATH_PROFILE, 'cookies.lwp'),ignore_discard=True)
            
            for cookie in cj:                
                if cookie.name == 'BIGipServerAdobe_Pass_Prod':
                    print cookie.name
                    print cookie.expires
                    print cookie.is_expired()
                    expired_cookies = cookie.is_expired()
        except:
            pass
        
        last_provider = ''
        fname = os.path.join(ADDON_PATH_PROFILE, 'provider.info')
        if os.path.isfile(fname):                
            provider_file = open(fname,'r') 
            last_provider = provider_file.readline()
            provider_file.close()

        auth_token = ''
        auth_token_file = os.path.join(ADDON_PATH_PROFILE, 'auth.token')  
        if os.path.isfile(auth_token_file):
            in_file = open(auth_token_file,'r')
            auth_token = in_file.readline()
            in_file.close()

        print "Did cookies expire? " + str(expired_cookies)
        print "Does the auth token file exist? " + str(os.path.isfile(auth_token_file))
        print "Does the last provider match the current provider? " + str(last_provider == self.PROVIDER)
        print "Who was the last provider? " +str(last_provider)

        if expired_cookies or auth_token.isspace() or (last_provider != self.PROVIDER):
            #var_1, var_2, var_3 = self.GET_SAML_REQUEST()

            if self.PROVIDER == 'TWC':
                provider = TWC()

            var_1, var_2, var_3 = provider.GET_IDP(self.SAML_REQUEST_URL)
            saml_response, relay_state = provider.LOGIN(var_1, var_2, var_3, self.USERNAME, self.PASSWORD)

            self.POST_SAML_ASSERTION_CONSUMER(saml_response,relay_state)
            self.POST_SESSION_DEVICE(self.SIGNED_REQ_ID,self.REQUESTOR) 

        authz = self.POST_AUTHORIZE_DEVICE(self.RESOURCE_ID,self.SIGNED_REQ_ID,self.REQUESTOR)  
        print authz      
        media_token = ''

        if 'Authorization failed' in authz or authz == '':
            msg = "Failed to authorize"
            dialog = xbmcgui.Dialog() 
            ok = dialog.ok('Authorization Failed', msg)
        else:
            media_token = self.POST_SHORT_AUTHORIZED(self.SIGNED_REQ_ID,authz,self.REQUESTOR)

            #stream_url = adobe.TV_SIGN(media_token,resource_id, stream_url)
            
        return urllib.quote(media_token)

        

    def GET_SAML_REQUEST(self):        
        if not os.path.exists(ADDON_PATH_PROFILE):
            os.makedirs(ADDON_PATH_PROFILE)
        
        cj = cookielib.LWPCookieJar(os.path.join(ADDON_PATH_PROFILE, 'cookies.lwp'))
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))    
        opener.addheaders = [ ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                            ("Accept-Language", "en-us"),
                            ("Proxy-Connection", "keep-alive"),
                            ("Connection", "keep-alive"),
                            ("User-Agent", UA_IPHONE)]
        
        resp = opener.open(self.SAML_REQUEST_URL)
        idp_source = resp.read()
        resp.close()
        #print idp_source
        #cj.save(ignore_discard=True);                
        SAVE_COOKIE(cj)

        idp_source = idp_source.replace('\n',"")        

        saml_request = FIND(idp_source,'<input type="hidden" name="SAMLRequest" value="','"')
        relay_state = FIND(idp_source,'<input type="hidden" name="RelayState" value="','"')
        saml_submit_url = FIND(idp_source,'action="','"')

        print saml_request
        print relay_state
        print saml_submit_url

        return saml_request, relay_state, saml_submit_url

    

    def POST_SAML_ASSERTION_CONSUMER(self,saml_response,relay_state):
        ###################################################################
        # SAML Assertion Consumer
        ###################################################################        
        url = 'https://sp.auth.adobe.com/sp/saml/SAMLAssertionConsumer'
        
        cj = cookielib.LWPCookieJar()
        cj.load(os.path.join(ADDON_PATH_PROFILE, 'cookies.lwp'),ignore_discard=True)

        cookies = ''
        for cookie in cj:
            #Possibly two JSESSION cookies being passed, may need to fix
            if (cookie.name == "BIGipServerAdobe_Pass_Prod" or cookie.name == "client_type" or cookie.name == "client_version" or cookie.name == "JSESSIONID" or cookie.name == "redirect_url") and cookie.path == "/":
                cookies = cookies + cookie.name + "=" + cookie.value + "; "
        

        http = httplib2.Http()
        http.disable_ssl_certificate_validation=True    
        headers = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                            "Accept-Encoding": "gzip, deflate",
                            "Accept-Language": "en-us",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Proxy-Connection": "keep-alive",
                            "Connection": "keep-alive",
                            "Origin": ORIGIN,
                            "Referer": REFERER,
                            "Cookie": cookies,
                            "User-Agent": UA_IPHONE}


        body = urllib.urlencode({'SAMLResponse' : saml_response,
                                 'RelayState' : relay_state
                                 })

        
        response, content = http.request(url, 'POST', headers=headers, body=body)        
        print 'POST_ASSERTION_CONSUMER_SERVICE------------------------------------------------'
        print headers
        print body
        print response
        print content
        print '-------------------------------------------------------------------------------'
        
    

    def POST_SESSION_DEVICE(self,signed_requestor_id,requestor_id):
        ###################################################################
        # Create a Session for Device
        ###################################################################                
        cj = cookielib.LWPCookieJar()
        cj.load(os.path.join(ADDON_PATH_PROFILE, 'cookies.lwp'),ignore_discard=True)
        
        cookies = ''
        for cookie in cj:
            #Possibly two JSESSION cookies being passed, may need to fix
            #if cookie.name == "BIGipServerAdobe_Pass_Prod" or cookie.name == "client_type" or cookie.name == "client_version" or cookie.name == "JSESSIONID" or cookie.name == "redirect_url":
            if (cookie.name == "BIGipServerAdobe_Pass_Prod" or cookie.name == "client_type" or cookie.name == "client_version" or cookie.name == "JSESSIONID" or cookie.name == "redirect_url") and cookie.path == "/":
                cookies = cookies + cookie.name + "=" + cookie.value + "; "

        
        url = 'https://sp.auth.adobe.com//adobe-services/1.0/sessionDevice'
        http = httplib2.Http()
        http.disable_ssl_certificate_validation=True    
        headers = { "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-us",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Proxy-Connection": "keep-alive",
                    "Connection": "keep-alive",                                                
                    "Cookie": cookies,
                    "User-Agent": UA_ADOBE_PASS}

        data = urllib.urlencode({'requestor_id' : requestor_id,
                                 '_method' : 'GET',
                                 'signed_requestor_id' : signed_requestor_id,
                                 'device_id' : DEVICE_ID
                                })
        
       
        response, content = http.request(url, 'POST', headers=headers, body=data)
        print 'POST_SESSION_DEVICE------------------------------------------------------------'
        print headers
        print data
        print response
        print content
        print '-------------------------------------------------------------------------------'
        
        auth_token = FIND(content,'<authnToken>','</authnToken>')
        print "AUTH TOKEN"        
        print auth_token
        auth_token = auth_token.replace("&lt;", "<")
        auth_token = auth_token.replace("&gt;", ">")
        # this has to be last:
        auth_token = auth_token.replace("&amp;", "&")
        print auth_token

        #Save auth token to file for         
        fname = os.path.join(ADDON_PATH_PROFILE, 'auth.token')
        #if not os.path.isfile(fname):            
        device_file = open(fname,'w')   
        device_file.write(auth_token)
        device_file.close()

        #return auth_token, session_guid        
   

    def POST_AUTHORIZE_DEVICE(self,resource_id,signed_requestor_id,requestor_id):
        ###################################################################
        # Authorize Device
        ###################################################################
        fname = os.path.join(ADDON_PATH_PROFILE, 'auth.token')
        device_file = open(fname,'r') 
        auth_token = device_file.readline()
        device_file.close()
        
        if auth_token == '':
            return ''

        url = 'https://sp.auth.adobe.com//adobe-services/1.0/authorizeDevice'
        http = httplib2.Http()
        http.disable_ssl_certificate_validation=True    
        headers = {"Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Accept-Language": "en-us",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Proxy-Connection": "keep-alive",
                    "Connection": "keep-alive",                                                                
                    "User-Agent": UA_ADOBE_PASS}

        data = urllib.urlencode({'requestor_id' : requestor_id,
                                 'resource_id' : resource_id,
                                 'signed_requestor_id' : signed_requestor_id,
                                 'mso_id' : self.PROVIDER,
                                 'authentication_token' : auth_token,
                                 'device_id' : DEVICE_ID,
                                 'userMeta' : '1'                             
                                })
        
        print data
        response, content = http.request(url, 'POST', headers=headers, body=data)
        
        print content        
        print response

        try:
            print "REFRESHED COOKIE"
            adobe_pass = response['set-cookie']
            print adobe_pass
            cj = cookielib.LWPCookieJar(os.path.join(ADDON_PATH_PROFILE, 'cookies.lwp'))
            cj.load(os.path.join(ADDON_PATH_PROFILE, 'cookies.lwp'),ignore_discard=True)
            #BIGipServerAdobe_Pass_Prod=526669578.20480.0000; expires=Fri, 19-Jun-2015 19:58:42 GMT; path=/
            value = FIND(adobe_pass,'BIGipServerAdobe_Pass_Prod=',';')
            expires = FIND(adobe_pass,'expires=',' GMT;')
            #date_time = '29.08.2011 11:05:02'        
            #pattern = '%d.%m.%Y %H:%M:%S'
            #Fri, 19-Jun-2015 19:58:42
            pattern = '%a, %d-%b-%Y %H:%M:%S'
            print expires
            expires_epoch = int(time.mktime(time.strptime(expires, pattern)))
            print expires_epoch
            ck = cookielib.Cookie(version=0, name='BIGipServerAdobe_Pass_Prod', value=value, port=None, port_specified=False, domain='sp.auth.adobe.com', domain_specified=True, domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=expires_epoch, discard=True, comment=None, comment_url=None, rest={'HttpOnly': None}, rfc2109=False)
            cj.set_cookie(ck)
            #cj.save(os.path.join(ADDON_PATH_PROFILE, 'cookies.lwp'),ignore_discard=True);
            SAVE_COOKIE(cj)

        except:
            pass
        authz = FIND(content,'<authzToken>','</authzToken>')                
        authz = authz.replace("&lt;", "<")
        authz = authz.replace("&gt;", ">")
        # this has to be last:
        authz = authz.replace("&amp;", "&")
        print "AUTH Z TOKEN"
        print authz
        
        return authz


    def POST_SHORT_AUTHORIZED(self,signed_requestor_id,authz,requestor_id):
        ###################################################################
        # Short Authorize Device
        ###################################################################
        fname = os.path.join(ADDON_PATH_PROFILE, 'auth.token')
        device_file = open(fname,'r') 
        auth_token = device_file.readline()
        device_file.close()

        session_guid = FIND(auth_token,'<simpleTokenAuthenticationGuid>','</simpleTokenAuthenticationGuid>')
        print "SESSION GUID"
        print session_guid    

        url = 'https://sp.auth.adobe.com//adobe-services/1.0/deviceShortAuthorize'
        cj = cookielib.LWPCookieJar()
        cj.load(os.path.join(ADDON_PATH_PROFILE, 'cookies.lwp'),ignore_discard=True)
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        opener.addheaders = [ ("Accept", "*/*"),
                            ("Accept-Encoding", "gzip, deflate"),
                            ("Accept-Language", "en-us"),
                            ("Content-Type", "application/x-www-form-urlencoded"),
                            ("Proxy-Connection", "keep-alive"),
                            ("Connection", "keep-alive"),                                                                            
                            ("User-Agent", UA_ADOBE_PASS)]
        

        data = urllib.urlencode({'requestor_id' : requestor_id,                             
                                 'signed_requestor_id' : signed_requestor_id,
                                 'mso_id' : self.PROVIDER,
                                 'session_guid' : session_guid,
                                 'hashed_guid' : 'false',
                                 'authz_token' : authz,
                                 'device_id' : DEVICE_ID
                                })

        resp = opener.open(url, data)
        media_token = resp.read()
        resp.close()    
        print "media token = " + media_token

        return media_token

    def TV_SIGN(self, media_token, resource_id, stream_url):    
        cj = cookielib.LWPCookieJar()
        cj.load(os.path.join(ADDON_PATH_PROFILE, 'cookies.lwp'),ignore_discard=True)
        #print cj
        cookies = ''
        for cookie in cj:        
            if cookie.name == "BIGipServerAdobe_Pass_Prod" or cookie.name == "JSESSIONID":
                cookies = cookies + cookie.name + "=" + cookie.value + "; "

        url = 'http://sp.auth.adobe.com//tvs/v1/sign'
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        opener.addheaders = [ ("Accept", "*/*"),
                            ("Accept-Encoding", "gzip, deflate"),
                            ("Accept-Language", "en;q=1"),
                            ("Content-Type", "application/x-www-form-urlencoded"),                                                                                         
                            ("Cookie", cookies),
                            ("User-Agent", "NBCSports/4.2.0 (iPhone; iOS 8.3; Scale/2.00)")]
        

        data = urllib.urlencode({'cdn' : 'akamai',
                                 'mediaToken' : base64.b64encode(media_token),
                                 'resource' : base64.b64encode(resource_id),
                                 'url' : stream_url
                                })

        resp = opener.open(url, data)
        url = resp.read()
        resp.close()    
        print url

        ################################
        # Get Cookie from manifest file
        ################################
        #stream_cookie = ''
        #try:
        #req = urllib2.Request(url)  
        #req.add_header('User-Agent',  'AppleCoreMedia/1.0.0.12F70 (iPhone; U; CPU OS 8_3 like Mac OS X; en_us)')
        #response = urllib2.urlopen(req)        
        #stream_cookie = response.info()['Set-Cookie']
        #response.close() 
        #except:
        #pass

        #print stream_cookie

        #Set quality level based on user settings
        url = SET_STREAM_QUALITY(url)            

        url = url+"|User-Agent="+UA_NBCSN
        #if stream_cookie != '':
        #url = url + "&Cookie="+stream_cookie

        print url
        #addLink(stream_name,url,stream_name,stream_icon,FANART) 
        return url
        