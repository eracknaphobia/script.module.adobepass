import os, sys
import uuid, hmac, hashlib, base64, time
import xbmc, xbmcgui, xbmcaddon
import cookielib, urllib, urllib2, json
from urllib2 import URLError, HTTPError


class ADOBE():    
    api_url = 'http://api.auth.adobe.com'
    base_url = 'http://sp.auth.adobe.com'
    activate_url = ''
    requestor_id = ''
    public_key = ''
    private_key = ''    
    device_id = ''
    regcode = ''    
    reg_body = ''
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.81 Safari/537.36'


    def __init__(self, service_vars):        
        self.requestor_id = service_vars['requestor_id']
        self.public_key = service_vars['public_key']
        self.private_key = service_vars['private_key']
        self.activate_url = service_vars['activate_url']        
        try:
            self.reg_body = service_vars['reg_body']
        except:
            pass
        self.device_id = self.getDeviceID()        


    def getDeviceID(self):
        addon_profile_path = xbmc.translatePath(xbmcaddon.Addon().getAddonInfo('profile'))
        fname = os.path.join(addon_profile_path, 'device.id')
        if not os.path.isfile(fname):
            if not os.path.exists(addon_profile_path):
                os.makedirs(addon_profile_path)         
            new_device_id =str(uuid.uuid1())
            device_file = open(fname,'w')   
            device_file.write(new_device_id)
            device_file.close()

        fname = os.path.join(addon_profile_path, 'device.id')
        device_file = open(fname,'r') 
        device_id = device_file.readline()
        device_file.close()
        
        return device_id


    def createAuthorization(self, request_method, request_uri):
        nonce = str(uuid.uuid4())
        epochtime = str(int(time.time() * 1000))        
        authorization = request_method + " requestor_id="+self.requestor_id+", nonce="+nonce+", signature_method=HMAC-SHA1, request_time="+epochtime+", request_uri="+request_uri
        signature = hmac.new(self.private_key , authorization, hashlib.sha1)
        signature = base64.b64encode(signature.digest())
        authorization += ", public_key="+self.public_key+", signature="+signature

        return authorization


    def registerDevice(self):         
        reggie_url = '/reggie/v1/'+self.requestor_id+'/regcode'
        authorization = self.createAuthorization('POST',reggie_url)       
        url = self.api_url+reggie_url
        headers = [ ("Accept", "*/*"),
                    ("Content-type", "application/x-www-form-urlencoded"),
                    ("Authorization", authorization),
                    ("Accept-Language", "en-US"),
                    ("Accept-Encoding", "gzip, deflate"),
                    ("User-Agent", self.user_agent),
                    ("Connection", "Keep-Alive"),                    
                    ("Pragma", "no-cache")
                    ]
        
       
        body += 'registrationURL='+self.base_url+'/adobe-services'
        body += '&ttl=2700'
        body += '&deviceId='+self.device_id
        body += '&format=json'
        
        
        json_source = self.requestJSON(url, headers, body)
       
        
        msg = '1. Go to [B][COLOR yellow]'+self.activate_url+'[/COLOR][/B][CR]'        
        msg += '2. Select any platform, it does not matter[CR]'
        msg += '3. Enter [B][COLOR yellow]'+json_source['code']+'[/COLOR][/B] as your activation code'        
        self.regcode = json_source['code']
        dialog = xbmcgui.Dialog()         
        ok = dialog.ok('Activate Device', msg)        

        

    def authorizeDevice(self, resource_id):        
        auth_url = '/api/v1/authorize'
        authorization = self.createAuthorization('GET',auth_url)
        url = self.api_url+auth_url
        url += '?deviceId='+self.device_id
        url += '&requestor='+self.requestor_id
        url += '&resource='+urllib.quote(resource_id)

        url += '&format=json'
        #req = urllib2.Request(url)

        headers = [ ("Accept", "*/*"),
                    ("Content-type", "application/x-www-form-urlencoded"),
                    ("Authorization", authorization),
                    ("Accept-Language", "en-US"),
                    ("Accept-Encoding", "deflate"),
                    ("User-Agent", self.user_agent),
                    ("Connection", "Keep-Alive"),                    
                    ("Pragma", "no-cache")
                    ]

        json_source = self.requestJSON(url, headers)
        mvpd = json_source['mvpd']

        return mvpd
        

    def deauthorizeDevice(self):        
        auth_url = '/api/v1/logout'
        authorization = self.createAuthorization('DELETE',auth_url)
        url = self.api_url+auth_url
        url += '?deviceId='+self.device_id
        url += '&requestor='+self.requestor_id
        url += '&format=json'
        #req = urllib2.Request(url)

        headers = [ ("Accept", "*/*"),
                    ("Content-type", "application/x-www-form-urlencoded"),
                    ("Authorization", authorization),
                    ("Accept-Language", "en-US"),
                    ("Accept-Encoding", "deflate"),
                    ("User-Agent", self.user_agent),
                    ("Connection", "Keep-Alive"),                    
                    ("Pragma", "no-cache")
                    ]

        try: json_source = self.requestJSON(url, headers, None, 'DELETE')
        except: pass
     

    def mediaToken(self, resource_id):
        url = 'http://api.auth.adobe.com/api/v1/tokens/media'
        url += '?deviceId='+self.device_id
        url += '&requestor='+self.requestor_id        
        url += '&resource='+urllib.quote(resource_id)
        url += '&format=json'
        authorization = self.createAuthorization('GET','/api/v1/tokens/media')
        headers = [ ("Accept", "*/*"),
                    ("Content-type", "application/x-www-form-urlencoded"),
                    ("Authorization", authorization),
                    ("Accept-Language", "en-US"),
                    ("Accept-Encoding", "deflate"),
                    ("User-Agent", self.user_agent),
                    ("Connection", "Keep-Alive"),                    
                    ("Pragma", "no-cache")
                    ]

        json_source = self.requestJSON(url, headers)

        return json_source['serializedToken']


    def authInfo(self):
        '''
        GET https://api.auth.adobe.com/api/v1/tokens/authn?deviceId=24E98C2A-393D-4421-9DC2-543953B60E9D&requestor=fx&deviceType=iPhone&format=json HTTP/1.1
        Host: api.auth.adobe.com
        Content-Type: application/x-www-form-urlencoded
        Connection: keep-alive
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
        User-Agent: FXNOW/1135 CFNetwork/808.3 Darwin/16.3.0
        Authorization: GET requestor_id=fx, nonce=9C2AB756-6302-48D3-B287-5A9D648370E6, signature_method=HMAC-SHA1, request_time=1489946938411, request_uri=/api/v1/tokens/authn, public_key=vE9GzmKVRAVFROPCqKeozoGdlQQMuYpb, signature=D5ouI1q5QSBkZa8mqyWa3HXOS2w=
        Accept-Language: en-us
        Accept-Encoding: gzip, deflate

        '''
        url = 'http://api.auth.adobe.com/api/v1/tokens/authn'
        url += '?deviceId='+self.device_id
        url += '&requestor='+self.requestor_id        
        url += '&resource='+urllib.quote(resource_id)
        url += '&format=json'
        authorization = self.createAuthorization('GET','/api/v1/tokens/authn')
        headers = [ ("Accept", "*/*"),
                    ("Content-type", "application/x-www-form-urlencoded"),
                    ("Authorization", authorization),
                    ("Accept-Language", "en-US"),
                    ("Accept-Encoding", "deflate"),
                    ("User-Agent", self.user_agent),
                    ("Connection", "Keep-Alive"),                    
                    ("Pragma", "no-cache")
                    ]

        json_source = self.requestJSON(url, headers)

        auth_info = ''
        try:
            auth_info = 'Provider: ' + json_source['mvpd'] + ' expires on ' + json_source['expires']
        except:
            pass

        return auth_info


    def requestJSON(self, url, headers, body=None, method=None):      
        addon_profile_path = xbmc.translatePath(xbmcaddon.Addon().getAddonInfo('profile'))  
        cj = cookielib.LWPCookieJar(os.path.join(addon_profile_path, 'cookies.lwp'))
        try: cj.load(os.path.join(addon_profile_path, 'cookies.lwp'),ignore_discard=True)
        except: pass
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))    
        opener.addheaders = headers     
        json_source = ''
          
        try:           
            request = urllib2.Request(url, body)
            if method == 'DELETE': request.get_method = lambda: method            
            response = opener.open(request)
            json_source = json.load(response) 
            response.close()
            self.saveCookie(cj)
        except HTTPError as e:            
            if e.code == 403:
                msg = 'Your device is not authorized to view the selected stream.\n Would you like to authorize this device now?'
                dialog = xbmcgui.Dialog() 
                answer = dialog.yesno('Account Not Authorized', msg)                 
                if answer:
                    self.registerDevice()
                else:
                    sys.exit(0)
            else:
                sys.exit(0)

        return json_source


    def saveCookie(self, cj):
        # Cookielib patch for Year 2038 problem
        # Possibly wrap this in if to check if device is using a 32bit OS
        for cookie in cj:
            # Jan, 1 2038
            if cookie.expires >= 2145916800:
                #Jan, 1 2037
                cookie.expires =  2114380800
        
        cj.save(ignore_discard=True)  