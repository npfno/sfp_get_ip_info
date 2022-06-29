# -*- coding: utf-8 -*-
# -------------------------------------------------------------------------------
# Name:         sfp_get_dns
# Purpose:      SpiderFoot plug-in for getting info from domain or ip addresses.
#
# Author:      Adrián Piquer Forcada  <adrianpiquer@gmail.com>
# Author:      Daniel García Baameiro <dagaba13@gmail.com>
#
# Created:     28/06/2022
# Copyright:   (c) Adrián Piquer Forcada 2022
# Licence:     GPL
# -------------------------------------------------------------------------------


from spiderfoot import SpiderFootEvent, SpiderFootPlugin
import json
import requests
import socket
import validators

class sfp_get_ip_info(SpiderFootPlugin):

    meta = {
        'name': "Get Ip Info",
        'summary': "Devuelve información sobre la IP o el dominio recibido>",
        'flags': [""],
        'useCases': [""],
        'categories': ["Passive IP_ADDRESS"]
    }

    # Default options
    opts = {
    }

    # Option descriptions
    optdescs = {
    }

    results = None

    def setup(self, sfc, userOpts=dict()):
        self.sf = sfc
        self.results = self.tempStorage()

        for opt in list(userOpts.keys()):
            self.opts[opt] = userOpts[opt]
    #++APF Función que devuelve si es IP o no        
    def isIP(self, eventData)
        try:
            if validators.ipv4(eventData):
                return True
        except ValidationFailure:
            return False
    ##--APF
    ##++APF Función que devuelve si es dominio o no
    def isDomain(eventData):
        try:
            if validators.domain(eventData):
                return True
        except ValidationFailure:
            return False
    ##--APF
    ##++APF Función que devuelve la IP de un dominio    
     def getIPfromDomain(domain):    
        valueAux = socket.gethostbyaddr(eventData)[2]
            return valueAux[0]
    ##--APF
    
    # What events is this module interested in for input
    def watchedEvents(self):
        return ["DOMAIN_NAME", "IP_ADDRESS"]

    # What events this module produces
    # This is to support the end user in selecting modules based on events
    # produced.
    def producedEvents(self):
        return ["IP_ADDRESS","PROVIDER_HOSTING","COUNTRY_NAME","GEOINFO","DOMAIN_NAME"]

    # Handle events sent to this module
    def handleEvent(self, event):
        eventName = event.eventType
        srcModuleName = event.module
        eventData = event.data

        if eventData in self.results:
            return

        self.results[eventData] = True

        self.sf.debug(f"Received event, {eventName}, from {srcModuleName}")

        try:
            data = None

            self.sf.debug(f"We use the data: {eventData}")
            print(f"We use the data: {eventData}")

            #++APF: código para obtener la IP, verificando si es IP o dominio    
            ip = ''
            if eventName in ['IP_ADDRESS']:
                ip = eventData
            elif eventName in ['IP_ADDRESS']
                if isIP(self, eventData):
                    ip = getIPfromDomain(eventData)
            else:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
            #Obtenemos la información desde ipinfo.io
            url= "http://ipinfo.io/" + ip + "/json"
            r = requests.get(url)
            r.raise_for_status()
            jsonResponse = r.json()
            #Devolvemos cada dato
            #IP
            data = jsonResponse["ip"]
            typ = ["IP_ADDRESS"]
            evt = SpiderFootEvent(typ, data, self.__name__, event)
            self.notifyListeners(evt)
            #Proveedor de hosting
            data = jsonResponse["org"]
            typ = ["PROVIDER_HOSTING"]
            evt = SpiderFootEvent(typ, data, self.__name__, event)
            self.notifyListeners(evt)
            #País del hosting
            data = jsonResponse["country"]
            typ = ["COUNTRY_NAME"]
            evt = SpiderFootEvent(typ, data, self.__name__, event)
            self.notifyListeners(evt)
            #Geolocalización del hosting
            data = jsonResponse["loc"]
            typ = ["GEOINFO"]
            evt = SpiderFootEvent(typ, data, self.__name__, event)
            self.notifyListeners(evt)
            #Dominio
            data = jsonResponse["hostname"]          
            typ = "DOMAIN_NAME"
            evt = SpiderFootEvent(typ, data, self.__name__, event)
            self.notifyListeners(evt)
            #--APF
            if not data:
                self.sf.error("Unable to perform <ACTION MODULE> on " + eventData)
                return
        except Exception as e:
            self.sf.error("Unable to perform the <ACTION MODULE> on " + eventData + ": " + str(e))
            return
# End of sfp_get_ip_info_class