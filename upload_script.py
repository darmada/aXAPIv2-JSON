#!/usr/bin/env python

import json, urllib2
from argparse import ArgumentParser
import os

FILE_MAP = [
            ('cookie_persistence_map' ,'/json_objects/PERSISTs-COOKIE.txt'),
            ('src_ip_persistence_map' ,'/json_objects/PERSISTs-SRC_IP.txt'),
            ('ssl_id_persistence_map' ,'/json_objects/PERSISTs-SSL_ID.txt'),
            ('real_server_map'        ,'/json_objects/RSs.txt'),
            ('service_group_map'      ,'/json_objects/SGs.txt'),
            ('vip_map'                ,'/json_objects/VIPs.txt'),               
           ]

TEXT_MAP  = {
             'cookie_persistence_template_list' : 'COOKIE PERSISTENCE',
             'src_ip_persistence_template_list' : 'SOURCE IP PERSISTENCE',
             'ssl_sid_persist_template_list'    : 'SSL ID PERSISTENCE',
             'server_list'                      : 'REAL SERVER',
             'service_group_list'               : 'SERVICE GROUP',
             'virtual_server_list'              : 'VIRTUAL SERVER',               
            }

METHOD_MAP = {
              'cookie_persistence_map' : 'slb.template.cookie_persistence.create',
              'src_ip_persistence_map' : 'slb.template.src_ip_persistence.create',
              'ssl_id_persistence_map' : 'slb.template.ssl_sid_persistence.create',  
              'real_server_map'        : 'slb.server.create',
              'service_group_map'      : 'slb.service_group.create',
              'vip_map'                : 'slb.virtual_server.create',               
             }

class A10Device(object):
    '''
    Class to abstract aXAPI session creation and method calling using HTTPs POST Requests
    and Responses.
    '''
    username = ""
    password = ""
    session = ""
    method = ""
    debug = False
    def __init__(self, ip, username, password):
        self.ip= ip
        self.username = username
        self.password = password
        self.session = ""
    def getSession(self):
        post_body = json.dumps(
        {
           "username": self.username,
           "password": self.password
        }
        )        
        url = "http://" + self.ip + "/services/rest/V2.1/?session_id=dummySessionId&format=json&method=authenticate"
        if self.debug: print "Generated URL: " + url + " - Post Body: " + post_body
        req = urllib2.Request(url, post_body)
        rsp = urllib2.urlopen(req)
        content = rsp.read()
        if self.debug: print "Result: " + content
        data = json.loads(content)
        session_id = data['session_id']
        print "Session Created. Session ID: " + session_id
        self.session= session_id
    def closeSession(self):
        if self.debug: print "Closing Session: "+self.session
        post_body = json.dumps(
        {
            "session_id":self.session
        }
        )
        url = "http://" + self.ip + "/services/rest/V2.1/?session_id=" + self.session + "&format=json&method=session.close"
        if self.debug: print "Generated URL: " + url + " - Post Body: " + post_body
        req = urllib2.Request(url, post_body)
        rsp = urllib2.urlopen(req)
        content = rsp.read()
        print "Result: " + content
    def genericPostApi(self,postBody):
        url = "http://"+self.ip+"/services/rest/V2.1/?session_id=" + self.session +"&format=json&method="+self.method
        if self.debug: print "Generated URL: " + url + " - Post Body: " + postBody
        req = urllib2.Request(url, postBody)
        rsp = urllib2.urlopen(req)
        content = rsp.read()
        print (content)
        
def main():
    '''
    Loads all the files existing in FILE_MAP. Then calls the aXAPI methods defined in 
    METHOD_MAP to upload the configuration to the A10 box. This is done by a loop that 
    loads a file (which contains alls the instances of a configuration element) and uses
    the particular aXAPI method to upload all the instances of that element.
    '''
    # Argument parsing
    parser = ArgumentParser(description=("Script to load the alteon processed "
                            "configuration file and upload it to the A10 box"), 
                            prog='python upload_script.py')
    parser.add_argument('a10_ip_address', action='store', help='A10 management IP')
    parser.add_argument('a10_admin_user', action='store', help='A10 admin user',
                        default='admin', nargs='?',) # Optional arg, defaults to 'admin'
    parser.add_argument('a10_admin_pwd', action='store', help='A10 admin user password',
                        default='a10', nargs='?',)   # Optional arg, defaults to 'a10'
    parser.add_argument('-v', '--verbose', action='store_true', help=('increase output '
                        'verbosity showing HTTPs POST Requests/Responses in detail'), 
                        dest= 'verbose')                    
    parsed_args = parser.parse_args()

    ip_address = parsed_args.a10_ip_address
    username = parsed_args.a10_admin_user
    password = parsed_args.a10_admin_pwd
    verbose = parsed_args.verbose
    
    # Get the script directory
    script_dir = os.path.dirname(os.path.realpath(__file__))
    
    thunder = A10Device(ip_address, username, password) # Initialize with IP, username and password
    thunder.debug = verbose                             # Turn ON/OFF debug messages
    thunder.getSession()                                # GET authentication session
    
    for (a_map, file_to_process) in FILE_MAP:
    
    	thunder.method = METHOD_MAP[a_map]              # SET Method
    	
    	with open(script_dir + file_to_process, 'r') as a_file:   
        	a_map = json.load(a_file)
    	a_file.close()
    
    	# All the files are dictionaries with only one key that contains a list of the
    	# elements of a particular type. Value gets the value of the key to use in
    	# the particular dictionary got from the file.
    	value = a_map.keys()[0]
    	
    	for index, a_object in enumerate(a_map[value]):
    		postBody = json.dumps(a_object)   # SET Post Body for the chosen method
    		print "### Uploading {} {} CONFIGURATION ###".format(TEXT_MAP[value], 
    		                                                     str(index+1))
        	thunder.genericPostApi(postBody)            # Call API to execute the method 
        	                                            # with POST body
    
    	print
    
    thunder.closeSession()                          # Close Session
    
    

if __name__ == '__main__':
    main()
    
    