#!/usr/bin/env python

import sys
import subprocess, ast
from argparse import ArgumentParser
from pprint import pprint

def main():
    '''
    Simple script to delete all the instances of common configuration elements in A10, by 
    using the methods defined in 'method_to_post_data_mapper' dictionary
    '''
	# Argument parsing
    parser = ArgumentParser(description="Script to delete A10's slb configuration ", 
                            prog='python delete_script.py')
    parser.add_argument('a10_ip_address', action='store', help='A10 management IP')
    parser.add_argument('a10_admin_user', action='store', help='A10 admin user',
                        default='admin', nargs='?',) # Optional arg, defaults to 'admin'
    parser.add_argument('a10_admin_pwd', action='store', help='A10 admin user password',
                        default='a10', nargs='?',)   # Optional arg, defaults to 'a10'                
    parsed_args = parser.parse_args()

    ip_address = parsed_args.a10_ip_address
    username = parsed_args.a10_admin_user
    password = parsed_args.a10_admin_pwd

    method_to_post_data_mapper = {
                             'slb.virtual_server.deleteAll'               : '', 
                             'slb.service_group.deleteAll'                : '',
                             'slb.server.deleteAll'                       : '',
                             'slb.template.vip.deleteAll'                 : '',
                             #'nat.pool.delete'                            : '{"name":"Snat_Pool_ServerSide"}',
                             'slb.template.src_ip_persistence.deleteAll'  : '',
                             'slb.template.ssl_sid_persistence.deleteAll' : '',
                             'slb.template.cookie_persistence.deleteAll'  : '',
                            } 

    url = "https://" + ip_address + ("/services/rest/V2.1/?method=authenticate&"
          "format=json&username=") + username + "&password=" + password
    (stdout, stderr) = subprocess.Popen(['curl2', '-v', '-k', '--tlsv1.0', url], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    session_id = ast.literal_eval(stdout)['session_id']

    for method, post_data in method_to_post_data_mapper.items():
        url = "https://192.168.144.35/services/rest/V2.1/?session_id=" + session_id + "&format=json&method=%s" % method
        (stdout, stderr) = subprocess.Popen(['curl2', '-v', '-k', '--tlsv1.0', '-H', "Content-Type: application/json", '-X', 'POST', '-d', post_data, url], stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()

        print
        print "###  Result to method {}  ###".format(method)
        pprint(ast.literal_eval(stdout))
        print

if __name__ == '__main__':
	main()