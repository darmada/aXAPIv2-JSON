#!/usr/bin/env python

from argparse import ArgumentParser
import os, sys, re, json
import subprocess, ast
from pprint import pprint

MAX_VIPS = 300
MAX_ALTEON_SGS = 500

PROTOCOL_MAP = {
                'smtp'  : '25',
                'http'  : '80',
                'imap'  : '143',
                'ldap'  : '389',
                'https' : '443',
                'pop3'  : '110',                
               }

CHAR_MAP = {
            '\xc3\x83\xc2\xb1' : 'n',
            '\xc3\x83\xc2\xad' : 'i',
            '->'               : '',
            ','                : '',
           }

HM_MAP = {
		  'smtp'      : 'HM_SMTP',
          'http'      : 'HM_HTTP',
          'imap'      : 'HM_IMAP',
          'ldap'      : 'HM_LDAP',
          'pop3'      : 'HM_POP3',
          '(default)' : '',              
         }

LB_METHOD_MAP = {
                 'roundrobin'            : 0,
                 'least-connection'      : 2,
                 'phash 255.255.255.255' : 14,
                }


def map_protocol_values(lines_in_a_file):
    '''
    Modifies all the occurrences of the string 'service xxxx', where xxxx could be any
    value defined in PROTOCOL_MAP constant dictionary.
    '''
    for index, a_line in enumerate(list(lines_in_a_file)):
        for a_protocol_name, a_protocol_value in PROTOCOL_MAP.items():
            if 'service ' + a_protocol_name in a_line:
                lines_in_a_file[index] = a_line.replace('service ' + a_protocol_name, 
                                                        'service ' + a_protocol_value)    


def find_section(lines_in_a_file, type, item_number, parent_number=''):
    '''
	Identifies and returns a configuration section to allow parsing of that section 
	afterwards.
    '''
    capture = False
    section = ''
    
    # Define all the possible sections we will want to identify
    element_map = {
                   'vip'           : '/c/slb/virt',
                   'service_group' : '/c/slb/group',
                   'real_server'   : '/c/slb/real',
                   'vport'         : '/c/slb/virt ' + parent_number + '/service',
                  }
    
    # String to match in the configuration
    matching_string = "{} {}".format(element_map[type], item_number)
        
    for a_line in lines_in_a_file:
        if not capture:
            if matching_string == a_line or (matching_string + '/') in a_line:
            	capture = True
            	section += a_line + '\n'
        else:
            if matching_string == a_line or (matching_string + '/') in a_line:
                section += a_line + '\n'
            elif ('/c/' in a_line) and (element_map[type] not in a_line):
                capture = False
            elif element_map[type] not in a_line:
                section += a_line + '\n'
            elif a_line == '':
                continue
            else:
                capture = False
    
    # Remove blank lines within the section
    section_lines = section.splitlines()
    while '' in section_lines:
    	section_lines.remove('')
    
    # Return the same original section without the blank lines
    return '\n'.join(section_lines) + '\n'


def find_all_occurrences(lines_in_a_file, type):
    '''
    Finds and returns a list of all the existing elements of a particular type in the 
    alteon configuration
    '''
    # Define all the possible elements we will want to find occurrences
    element_map = {
                   'vip'           : '/c/slb/virt',
                   'service_group' : '/c/slb/group',
                   'real_server'   : '/c/slb/real',
                  }

    element_list = []
    for a_line in lines_in_a_file:
		re_pattern = re.search(element_map[type] + ' (\d+)', a_line)
		try:
		    #  Try to add the element number in the element_list if there was a match
			if not str(re_pattern.group(1)) in element_list:
				element_list.append(re_pattern.group(1))
		except AttributeError:
			continue

    return element_list


def process_config_field(section_string, field):
    '''
    Returns the value of the desired field of the given alteon configuration section.
    Alteon fields are always strings that can start or not with " char, and are followed
    by:
        - letters with or without '.' chars (IP addresses are a example with '.')
        - numbers
    So the string (probably following " at the beggining) is compound of \w or '.' chars
    '''
    re_pattern = re.search(field + ' "*((\w|.)+)', section_string)
    
    # Delete " chars in the processed field before returning it
    return re_pattern.group(1).replace('"', '')
		

def add_vport_occurrences(section_string, vip_number, vport_list):
    '''
    Adds the vports to a particular A10 VIP within the vip_map_list
    '''
    string_to_process = '/c/slb/virt ' + vip_number + '/service'
    
    # Find all the string indexes of vports within a vip. Indexes are returned at the
    # beginning of string_to_process
    pointers = [match.start() for match in re.finditer(string_to_process, section_string)]
    
    for a_pointer in pointers:
    	# Get the vport number
    	a_number = process_config_field(section_string[a_pointer:], string_to_process)
    	
    	# When the protocol name is found, change it to its number value
    	if a_number in PROTOCOL_MAP:
    	    a_number = PROTOCOL_MAP[a_number]
    	elif '/' in a_number:
    		# Remove trailing in lines with something after the match.
    		# Ex: /c/slb/virt 72/service 38081/pbind cookie insert
    	    a_number = a_number.split('/')[0]
    	
        # Check if vport already in vport_list of the particular VIP within vip_map_list
    	exists_in_list = False
    	aux_list = list(vport_list)  
    	for a_item in aux_list:
            if int(a_number) == a_item['port']:
                exists_in_list = True
                break
        
        if not exists_in_list:
            # New vport, adding it
            vport_list.append({'port' : int(a_number)})

    
def find_vip_number(dict_list, vip_address):
    '''
    Finds the VIP index within the A10's VIP_list
    '''
    for index, a_dict in enumerate(dict_list):
    	if a_dict['address'] == vip_address :
            return index


def process_vip_info(vip_map_list, vip_address, vip_number, section):
    '''
    Creates the A10 VIP list adding the vports to A10 VIPs, preserving the relationship
    between Alteon vip_numbers and A10 VIPs and also the section information.
    ''' 
    # Search if the VIP is already in the vip dictionary using a auxiliar list
    aux_list = list(vip_map_list)
    aux_list.append({'address' : 'start'})
       
    vip_in_list = False
    for a_vip in aux_list:
        if vip_address == a_vip['address']:
            vip_in_list = True
            
    # Process the VIP information depending on if it's a new VIP or the same VIP
    # with more vports
    if not vip_in_list:
        # New VIP in vip_map_list
        new_vip_dict = {
                        'address'         : vip_address,
                        'vport_list'      : [],
                        'alteon_vip_list' : [vip_number],
                        'section'         : section,
                        'conn_limit'      : 8000000,
    	                'conn_limit_log'  : 1,
                       }
        # 'alteon_vip_list' is an auxiliar key containing the relationship between the 
        # Alteon vip_numbers and the A10 vips, because many alteon vip_numbers will be 
        # the same VIP in A10, due to 8 vports limitation per VIP in Alteon
        
        # 'section' is an auxiliar key containing the configuration lines of the VIP in 
        # Alteon configuration file
        
            
        if 'dname' in section:
        	# Get VIP name from Alteon configuration
        	dname = process_config_field(section, 'dname')
        	# Split the VIP name in words
        	dname_in_list = dname.split(' ')
        	# Convert to uppercase the first letter of each word of the VIP name
        	parsed_dname = [substring[0].upper() + substring[1:] 
            	            for substring in dname_in_list]
        	# Get a one-word VIP name by joining all the words with '_'
        	new_vip_dict['name'] =  '_'.join(parsed_dname)
        else:
            new_vip_dict['name'] = '_' + str(vip_address) + '_'
            
        # Parse the status of the VIP
        if 'ena' in section.splitlines()[1]:
            new_vip_dict['status'] = 1
        else:
            new_vip_dict['status'] = 0
                    
        # Add the new vip to the master vip dictionary
        vip_map_list.append(new_vip_dict)
            
    else:
        # Existing VIP in vip_map_list
        
        # Locate the A10 VIP index in vip_map_list
        index = find_vip_number(vip_map_list, vip_address)
        # Add the Alteon vip_number to and the configuration section to the A10 VIP 
        # information 
        vip_map_list[index]['alteon_vip_list'].append(vip_number) 	
        vip_map_list[index]['section'] += section
            
    # Regardless of being a new VIP or a new one, vports must be added to it. This is done
    # by locating the the A10 VIP index in vip_map_list and adding the vports.
    index = find_vip_number(vip_map_list, vip_address)
    add_vport_occurrences(section, str(vip_number), vip_map_list[index]['vport_list'])   


def renumber_vip_section(vip_map_list):
    '''
    Renumbers A10's VIP 'section' key content so it will only have 1 vip_number per 
    vip_address in each section (Alteon has many vip_numbers with the same vip_address, 
    because they can't have more than 8 vports per vip_adddress with the same vip_number, 
    so they do it with a new vip_number). The relationship between the Alteon VIP numbers
    and this new assigned number is kept in 'alteon_vip_list' key within each A10 VIP
    '''
    for index, a_vip in enumerate(vip_map_list):
        for alteon_vip_number in a_vip['alteon_vip_list']:
            a_vip['section'] = a_vip['section'].replace('/c/slb/virt ' 
                                                         + str(alteon_vip_number),
    	                                                '/c/slb/virt ' + str(index))

            
def process_vport_info(vport, subsection, original_alteon_sgs_list):
    '''
    Process the vport information from a given particular vport and adds it to the vip_map
    dictionary. Service-group data will be added afterwards in the script, NOT HERE.
    '''     
    # define vport connection limit default values
    vport['connection_limit'] = {
                                 'status':0,
                                 'connection_limit' : 8000000,
                                 'connection_limit_action' : 0,
                                 'connection_limit_log' : 1
                                }
    
    # Process vport type and add persistence templates
    if 'dbind ena' in subsection:
        # 11 denotes a VIP type = http, 2 denotes VIP type = tcp
        if 'pbind cookie insert' in subsection:
            if ' 443\n' in subsection:
    	    	vport['protocol'] = 2
    	    else:
    	        vport['protocol'] = 11
    	        vport['cookie_persistence_template'] = 'Persist_Cookie'
        elif 'pbind cookie passive JSESSIONID' in subsection:
            if ' 443\n' in subsection:
    	    	vport['protocol'] = 2
    	    else:
    	        vport['protocol'] = 11
    	        vport['cookie_persistence_template'] = 'Persist_Cookie_JSESSIONID'
    	elif 'pbind clientip' in subsection:
    	    if ' 443\n' in subsection:
    	    	vport['protocol'] = 2
    	    elif ' 80\n' in subsection:
    	    	vport['protocol'] = 11
    	    else:
    	        vport['protocol'] = 2
    	    vport['source_ip_persistence_template'] = 'Persist_Srcip'
    	elif 'pbind sslid' in subsection:
    	    vport['protocol'] = 2
    	    vport['ssl_session_id_persistence_template'] = 'Persist_SSLID'
    	else:
    	    if ' 80\n' in subsection:
    	    	vport['protocol'] = 11
    	    else:
    	        vport['protocol'] = 2
    else:
    	# 2 denotes a VIP type = tcp
    	vport['protocol'] = 2
    	
    	# To solve persistence configured in ports with no dbind ena
    	#if 'cookie_persistence_template' in vport:
    	#		vport.pop('cookie_persistence_template', None)
    
    # Store Alteon configuration 'group' to get the service-group information later on.
    if 'group' in subsection:
        vport['alteon_sg_number'] = process_config_field(subsection, 'group') 
        
        # Logic to control unapplied groups in alteon config at the end of the script
        # Groups found in a VIP within the vport section are removed from the list that
        # stored all the groups earlier in the script.
        if vport['alteon_sg_number'] in original_alteon_sgs_list:
        	original_alteon_sgs_list.remove(vport['alteon_sg_number'])

def process_service_group_name(vport, section_string, vip_name):
    '''
    Generates a service-group name based on Alteon configuration group name if it exists
    Otherwise it uses the vip name to generate the name. The new SG name will end with
    ':port_number' where port_number corresponds to the vport_number where it is applied.
    Conversions applied to get the name:
    	- replace chars in CHAR_MAP keys with their corresponding values
    	- uppercase each word in the name
    	- ensure ':vport_number' will be at the end of the name
    	- join different words with '_' char instead of backspace
    This function requires to check no duplicate names exist and port exists in 
    Alteon configuration.
    '''
	# Convert backspace to '_' and upper after '_' before saving the service_group name
    if 'name' in section_string:
        service_group_name = process_config_field(section_string, 'name')
        service_group_name = service_group_name.replace('"','')
        # Replace '_' temporarily for further processing	
    else:
        service_group_name = vip_name
    
    #print "original sg_name = {}, vport_number = {}".format([service_group_name], 
    #                                                        str(vport['port']))
    
    # Substitute ilegal chars and remove ',' from service_group_name
    for a_substring_key, a_substring_value in CHAR_MAP.items():
    	if a_substring_key in service_group_name:
    		service_group_name = service_group_name.replace(a_substring_key, 
    		                                                a_substring_value)
    
    # Substitute names ending with '_number' or '-number'.Ex: 'SG_name_13' or 'SG_name-13'
    # would be replaced by 'SG_name 13'
    pattern_match = re.search("(_|-)(?=(\d+)$)", service_group_name)
    if pattern_match:
    	service_group_name = re.sub('(_|-)(?=(\d+)$)', ' ', service_group_name)	

    # Remove vport in name temporarily
    if str(vport['port']) in service_group_name:
    	service_group_name = service_group_name.replace(str(vport['port']), '')
    	# Remove extra backspaces
    	service_group_name = ' '.join(service_group_name.split())
    	# Remove last char before vport_number (could be ' ', '.', '_' or '-')
    	if service_group_name[-1] == ' ' or service_group_name[-1] == '.' or \
    	   service_group_name[-1] == '_' or service_group_name[-1] == '-':
        	delimiter_char = service_group_name[-1]
        	service_group_name = service_group_name[:-1]
    
    # Convert to uppercase each word in the service-group name	
    parsed_name = [substring[0].upper() + substring[1:] 
                   for substring in service_group_name.split(' ')]
    
    # Add ':vport_number' as a trailing and join words with '_' if more than 1 one word in
    # service_group_name
    if len(parsed_name) > 1:
    	service_group_name = '_'.join(parsed_name) + ':' + str(vport['port'])
    else:
    	service_group_name += ':' + str(vport['port'])
    
    #print "formatted sg = {}".format([service_group_name])
    
    return service_group_name
    

def process_service_group_info(vport, service_group_list, section_string, vip_name, 
                               duplicate):
    '''
    Generates a service-group name, applies it to the vport and checks if the new
    service-group name is already in the configuration or not to proceed accordingly.
    If it's not already in the configuration:
     - creates the new service-group and assigns the lb_method ('metric' in Alteon) and 
       the health-monitor ('health' in Alteon). Members can't be added until we have a 
       real-server name generated, which is done afterwards in the script.
     - 'alteon_real_server_list' keeps the information of the members in Alteon 
       configuration within the service_group element of the service_group_list
    Also, a optional print statement is provided to check duplicates (they are important
    particularly when duplicates don't come from SG reuses, that can be checked in the 
    SUMMARY section), enabled with the duplicate given parameter.
    '''
    # Normalize service-group name from alteon config
    service_group_name = process_service_group_name(vport, section_string, vip_name)
	
    # Add the service-group to the vport configuration
    vport['service_group'] = service_group_name
	
    # Process the service-group information if not already in configuration
    service_group_exists = False
    for a_service_group in service_group_list:
        if service_group_name == a_service_group['name']:
            service_group_exists = True
            # Optional print to check duplicate service-group names in the form
            # [already_existing_service_group_name, already_existing_alteon_sg_number]
            if duplicate:
            	print [a_service_group['name'], vport['alteon_sg_number']]
	
    if not service_group_exists:
        new_service_group_dict = {
                                  'name' : service_group_name,
                                  'protocol': 2,
                                  'member_list': [],
                                 }

        # Find all the real servers within a service-group and it's status
        real_server_list = ([[match.group(1), 'enabled'] for match in re.finditer(
                             'add (\d+)', section_string)])
        real_server_disabled_list = [match.group(1) for match in re.finditer('dis (\d+)', 
                                     section_string)]
        
        for index, a_real_server in enumerate(list(real_server_list)):
            if a_real_server[0] in real_server_disabled_list:
                real_server_list[index][1] = 'disabled'

        new_service_group_dict['alteon_real_server_list'] = real_server_list
    	
    	# Assign the health required health check
    	if 'health' in section_string:
    		hm_type = process_config_field(section_string, 'health')
    	else:
    		hm_type = '(default)'
    	
    	# Some hm types require 'content' configured. Also bypass ldap...
    	if hm_type in ['http', 'smtp', 'imap', 'pop3'] or hm_type == 'ldap':
    		if 'content' not in section_string:
    			hm_type = '(default)'
    	
    	
    	new_service_group_dict['health_monitor'] = HM_MAP[hm_type]
    	
    	# Assign the correct load balancing method
    	if 'metric' in section_string:
    		lb_method_type = process_config_field(section_string, 'metric')
    	else:
    		lb_method_type = 'least-connection'
    	
    	new_service_group_dict['lb_method'] = LB_METHOD_MAP[lb_method_type]
    	
    	#Add the new service_group to the master service_group dictionary
    	service_group_list.append(new_service_group_dict)
    	

def process_real_server_name(service_group, section_string):
    '''
    Generates a real-server name based on Alteon configuration real name if it 
    exists. Otherwise it uses the service_group name to generate the name without the 
    trailing ':vport_number' part to generate it.
    Conversions applied to get the name:
    	- uppercase each word in the name
    	- join different words with '_' char instead of backspace
    '''
    if 'name' in section_string:
    	real_server_name = process_config_field(section_string, 'name')
    else:
    	real_server_name = service_group['name'].rsplit(':')[0]
    
    # Convert to uppercase each word in the real_server name
    parsed_name = [substring[0].upper() + substring[1:] 
                   for substring in real_server_name.split(' ')]
    
    # Join words with '_' if more than 1 one word in real_server_name
    if len(parsed_name) > 1:
    	real_server_name = '_'.join(parsed_name)

    return real_server_name
    	
def process_real_server_info(service_group, alteon_real_server_in_sg, 
                             real_server_list, section_string, original_alteon_rss_list,
                             duplicate):
    '''
    Generates a real-server name, applies and checks if the new real-server name is
    already in the configuration or not to proceed accordingly, checking if there's 
    already real-server with the same IP address and/or with the same name.
    First, duplicated names/IP_addresses are fixed:
    	- duplicate real_server_name without duplicate real_server_address MUST be fixed 
    	  manually in the source file with the help of the optional print statement
    	  'print real_server_name'.
    	- duplicate real_server_address without duplicate real_server_name fixes the name
    	  mismatch automatically.
    Second, fill the service-group member information now that we know the real-server
    name.
    Third,
      If real-server:
    	- does not exist: create it and its ports.
    	- does exist: checks if the current port is not in the config and adds it in that 
    	  case.
    Also, a optional print statement is provided to check duplicates (they are important
    particularly when duplicates don't come from SG reuses, that can be checked in the 
    SUMMARY section), enabled with the duplicate given parameter.
    '''
	# Normalize real-server name and addres from alteon config
    real_server_name = process_real_server_name(service_group, section_string) 
    real_server_address = process_config_field(section_string, 'rip')
    
    # Detect if real_server_name and real_server_address already exist and proceed
    # appropriately, using list [name_matches, real_server_address_matches]
    real_server_exists = [False, False]
    for a_real_server in real_server_list:
        if real_server_name == a_real_server['name']:
            if real_server_address == a_real_server['host']:
                # Existing real_server, nothing to do
            	real_server_exists = [True, True]
            	break
            else:
            	# Duplicate real_server_name
            	real_server_exists = [True, False]
            	# Optional print to check Alteon duplicate real_server names
            	if duplicate:
            		print real_server_name
            	break
        else:
            if real_server_address == a_real_server['host']:
                # Duplicate real_server_address due to previous addition of the same
                # server with another name
                
            	# Fix real server name mismatch using the existing name in the configuration
            	real_server_name = a_real_server['name']
            	real_server_exists = [True, True]
            	break
    
    # The script assumes you previously have fixed duplicated real server names in the
    # alteon config file
        
    #print "Real server {}, IP address {}".format(real_server_name, real_server_address)
    
    # Once we have the real-server name, we can fill the service-group member name
    # Member port derived from service-group name because in alteon it doesn't exists port
    # NAT
    member_port = service_group['name'].rsplit(':')[-1]
    new_service_group_member_dict = {
    								 'port'   : int(member_port),
    								 'server' : real_server_name,
                                    }
    
    if alteon_real_server_in_sg[1] == 'enabled':
        new_service_group_member_dict['status'] = 1
    elif alteon_real_server_in_sg[1] == 'disabled':
    	new_service_group_member_dict['status'] = 0
    
    service_group['member_list'].append(new_service_group_member_dict)
    
    # Add the real_server and real_port information to data structures
    new_real_port_dict = {
                          'port_num'       : int(member_port),
    	                  'protocol'       : 2,
    	                  'health_monitor' : '(default)',
    	                  'status'         : 1,
    	                 }
    
    if real_server_exists == [False, False]:
    	# New real-server
    	new_real_server_dict = {
    	                        'name'           : real_server_name,
    	                        'host'           : real_server_address,
    	                        'conn_limit'     : 8000000,
    	                        'conn_limit_log' : 1,
    	                        'port_list'      : [],
    	                        'health_monitor' : '',
    	                       }
    	
    	if 'ena' in section_string:
    		new_real_server_dict['status'] = 1
    	
    	new_real_server_dict['port_list'].append(new_real_port_dict)
    	real_server_list.append(new_real_server_dict)
    	
    	# Logic to control unapplied servers in alteon config at the end of the script
    	if alteon_real_server_in_sg[0] in original_alteon_rss_list:
    		original_alteon_rss_list.remove(alteon_real_server_in_sg[0])
    
    elif real_server_exists == [True, True]:
    	# Add port if not exists within the real-server
        
        # Get the real_server index
        for index, a_real_server in enumerate(real_server_list):
    		if real_server_name == a_real_server['name']:
    			break
    	
    	# Check if port already exists
        real_port_exists = False
    	for a_real_port in real_server_list[index]['port_list']:
    		if a_real_port['port_num'] == new_real_port_dict['port_num']:
    			real_port_exists = True
    			break
    	
    	if not real_port_exists:
    		real_server_list[index]['port_list'].append(new_real_port_dict)
    	#else:
    	    #print "Not adding port {} belonging to real server {}".format(
    	    #       real_server_name, new_real_port_dict['port_num'])


def reuse_computation(lines_in_a_file):
     '''
     Calculates service-group reutilization in Alteon configuration and how many extra
     service-groups will be created due to reutilization in different ports (service-group
     names are all differentiated by ':vport_number' at the end of the name, so different
     port numbers mean different service-group names).
     The key/values in reuse_dict will be used in the SUMMARY section to check that the
     script is doing exactly what it should do. Specifically, it checks that the number
     of service-groups and real-servers that the script has in it's master structures
     matches what theoretically should be.
     '''
     reuse_dict = {
                  'sg_reuse_counter'            : 0,
                  'sg_extra_counter'            : 0,
                  'master_reuse_list'           : [],
                  'master_reuse_different_port' : [],
                  }
    
     for a_alteon_sg in range(MAX_ALTEON_SGS):
        string_to_process = 'group '+ str(a_alteon_sg)
        reuse_list_pointers = []
        for line_index, a_line in enumerate(lines_in_a_file):
        	if a_line.endswith('/' + string_to_process):
        	    continue
        	elif a_line.endswith(string_to_process):
        		reuse_list_pointers.append(line_index)

    	reuse_port_list = []
    	for a_reuse_pointer in reuse_list_pointers:
    	    index = int(a_reuse_pointer)
    	    while '/c/slb/virt' not in lines_in_a_file[index]:
    	    	index -= 1
    		sg_port = lines_in_a_file[index].rsplit('/service ')[-1]
    		
    		if sg_port not in reuse_port_list:
    		    reuse_port_list.append(sg_port)
    	
    	if len(reuse_port_list) > 1 :
    		reuse_dict['master_reuse_different_port'].append([a_alteon_sg, 
    		                                                  reuse_port_list])
    		reuse_dict['sg_extra_counter'] += len(reuse_port_list) - 1
    			
    	
    	# When there's repetition, the string 'group #SG \n', where #SG is the Alteon 
    	# group number, is present at least 3 times: 1 for group definition + at least
    	# 2 times to apply it
    	times_seen = len(reuse_list_pointers)			      
        if times_seen > 1:           
        	# There's repetition in the alteon SG
        	#print "Alteon SG {} reused {} times".format(str(a_alteon_sg), 
        	#                                            str(times_seen - 1))
    		reuse_dict['sg_reuse_counter'] += times_seen - 1
    		reuse_dict['master_reuse_list'].append((str(a_alteon_sg), times_seen - 1))

     return reuse_dict


def main():
    '''
    Alteon migration tool v1.0 to A10 2.7.[1-2] ACOS software (aXapi 2.1). This script
    migrates persistence templates, real servers, service-groups and virtual-servers.
    IMPORTANT: to avoid issues, it is required to ensure that no duplicate 
    names exist in Alteon configuration prior running the script. This entails:
    	- 'dname' duplicated values within Alteon '/c/slb/virt' elements. This must be
    	  checked manually.
    	- 'name' duplicated values within Alteon '/c/slb/group' elements. This must be
    	  checked manually but there's a optional print statement in function called
    	  'process_service_group_info' which can be enabled with '-d' argument.
    	- 'name' duplicated values within Alteon '/c/slb/real' elements. This must be
    	  checked manually but there's optional print statement in function called
    	  'process_real_server_info' which can be enabled with '-d' argument.
    '''
    
    # Argument parsing, requires alteon config file full path, and allows verbosity
    parser = ArgumentParser(description=("Script to process alteon configuration file and"
                            " store the information in json objects formatted like the "
                            "A10 is expecting"), prog='python process_script.py')
    parser.add_argument('alteon_config_file', action='store', help=('Alteon configuration'
                        ' file to process'))
    parser.add_argument('-d', '--duplicate', action='store_true', help=('help to detect '
                        'duplicate service-groups names and duplicate real-server names.'
                        " It's advised to use this option at the beginning to fix names.")
                        , dest= 'duplicate')
    parser.add_argument('-v', '--verbose', action='store_true', help=('increase output '
                        'verbosity (will show VIPs, SERVICE-GROUPs and REAL-SERVERs '
                        'stored in master dictionaries)'), dest= 'verbose')                    
    parsed_args = parser.parse_args()

    full_path_to_file = parsed_args.alteon_config_file
    # This enables duplicate element names printing
    duplicate = parsed_args.duplicate
    # verbose option will show the process virtual-server, service-group and real-server
    # configuration in dictionary structures ready to convert to json.
    verbose = parsed_args.verbose
    
    with open(full_path_to_file, 'r') as a_file:   
        file_content = a_file.read()
    a_file.close()
    
    # Normalize line feeds (force all lines to end with '\n') and split file in lines
    file_content = file_content.replace('\r\r\n', '\n')
    lines_in_a_file = file_content.splitlines()
    
    # Replace 'service' + protocol_name with 'service' + protocol_value in all the config
    map_protocol_values(lines_in_a_file)
    
    # Finds configured numbers of each relevant elements in Alteon configuration. This 
    # lists are used to detect unapplied SGs, reused SGs, and others.
    original_alteon_vips_list = find_all_occurrences(lines_in_a_file, 'vip')
    original_alteon_sgs_list = find_all_occurrences(lines_in_a_file, 'service_group')
    original_alteon_rss_list = find_all_occurrences(lines_in_a_file, 'real_server')
    original_alteon_figures = [len(original_alteon_vips_list),
                               len(original_alteon_sgs_list), 
    						   len(original_alteon_rss_list),]
 
    # VIP level processing
    
    # Creating 1st master structure eventually stored in 'VIPs.txt' file
    vip_map = {'virtual_server_list': []}
    vip_map_list = vip_map['virtual_server_list']
    
    for a_vip_number in range(MAX_VIPS):
        if ('/c/slb/virt ' + str(a_vip_number) + '\n') in file_content:
            # Get the configuration subsection and the VIP IP address
            section = find_section(lines_in_a_file, 'vip', str(a_vip_number))
    	    vip_address = process_config_field(section, 'vip')
            
            # Process the VIP information and add it to the vip_map dictionary
            process_vip_info(vip_map_list, vip_address, a_vip_number, section) 

    # Consolidate VIP sections to have only 1 vip_number per vip_address    
    renumber_vip_section(vip_map_list)

    
    # VPORT level processing (except service-group configuration)
    for index, a_vip in enumerate(vip_map_list):
    	vport_map = a_vip['vport_list']
    	for a_vport in vport_map:
    	    # Get each vport configuration to process it
    	    subsection = find_section(a_vip['section'].splitlines(), 'vport', 
    	                              str(a_vport['port']),
    	                              parent_number=str(index))
 
            # Process and add the vport information based on the subsection information
            # It requires the mapping between Alteon vip_numbers and A10 VIPs.
            process_vport_info(a_vport, subsection, original_alteon_sgs_list)
    
    
    # SERVICE-GROUP level processing (includes applying it to a vport)
    
    # Creating 2nd master structure eventually stored in 'SGs.txt' file
    service_group_map = {'service_group_list': []}
    service_group_map_list = service_group_map['service_group_list']
    
    # Duplicate names optional output logic
    if duplicate:
    	print '#' * 80
    	print "{:>20} SERVICE-GROUP NAME DUPLICATION INFORMATION {}".format(10 * '*', 
    	                                                                   10 * '*')
    	print
    	
    
    for a_vip in vip_map_list:
    	vport_map = a_vip['vport_list']
    	for a_vport in vport_map:
            # Get each service-group configuration to process it
    	    section = find_section(lines_in_a_file, 'service_group', 
    	                           str(a_vport['alteon_sg_number']))
    	    
    	    # Process and add the service-group information based on the section
    	    # information. Includes applying the service-group to the particular vport.
            process_service_group_info(a_vport, service_group_map_list, section,
                                       a_vip['name'], duplicate)
            

    # REAL-SERVER level processing
    
    # Creating 3rd master structure eventually stored in 'RSs.txt' file
    real_server_map = {'server_list': []}
    real_server_map_list = real_server_map['server_list']
    
    # Duplicate names optional output logic
    if duplicate:
    	print 
    	print "{:>20} REAL-SERVER NAME DUPLICATION INFORMATION {}".format(10 * '*', 
    	                                                                 10 * '*')
    	print
    
    for a_service_group in service_group_map_list:
        # Members information was previously stored in an auxiliar key within each 
        # service-group called 'alteon_real_server_list'.
        for index, a_alteon_real_server_in_sg in enumerate(
            a_service_group['alteon_real_server_list']):
            # Get each real_server configuration of each service-group to process it
    	    section = find_section(lines_in_a_file, 'real_server', 
    	                           a_alteon_real_server_in_sg[0])
    	    
            # Process and add the real-server information based on the section
    	    # information. Includes adding the members information to each service-group
    	    # in the A10 configuration.
            process_real_server_info(a_service_group, a_alteon_real_server_in_sg, 
                                     real_server_map_list, section, 
                                     original_alteon_rss_list, duplicate)
    
    
    # SERVICE GROUP REUSE PROCESSING (within Alteon Configuration)
    
    # This computation is required for check everything is correct in the SUMMARY section
    reuse_dict = reuse_computation(lines_in_a_file)
    		      
    
    # AUXILIAR KEYS REMOVAL PROCESSING
                                       
    list_vips = vip_map['virtual_server_list']
    list_service_groups = service_group_map['service_group_list']
    
    # Remove auxiliar keys with information from Alteon configuration that are no longer 
    # required.
    for a_vip in list_vips:
        a_vip.pop('alteon_vip_list', None)
        a_vip.pop('section', None)
        for a_port in a_vip['vport_list']:
        	a_port.pop('alteon_sg_number', None)

	for a_service_group in list_service_groups:
		a_service_group.pop('alteon_real_server_list', None)
    
    
    # RESULTS PRINTING
     
    print
    if verbose:
    	print '#' * 80
    
    for a_vip in list_vips:
    	if verbose:    
            print "{:>20} VIP_CONFIGURATION {}".format(10 * '*', 10 * '*')
            pprint(a_vip)
            print
        
        for a_port in a_vip['vport_list']:
            if verbose:
                print "{:>6} SERVICE_GROUP {} CONFIGURATION {}".format(3 * '*',
                       a_port['service_group'], 3 * '*')
            
                for a_service_group in list_service_groups:
            	    if a_service_group['name'] == a_port['service_group']:
                        pprint(a_service_group)
                        print
		
	if verbose:
		print '#' * 80
    
    list_real_servers = real_server_map['server_list']
    
    if verbose:
        for index, a_real_server in enumerate(real_server_map['server_list']):
    	    print "{:>20} REAL_SERVER_{}_CONFIGURATION {}".format(10 * '*', 
    	                                                          str(index+1),
    	                                                          10 * '*')
            pprint(a_real_server)
        print
    
    
    	# SUMMARY subsection within RESULTS PRINTING
    
    print '#' * 80
    print "{:>20} SUMMARY {}".format(10 * '*', 10 * '*')
    print
    print "Number of original unmerged VIPs in Alteon  : {}".format(
                                                             original_alteon_figures[0])
    print "Number of VIPs in A10                       : {}".format(str(len(list_vips)))
    print ("(A10 is not limited to 8 vports/ VIP so it does not require a new VIP with "
    	   "the same IP address for  VIPs with more than 8 vports like Alteon requires)")
    print "\n"
    print ("Applied original Alteon SGs        : {:<3}  "
           "Original Alteon config SGs : {}").format(
           original_alteon_figures[1] - len(original_alteon_sgs_list), 
           original_alteon_figures[1])
    print "{} Unapplied Alteon SGs       : {:<3}".format(41 * ' ', 
           len(original_alteon_sgs_list))
    print "Total Reuse number of Alteon SGs   : {}".format(
                                                    str(reuse_dict['sg_reuse_counter']))
    print "Total Extra SGs due to Reuse with"
    print "different port                     : {}".format(
                                                    str(reuse_dict['sg_extra_counter']))
    print
    print "Expected SGs in A10 config (Applied original + extra_counter) : {}".format(str(
           original_alteon_figures[1] - len(original_alteon_sgs_list) + 
           reuse_dict['sg_extra_counter']))
    print "Service Groups (SGs) ready to apply to A10 config {}: {}".format(12 * ' ',
                                                            str(len(list_service_groups)))
    print ("(A10 generates a new SG for each reuse in a specific service-port, so will "
           " have +extra_SG_number SGs than the applied SGs number in Alteon "
           " configuration)")
    print
    print "List of unapplied Alteon SGs                : {:<50}".format(
           original_alteon_sgs_list)
    print "Alteon SGs reuse list (number, reuse times) : {:<50}".format(
           reuse_dict['master_reuse_list'])
    print "Alteon SGs reuse list in different port"
    print "(number, different ports)                   : {:<50}".format(
           reuse_dict['master_reuse_different_port'])
    print "\n"
    print "Number of RSs in original config   {}: {}".format(17 * ' ',
                                                             original_alteon_figures[2])
    print "Number of unapplied Alteon RSs   {}: {}".format(19 * ' ',
                                                           len(original_alteon_rss_list))
    print
    print "Expected RSs in A10 config (Total - unapplied)      : {}".format(
           str(original_alteon_figures[2] - len(original_alteon_rss_list)))
    print "Real Servers (RSs) ready to apply to A10 config     : {}".format(
           str(len(list_real_servers)))
    print ("(A10 will have the RS configured as long as it is applied in the"
          " Alteon config)")
    print
    print "List of unapplied Alteon RSs       : {}".format(original_alteon_rss_list)
    print
    print '#' * 80
    print
    
    
    # JSON CONVERSION AND STORING TO FILES PROCESSING
        
    print
    store_objects = raw_input("Would you like to store the extracted data (yes/no): ")
    
    if store_objects.lower() == 'yes':
        # Get the script directory
        script_dir = os.path.dirname(os.path.realpath(__file__))
    
    	# Create json_objects subdir if it doesn't exist
    	if not os.path.exists(script_dir + '/json_objects/'):
    		os.makedirs('./json_objects/')
    	
    	# Store VIPs dictionary
    	with open(script_dir + '/json_objects/VIPs.txt', 'w') as a_file:   
        	json.dump(vip_map, a_file, indent=4)
        	print "Successfully saved {} file...".format(
        	       script_dir + '/json_objects/VIPs.txt')
    	a_file.close()
    	
    	# Store SGs dictionary
    	with open(script_dir + '/json_objects/SGs.txt', 'w') as a_file:   
        	json.dump(service_group_map, a_file, indent=4)
        	print "Successfully saved {} file...".format(
        	       script_dir + '/json_objects/SGs.txt')
    	a_file.close()
    	
    	# Store RSs dictionary
    	with open(script_dir + '/json_objects/RSs.txt', 'w') as a_file:   
        	json.dump(real_server_map, a_file, indent=4)
        	print "Successfully saved {} file...".format(
        	       script_dir + '/json_objects/RSs.txt')
    	a_file.close()
    	
    elif store_objects.lower() == 'no':
        print "Data not saved....bye"
    
    else:
        print "Invalid entry....assuming the entry as 'no'"
        print "Data not saved....bye"
    
    print
    
         
    # Troubleshooting logic to check correct SG process from alteon config
    # It requires to comment all the 'AUXILIAR KEYS REMOVAL PROCESSING' section
    #new_list = []
    #for a_vip in list_vips:
	#	print "VIP address             : {}".format(a_vip['address'])
	#	print "Alteon VIP numbers      : {}".format(a_vip['alteon_vip_list'])
	#	print "Number of Alteon SGs    : {}".format(len(a_vip['vport_list']))
	#	temp_list = []
	#	for a_vport in a_vip['vport_list']:
	#		temp_list.append(a_vport['alteon_sg_number'])
	#	print "Alteon SGs on VIP list  : {}".format(temp_list)
	#	print
	#	for a_vport in a_vip['vport_list']:
	#		new_list.append(a_vport['alteon_sg_number'])
	#
    #print
    #print "Alteon SGs list       : {}".format(new_list)
    #print "Number of SG to apply : {}".format(len(new_list))
    #print
    #
    

if __name__ == '__main__':
	main()   

	
