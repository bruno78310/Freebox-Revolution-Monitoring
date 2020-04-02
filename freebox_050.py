#!/usr/bin/python3
#-*- coding: utf-8 -*-
# coding: utf-8
# pylint: disable=C0103,C0111,W0621


from __future__ import print_function
from __future__ import unicode_literals

import requests
import os
import json
import hmac
import time
import argparse
import sys
import time
from time import strftime, gmtime
from datetime import datetime
from hashlib import sha1

if sys.version_info >= (3, 0):
    import configparser as configp
else:
    import ConfigParser as configp

#
# Freebox API SDK / Docs: http://dev.freebox.fr/sdk/os/login/
# version 4
#

VERSION = "0.5.0"

#
# update version 0.4.5 : 
#    interpreteur ligne 1 : python3 au lieu de python
#    remise en place des indentations dans la fonction "try" de def 'get_auth()'
#    unicode n'existe plus en Python3.     
#         if type(my_data[i]) == unicode:                                                                                         
#           NameError: name 'unicode' is not defined                                                                                    
#     => replace unicode by str dans le  "switching output format" test
#    indentation à corriger
#    reste pb lié ? au choix data_format / vs influxdb !!!
# version 046 : simplifiee => format unique influxdb
# disk : disk 0 et non pas disk 1
# ajout serial / model pour disque
# version 047 : 
#        je remets data_format=influx
#        je remets le test dans le script
#
# version 048 : 
#        ajout option -L pour Lan (ok)
#        ajout option -W pour Wifi (pas codée)
#
# version 049
#        prise en compte de 3 tags par nom de variable
#        les tags sont séparés pas des "."
#        tag1.tag2.tag3.valeur
#
# version 050
#        iso fonctionnelle 049
#        nettoyage du code et des commentaires

  

def get_challenge(freebox_app_id):
    api_url = '%s/login/authorize/%s' % (ENDPOINT, freebox_app_id)

    r = requests.get(api_url)

    if r.status_code == 200:
        return r.json()
    else:
        print("Failed request: %s\n" % r.text)


def open_session(password, freebox_app_id):
    api_url = '%s/login/session/' % ENDPOINT

    app_info = {
        'app_id': freebox_app_id,
        'password': password
    }
    json_payload = json.dumps(app_info)

    r = requests.post(api_url, data=json_payload)

    if r.status_code == 200:
        return r.json()
    else:
        print("Failed request: %s\n" % r.text)


def get_internal_disk_stats(headers):
    api_url = '%s/storage/disk/0' % ENDPOINT

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print("Failed request: %s\n" % r.text)


def get_connection_stats(headers):
    api_url = '%s/connection/' % ENDPOINT

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print("Failed request: %s\n" % r.text)


def get_ftth_status(headers):
    api_url = '%s/connection/ftth/' % ENDPOINT

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)


def get_xdsl_status(headers):
    api_url = '%s/connection/xdsl/' % ENDPOINT

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)


def get_system_config(headers):
    api_url = '%s/system/' % ENDPOINT

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)


def get_switch_status(headers):
    api_url = '%s/switch/status/' % ENDPOINT

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)


def get_switch_port_stats(headers, port):
    api_url = '%s/switch/port/%s/stats' % (ENDPOINT, port)

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)

 
def get_lan_config(headers):
    api_url = '%s/lan/config/' % ENDPOINT
    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)


def get_wifi_stats(headers):
    api_url = '%s/wifi/ap/0/stations/' % (ENDPOINT)
    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)  


def get_lan_interfaces(headers):
    api_url = '%s/lan/browser/interfaces/' % ENDPOINT
    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)
   

def get_interfaces_hosts(headers):
    api_url = '%s/lan/browser/pub/' % ENDPOINT
    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)

def get_and_print_metrics(creds, s_switch, s_ports, s_sys, s_disk, s_lan, s_wifi, s_lan_interfaces, s_interfaces_hosts):
    #freebox_app_id = "fr.freebox.seximonitor"
    #freebox_app_id = "fr.freebox.grafanamonitor"
    freebox_app_id = creds['app_id']
    #

    # setup output dataformat, default Graphite

    # tag for influxdb
    # regle de nommage : mettre les informations (rx, tx, port 1, ...) dans les tags.
    # ne mettre que des noms de valeurs de variables generiques : bytes, bits, rate, bandwidth, firmware .....
    # les tags sont la pour donnner le contexte
    # cela permettra des tris et regroupements plus complets sous grafana
    # 3 tags séparé par des "."
    # chaque valeur aura donc un nom de la forme : tag1.tag2.tag3.valeur
    #
    tag1=tag2=tag3=""

    dataformat='influxdb'

    # Fetch challenge
    resp = get_challenge(creds['track_id'])
    challenge = resp['result']['challenge']

    # Generate session password
    if sys.version_info >= (3, 0):
        h = hmac.new(bytearray(creds['app_token'], 'ASCII'), bytearray(challenge, 'ASCII'), sha1)
    else:
        h = hmac.new(creds['app_token'], challenge, sha1)
    password = h.hexdigest()

    # Fetch session_token
    resp = open_session(password, freebox_app_id)
    session_token = resp['result']['session_token']

    # Setup headers with the generated session_token
    headers = {
        'X-Fbx-App-Auth': session_token
    }

    # Setup hashtable for results
    my_data = {}

    # Fetch connection stats
    json_raw = get_connection_stats(headers)

    # Generic datas, same for FFTH or xDSL

    tag1="box"
    if 'result' in json_raw:
        tag3 = "NULL"

        tag2 = "down"
        my_data[tag1+"."+tag2+"."+tag3+"."+'bytes'] = json_raw['result']['bytes_down']  # total in bytes since last connection
        my_data[tag1+"."+tag2+"."+tag3+"."+'rate'] = json_raw['result']['rate_down']  # current rate in byte/s
        my_data[tag1+"."+tag2+"."+tag3+"."+'bandwidth'] = json_raw['result']['bandwidth_down']  # available bw in bit/s
        my_data[tag1+"."+tag2+"."+tag3+"."+'bytes'] = json_raw['result']['bytes_down']

        tag2 = "up"
        my_data[tag1+"."+tag2+"."+tag3+"."+'bytes'] = json_raw['result']['bytes_up']
        my_data[tag1+"."+tag2+"."+tag3+"."+'rate'] = json_raw['result']['rate_up']
        my_data[tag1+"."+tag2+"."+tag3+"."+'bandwidth'] = json_raw['result']['bandwidth_up']
        my_data[tag1+"."+tag2+"."+tag3+"."+'bytes'] = json_raw['result']['bytes_up']

        tag2 = "NULL"
        my_data[tag1+"."+tag2+"."+tag3+"."+'media'] = json_raw['result']['media']
        my_data[tag1+"."+tag2+"."+tag3+"."+'ipv4'] = json_raw['result']['ipv4']
        my_data[tag1+"."+tag2+"."+tag3+"."+'ipv6'] = json_raw['result']['ipv6']

    # ffth for FFTH (default)
    # xdsl for xDSL
    connection_media = json_raw['result']['media']

    # FTTH specific
    if connection_media == "ftth":
        json_raw = get_ftth_status(headers)

        if 'result' in json_raw:       
            tag1="box"
            tag2="signal"
            tag3 = "NULL"
            my_data[tag1+"."+tag2+"."+tag3+"."+'sfp_has_signal'] = json_raw['result']['sfp_has_signal']  # BrW : cet attribu est bien présent: boolean 

    # xDSL specific
    if connection_media == "xdsl":
        json_raw = get_xdsl_status(headers)

        if 'result' in json_raw:
            my_data['xdsl_modulation'] = json_raw['result']['status']['modulation'] + " ("+json_raw['result']['status']['protocol']+")"  # in seconds

            my_data['xdsl_uptime'] = json_raw['result']['status']['uptime']  # in seconds

            my_data['xdsl_status_string'] = json_raw['result']['status']['status']
            if json_raw['result']['status']['status'] == "down":  # unsynchronized
                my_data['xdsl_status'] = 0
            elif json_raw['result']['status']['status'] == "training":  # synchronizing step 1/4
                my_data['xdsl_status'] = 1
            elif json_raw['result']['status']['status'] == "started":  # synchronizing step 2/4
                my_data['xdsl_status'] = 2
            elif json_raw['result']['status']['status'] == "chan_analysis":  # synchronizing step 3/4
                my_data['xdsl_status'] = 3
            elif json_raw['result']['status']['status'] == "msg_exchange":  # synchronizing step 4/4
                my_data['xdsl_status'] = 4
            elif json_raw['result']['status']['status'] == "showtime":  # ready
                my_data['xdsl_status'] = 5
            elif json_raw['result']['status']['status'] == "disabled":  # disabled
                my_data['xdsl_status'] = 6
            else:  # unknown
                my_data['xdsl_status'] = 999

            if 'es' in json_raw['result']['down']: my_data['xdsl_down_es'] = json_raw['result']['down']['es']  # increment
            if 'attn' in json_raw['result']['down']: my_data['xdsl_down_attn'] = json_raw['result']['down']['attn']  # in dB
            if 'snr' in json_raw['result']['down']: my_data['xdsl_down_snr'] = json_raw['result']['down']['snr']  # in dB
            if 'rate' in json_raw['result']['down']: my_data['xdsl_down_rate'] = json_raw['result']['down']['rate']  # ATM rate in kbit/s
            if 'hec' in json_raw['result']['down']: my_data['xdsl_down_hec'] = json_raw['result']['down']['hec']  # increment
            if 'crc' in json_raw['result']['down']: my_data['xdsl_down_crc'] = json_raw['result']['down']['crc']  # increment
            if 'ses' in json_raw['result']['down']: my_data['xdsl_down_ses'] = json_raw['result']['down']['ses']  # increment
            if 'fec' in json_raw['result']['down']: my_data['xdsl_down_fec'] = json_raw['result']['down']['fec']  # increment
            if 'maxrate' in json_raw['result']['down']: my_data['xdsl_down_maxrate'] = json_raw['result']['down']['maxrate']  # ATM max rate in kbit/s
            if 'rtx_tx' in json_raw['result']['down']: my_data['xdsl_down_rtx_tx'] = json_raw['result']['down']['rtx_tx']  # G.INP on/off
            if 'rtx_c' in json_raw['result']['down']: my_data['xdsl_down_rtx_c'] = json_raw['result']['down']['rtx_c']  # G.INP corrected
            if 'rtx_uc' in json_raw['result']['down']: my_data['xdsl_down_rtx_uc'] = json_raw['result']['down']['rtx_uc']  # G.INP uncorrected
    
            if 'es' in json_raw['result']['up']: my_data['xdsl_up_es'] = json_raw['result']['up']['es']
            if 'attn' in json_raw['result']['up']: my_data['xdsl_up_attn'] = json_raw['result']['up']['attn']
            if 'snr' in json_raw['result']['up']: my_data['xdsl_up_snr'] = json_raw['result']['up']['snr']
            if 'rate' in json_raw['result']['up']: my_data['xdsl_up_rate'] = json_raw['result']['up']['rate']
            if 'hec' in json_raw['result']['up']: my_data['xdsl_up_hec'] = json_raw['result']['up']['hec']
            if 'crc' in json_raw['result']['up']: my_data['xdsl_up_crc'] = json_raw['result']['up']['crc']
            if 'ses' in json_raw['result']['up']: my_data['xdsl_up_ses'] = json_raw['result']['up']['ses']
            if 'fec' in json_raw['result']['up']: my_data['xdsl_up_fec'] = json_raw['result']['up']['fec']
            if 'maxrate' in json_raw['result']['up']: my_data['xdsl_up_maxrate'] = json_raw['result']['up']['maxrate']
            if 'rtx_tx' in json_raw['result']['up']: my_data['xdsl_up_rtx_tx'] = json_raw['result']['up']['rtx_tx']
            if 'rtx_c' in json_raw['result']['up']: my_data['xdsl_up_rtx_c'] = json_raw['result']['up']['rtx_c']  # G.INP corrected
            if 'rtx_uc' in json_raw['result']['up']: my_data['xdsl_up_rtx_uc'] = json_raw['result']['up']['rtx_uc']  # G.INP uncorrected

    #
    # General infos
#
# option -L
#
    if s_lan:
        sys_json_raw = get_lan_config(headers)
        tag1="Lan Config"
        tag2="NULL"
        tag3="NULL"
        if 'result' in sys_json_raw:
            if 'mode' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'lan_mode'] = sys_json_raw['result']['mode']
            if 'ip' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'lan_ip'] = sys_json_raw['result']['ip']
            if 'name' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'lan_name'] = sys_json_raw['result']['name']
            if 'name_dns' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'lan_name_dns'] = sys_json_raw['result']['name_dns']
            if 'name_mdns' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'lan_name_mdns'] = sys_json_raw['result']['name_mdns']
            if 'name_netbios' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'lan_name_netbios'] = sys_json_raw['result']['name_netbios']

#
# option -I
#   
    if s_lan_interfaces:
        sys_json_raw = get_lan_interfaces(headers)
        
        tag1="Interfaces"
        tag2="NULL"
        tag3="NULL"
        
        if 'result' in sys_json_raw:

            l=len(sys_json_raw['result'])
            i=0
            while i<l:
                tag2=("if#%s" % i)
                my_data[tag1+"."+tag2+"."+tag3+"."+'name']=sys_json_raw['result'][i]['name']
                my_data[tag1+"."+tag2+"."+tag3+"."+'host_count']=sys_json_raw['result'][i]['host_count']
                i=i+1
#
# liste des stations -X
#

    if s_interfaces_hosts:
        sys_json_raw = get_interfaces_hosts(headers)
        if 'result' in sys_json_raw:
            l=len(sys_json_raw['result'])
            tag1="hosts_list"
            k=0
            while k<l :
                tag2="NULL"
                if 'l3connectivities' in sys_json_raw['result'][k]:
                     length_l3_conn = len(sys_json_raw['result'][k]['l3connectivities'])
                     j=0
                     while j<length_l3_conn :
                          if sys_json_raw['result'][k]['l3connectivities'][j]['addr'] != "" :
                              if 'id' in sys_json_raw['result'][k]['l2ident']:
                                  tag3=sys_json_raw['result'][k]['l2ident']['id'] 
                                  if sys_json_raw['result'][k]['l3connectivities'][j]['af']=="ipv4":
                                      my_data[tag1+"."+tag2+"."+tag3+"."+'addr']=sys_json_raw['result'][k]['l3connectivities'][j]['addr']
                                      my_data[tag1+"."+tag2+"."+tag3+"."+'last_activity']=datetime.fromtimestamp(sys_json_raw['result'][k]['l3connectivities'][j]['last_activity']).strftime("%c")
                                      if 'primary_name' in sys_json_raw['result'][k]:my_data[tag1+"."+tag2+"."+tag3+"."+'primary_name']=sys_json_raw['result'][k]['primary_name']
                                      if 'host_type' in sys_json_raw['result'][k]:my_data[tag1+"."+tag2+"."+tag3+"."+'host_type']=sys_json_raw['result'][k]['host_type']
                                      if 'active' in sys_json_raw['result'][k]:my_data[tag1+"."+tag2+"."+tag3+"."+'active']=sys_json_raw['result'][k]['active']
                          j=j+1    
                k=k+1

#
# option -H
#
    if s_sys:
        sys_json_raw = get_system_config(headers)
        
        tag1="System"
        tag2="NULL"
        tag3="NULL"        
        
        if 'result' in sys_json_raw:
            if 'fan_rpm' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'sys_fan_rpm'] = sys_json_raw['result']['fan_rpm']        # rpm
            if 'temp_sw' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'sys_temp_sw'] = sys_json_raw['result']['temp_sw']        # Temp Switch, degree Celcius
            if 'uptime_val' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'sys_uptime_val'] = sys_json_raw['result']['uptime_val']   # Uptime, in seconds
            if 'uptime' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'uptime'] = sys_json_raw['result']['uptime']           # uptime in readable format ?
            if 'temp_cpub' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'sys_temp_cpub'] = sys_json_raw['result']['temp_cpub']  # Temp CPU Broadcom, degree Celcius
            if 'temp_cpum' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'sys_temp_cpum'] = sys_json_raw['result']['temp_cpum']  # Temp CPU Marvell, degree Celcius
            if 'firmware_version' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'firmware_version'] = sys_json_raw['result']['firmware_version']  # Firmware version   
#
# option -S
#    
# 
    if s_switch:
        switch_json_raw = get_switch_status(headers)
        
        tag1="Switch"
        tag2="NULL"
        tag3="NULL" 
        
        if 'result' in switch_json_raw:
            for i in switch_json_raw['result']:
                # 0 down, 1 up
                tag2="link#"+str(i['id'])
                if i['link'] == "up" : my_data[tag1+"."+tag2+"."+tag3+"."+'Etat'] = 1
                else: my_data[tag1+"."+tag2+"."+tag3+"."+'Etat'] = 0
                # 0 auto, 1 10Base-T, 2 100Base-T, 3 1000Base-T
                # In fact the duplex is appended like 10BaseT-HD, 1000BaseT-FD, 1000BaseT-FD
                # So just is an "in" because duplex isn't really usefull
                if "10BaseT" in i['mode']:
                    my_data[tag1+"."+tag2+"."+tag3+"."+'mode'] = 1
                elif "100BaseT" in i['mode']:
                    my_data[tag1+"."+tag2+"."+tag3+"."+'mode'] = 2
                elif "1000BaseT" in i['mode']:
                    my_data[tag1+"."+tag2+"."+tag3+"."+'mode'] = 3
                else:
                    my_data[tag1+"."+tag2+"."+tag3+"."+'mode'] = 0  # auto

#
# Option -P
#
# Switch ports status
    if s_ports:
    	 	        
        tag1="Ports"
        tag2="NULL"
        tag3="NULL"
    	
        for i in [1, 2, 3, 4]:
            switch_port_stats = get_switch_port_stats(headers, i)
            tag1="Port#"+str(i)
            tag2="Rx"
            my_data[tag1+"."+tag2+"."+tag3+"."+'bytes_rate'] = switch_port_stats['result']['rx_bytes_rate']  # bytes/s (?)
            tag2="Tx"
            my_data[tag1+"."+tag2+"."+tag3+"."+'bytes_rate'] = switch_port_stats['result']['tx_bytes_rate']

#
# Option -D
#
# Fetch internal disk stats
    if s_disk:
        json_raw = get_internal_disk_stats(headers)
        
        tag1="Disque"
        tag2="NULL"
        tag3="NULL"

    if 'result' in json_raw and 'partitions' in json_raw['result']:
            if 'total_bytes' in json_raw['result']['partitions'][0]:my_data[tag1+"."+tag2+"."+tag3+"."+'disk_total_bytes'] = json_raw['result']['partitions'][0]['total_bytes']
            if 'used_bytes' in json_raw['result']['partitions'][0]:my_data[tag1+"."+tag2+"."+tag3+"."+'disk_used_bytes'] = json_raw['result']['partitions'][0]['used_bytes']
            if 'temp' in json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'disk_temp'] = json_raw['result']['temp']
            if 'serial' in json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'disk_serial'] = json_raw['result']['serial']
            if 'model' in json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'disk_model'] = json_raw['result']['model']
            if 'firmware' in json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'disk_firmware'] = json_raw['result']['firmware']            

#
# Option -W
#
# Wifi stats
#
    if s_wifi:
        sys_json_raw = get_wifi_stats(headers)
        l=len(sys_json_raw['result'])
        tag1="Wifi"
        tag2="NULL"
        tag3="NULL" 

        if 'result' in sys_json_raw:
            l=len(sys_json_raw['result'])
            tag1="wifi_list"
            k=0
            while k<l :
                if 'mac' in sys_json_raw['result'][k]:
                     tag3=sys_json_raw['result'][k]['mac']
                     length_l3_conn = len(sys_json_raw['result'][k]['host']['l3connectivities'])
                     if 'primary_name' in sys_json_raw['result'][k]['host']:
                          if sys_json_raw['result'][k]['host']['primary_name'] != "" : 
                                if 'interface' in sys_json_raw['result'][k]['host']:
                                      if sys_json_raw['result'][k]['host']['interface'] != "" :
                                            m=0
                                            while m < length_l3_conn :
                                                if sys_json_raw['result'][k]['host']['l3connectivities'][m]['af'] == "ipv4":
                                                    my_data[tag1+"."+tag2+"."+tag3+"."+'primary_name']=sys_json_raw['result'][k]['host']['primary_name']
                                                    my_data[tag1+"."+tag2+"."+tag3+"."+'host_type']=sys_json_raw['result'][k]['host']['host_type']
                                                    my_data[tag1+"."+tag2+"."+tag3+"."+'interface']=sys_json_raw['result'][k]['host']['interface']
                                                    my_data[tag1+"."+tag2+"."+tag3+"."+'addripv4']=sys_json_raw['result'][k]['host']['l3connectivities'][m]['addr']
                                                    my_data[tag1+"."+tag2+"."+tag3+"."+'reachable']=sys_json_raw['result'][k]['host']['l3connectivities'][m]['reachable']
                                                    my_data[tag1+"."+tag2+"."+tag3+"."+'active']=sys_json_raw['result'][k]['host']['l3connectivities'][m]['active']
                                                    lasttimeactivity=sys_json_raw['result'][k]['host']['l3connectivities'][m]['last_activity']
                                                    date_last_activity=datetime.fromtimestamp(lasttimeactivity)
                                                    my_data[tag1+"."+tag2+"."+tag3+"."+'last_activity_date']=date_last_activity.strftime("%c")
                                                m=m+1   
                k=k+1
 #
    
########################################################################################################################################################    
    # Switching between outputs formats 
    # c'est args.format qu'il faut utiliser, et non pas args.data_format.
    # if args.format == 'influxdb':
    if dataformat == 'influxdb' :

    # Prepping Influxdb Data format
        timestamp = int(time.time()) * 1000000
    
    # Output the information

        if tag1 == "": tag1="test-tag1"
        if tag2 == "": tag2="test-tag2"
        if tag3 == "": tag2="test-tag3"

#
# extraire les 3 tags
#
    # positions des 3 "." points séparateurs de tags

        for i in my_data:
            pos=[0,0,0]
            j=0
            k=0

            while  j < len(i):	
               if i[j] == ".":
                     pos[k]=j
                     k=k+1  
               j=j+1     
                 
            tag1=i[0:pos[0]]
            tag2=i[pos[0]+1:pos[1]]
            tag3=i[pos[1]+1:pos[2]]        	
#
# supprimer les blancs " " dans les tags par des "-"
#
            tag1=tag1.replace(" ","-")
            tag2=tag2.replace(" ","-")
            tag3=tag3.replace(" ","-")
        	
            if type(my_data[i]) == str:

# et dans le print on enlève les 3 tags de la partie my_data
# on va de pos[2]+1  à la fin de i

                print("freebox,endpoint=%s,tag1=%s,tag2=%s,tag3=%s %s=\"%s\"" % (args.Endpoint,tag1,tag2,tag3, i[pos[2]+1:], my_data[i]))
            else:         
                print("freebox,endpoint=%s,tag1=%s,tag2=%s,tag3=%s %s=%s" % (args.Endpoint,tag1,tag2,tag3, i[pos[2]+1:], my_data[i]))

    else:
    # Prepping Graphite Data format
        timestamp = int(time.time())

         # Output the information
        for i in my_data:
            print("freebox.%s %s %d" % (i, my_data[i], timestamp))


def get_auth():
    script_dir = os.path.dirname(os.path.realpath(__file__))
    cfg_file = os.path.join(script_dir, ".credentials")
    ret_args={}
    f = configp.RawConfigParser()
    f.read(cfg_file)
    
    try:
        _ = f.has_section(args.Endpoint)

        ret_args.update(track_id= f.get(args.Endpoint, "track_id"))
        ret_args.update(app_token= f.get(args.Endpoint, "app_token"))

        if f.has_option(args.Endpoint, "app_id"):
             ret_args.update(app_id= f.get(args.Endpoint, "app_id")) 
        else:
             ret_args.update(app_id= app_id)

        if f.has_option(args.Endpoint, "app_name"):
             ret_args.update(app_name= f.get(args.Endpoint, "app_name")) 
        else:
             ret_args.update(app_name= app_name) 

        if f.has_option(args.Endpoint, "device_name"):
             ret_args.update(device_name= f.get(args.Endpoint, "device_name")) 
        else:
             ret_args.update(device_name= device_name)

    except configp.NoSectionError:
        if args.register:
             return None
        else:
             exit();

    return ret_args


def write_auth(auth_infos):
    script_dir = os.path.dirname(os.path.realpath(__file__))
    cfg_file = os.path.join(script_dir, ".credentials")
    f = configp.RawConfigParser()
    f.add_section(args.Endpoint)
    f.set(args.Endpoint, "track_id", auth_infos['track_id'])
    f.set(args.Endpoint, "app_token", auth_infos["app_token"])
    f.set(args.Endpoint, "app_id", app_id)
    f.set(args.Endpoint, "app_name", app_name)
    f.set(args.Endpoint, "device_name", device_name)
    with open(cfg_file, "ab") as authFile:
        f.write(authFile)


def do_register(creds):
    #global app_id,app_name,device_name
    if creds is not None:
        if 'track_id' in creds and 'app_token' in creds:
            print("Already registered, exiting")
            return

    print("Doing registration")
    headers = {'Content-type': 'application/json'}
    app_info = {
        'app_id': app_id,
        'app_name': app_name,
        'app_version': VERSION,
        'device_name': device_name
    }
    json_payload = json.dumps(app_info)

    r = requests.post('%s/login/authorize/' % ENDPOINT, headers=headers, data=json_payload)
    register_infos = None

    if r.status_code == 200:
        register_infos = r.json()
    else:
        print('Failed registration: %s\n' % r.text)

    write_auth(register_infos['result'])
    print("Don't forget to accept auth on the Freebox panel !")


def register_status(creds):
    if not creds:
        print("Status: invalid config, auth not done.")
        print("Please run `%s --register` to register app." % sys.argv[0])
        return
    print("Status: auth already done")

# Main
if __name__ == '__main__':
    app_id='fr.freebox.grafanamonitor'
    app_name='GrafanaMonitor'   
    device_name='GrafanServer' 


    parser = argparse.ArgumentParser(add_help=False)
    #helpgroup = parser.add_argument_group()
    parser.add_argument("-h", "--help", action="help", help="show this help message and exit")
    parser.add_argument('-s', '--register-status', dest='status', action='store_true', help="Get register status")

    #registergroup = parser.add_mutually_exclusive_group()
    parser.add_argument('-r', '--register', action='store_true', help="Register app with Freebox API")
    #parser.add_argument('-a', '--appname', dest='appname', action='store_true', help="Register with appname")
    #parser.add_argument('-i', '--appid', dest='appid', action='store_true', help="Register with appid")
    #parser.add_argument('-d', '--device-name', dest='devicename', action='store_true', help="Register with device-name")

    parser.add_argument('-n', '--appname',
                        dest='app_name',
            metavar='app_name',
                        help="Register with app_name")

    parser.add_argument('-i', '--appid',
                        dest='app_id',
            metavar='app_id',
                        help="Register with app_id")

    parser.add_argument('-d', '--devicename',
                        dest='device_name',
            metavar='device_name',
                        help="Register with device_name")

    parser.add_argument('-f', '--format',
                        dest='format',
            metavar='format',
            default='graphite',
                        help="Specify output format between graphite and influxdb")

    parser.add_argument('-e', '--endpoint',
                        dest='Endpoint',
            metavar='endpoint',
            default='mafreebox.freebox.fr',
                        help="Specify endpoint name or address")

    parser.add_argument('-S', '--status-switch',
                        dest='status_switch',
                        action='store_true',
                        help="Get and show switch status")

    parser.add_argument('-P', '--status-ports',
                        dest='status_ports',
                        action='store_true',
                        help="Get and show switch ports stats")

    parser.add_argument('-H', '--status-sys',
                        dest='status_sys',
                        action='store_true',
                        help="Get and show system status")

    parser.add_argument('-D', '--internal-disk-usage',
                        dest='disk_usage',
                        action='store_true',
                        help="Get and show internal disk usage")

#
# Ajout 0.4.8 et 0.4.9
#
    parser.add_argument('-L', '--lan-config',
                        dest='lan_config',
                        action='store_true',
                        help="Get and show LAN config")

    parser.add_argument('-W', '--wifi-usage',
                        dest='wifi_usage',
                        action='store_true',
                        help="Get and show wifi usage")   

    parser.add_argument('-I', '--lan-interfaces',
                        dest='lan_interfaces',
                        action='store_true',
                        help="Get and show lan interfaces")                                                 

    parser.add_argument('-X', '--interfaces-hosts',
                        dest='interfaces_hosts',
                        action='store_true',
                        help="Get and show interfaces hosts") 

    args = parser.parse_args()

    if args.app_id is not None:
      app_id=args.app_id

    if args.app_name is not None:
      app_name=args.app_name

    if args.device_name is not None:
      device_name=args.device_name

    ENDPOINT="http://"+args.Endpoint+"/api/v4/"
    auth = get_auth()

    if args.register:
        do_register(auth)
    elif args.status:
        register_status(auth)
    else:     
        get_and_print_metrics(auth, args.status_switch, args.status_ports, args.status_sys, args.disk_usage, args.lan_config, args.wifi_usage, args.lan_interfaces, args.interfaces_hosts)
