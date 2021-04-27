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


# To install the latest version of Unidecode from the Python package index, use these commands:
# $ pip install unidecode
from unidecode import unidecode
#
if sys.version_info >= (3, 0):
    import configparser as configp
else:
    import ConfigParser as configp

#
# Freebox API SDK / Docs: http://dev.freebox.fr/sdk/os/login/
# version 8
#

VERSION = "0.6.1  2021/04/27"

# version 059
#         prise en compte api v8 (option -H en particulier)
#         meilleure prise en compte des autres plateforme que Fbox Rev.
#              avec en particulier meilleur traitement des listes de paramètres.
# version 060
#         le Rasp Pi vu sans nom depuis le DHCP freebox n'apparait pas dans la liste des hotes !
#              verifier ce qui se passe si on a l'addr MAC mais pas de nom
#                => aller prendre les données DHCP statiques et dynamiques
# version 061
#         prise en compte de l agregation xdsl / lte
#         prise en compte corrections xdsl en cas de connexion state=down
#         prise en compte test présence disk


def get_creation_date(file):
    stat = os.stat(file)
    return stat.st_mtime 

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
    api_url = '%s/storage/disk/' % ENDPOINT

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


def get_lteconfig_status(headers):  
    api_url = '%s/connection/lte/config' % ENDPOINT

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)


def get_cnx_status(headers):
    api_url = '%s/connection/' % ENDPOINT

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
# -P => update pour avec POP
    api_url = '%s/switch/port/%s/stats/' % (ENDPOINT, port)

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

def get_wifi_stats(headers, num):
    api_url = '%s/wifi/ap/%s/stations' % (ENDPOINT, num)

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)

def get_wifi_statsx(headers):
    api_url = '%s/wifi/ap/' % (ENDPOINT)

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
   
def get_interfaces_hosts(headers, interf):
    api_url = '%s/lan/browser/%s/' % (ENDPOINT, interf)

    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)
        
def get_static_dhcp(headers):
    api_url = '%s/dhcp/static_lease/' % ENDPOINT
    r = requests.get(api_url, headers=headers)
    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)
        
def get_dynamic_dhcp(headers):
    api_url = '%s/dhcp/dynamic_lease/' % ENDPOINT
    r = requests.get(api_url, headers=headers)

    if r.status_code == 200:
        return r.json()
    else:
        print('Failed request: %s\n' % r.text)
        


def get_and_print_metrics(creds, s_switch, s_ports, s_sys, s_disk, s_lan, s_wifi, s_lan_interfaces, s_interfaces_hosts, s_static_dhcp, s_dynamic_dhcp, s_xdsl_tunnel):
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
    #Additionnal informations when state is down
    connection_media = ""
    if 'result' in json_raw:
            if 'state' in json_raw['result']:
                if json_raw['result']['state'] == 'down':
                    json_raw['result']['ipv4'] = 'None'
                    json_raw['result']['ipv6'] = 'None'
                    json_raw['result']['ipv4_port_range'] = [0,0]
                    connection_media = 'None'

    # fbx telegraf docker info
    tag1="python"
    tag2="version"
    tag3="NULL"
    my_data[tag1+"."+tag2+"."+tag3+"."+'version_script'] = VERSION
    tag2="fichier"
    my_data[tag1+"."+tag2+"."+tag3+"."+'nom_fichier'] = __file__
    tag2="derniere modification"
    # Convertir Timestamp en datetime
    update_date = datetime.fromtimestamp(get_creation_date(__file__))
    update_str = datetime.ctime(update_date)
    my_data[tag1+"."+tag2+"."+tag3+"."+'last_updated'] = update_str

    # Generic datas, same for FFTH or xDSL
    # ffth for FFTH (default)
    # xdsl for xDSL, with or without 4G
    if connection_media != 'None' :
        connection_media = json_raw['result']['media']


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
        my_data[tag1+"."+tag2+"."+tag3+"."+'media'] = connection_media
        my_data[tag1+"."+tag2+"."+tag3+"."+'ipv4'] = json_raw['result']['ipv4']
        my_data[tag1+"."+tag2+"."+tag3+"."+'ipv6'] = json_raw['result']['ipv6']

        tag2 = "ip_port_range"
        my_data[tag1+"."+tag2+"."+tag3+"."+'ipv4_port_range_low'] = json_raw['result']['ipv4_port_range'][0]
        my_data[tag1+"."+tag2+"."+tag3+"."+'ipv4_port_range_up'] = json_raw['result']['ipv4_port_range'][1]

        tag2 = "state"
        my_data[tag1+"."+tag2+"."+tag3+"."+'cnx_state'] = json_raw['result']['state']


    cnx_status = get_cnx_status(headers)


# FTTH specific
    if connection_media == "ftth":
        json_raw = get_ftth_status(headers)

        if 'result' in json_raw:  

            tag1="box"
            tag2="signal"
            tag3 = "NULL"
            my_data[tag1+"."+tag2+"."+tag3+"."+'sfp_has_signal'] = json_raw['result']['sfp_has_signal']  # BrW : cet attribu est bien présent: boolean 

# xDSL specific (galm : ajout condition state=up)
    if connection_media == "xdsl" and json_raw['result']['state'] == 'up':
        json_raw = get_xdsl_status(headers)

        tag1="box"
        tag2="xDSL"
        tag3 = "NULL"

        if 'result' in json_raw:

            my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_modulation'] = json_raw['result']['status']['modulation'] + " ("+json_raw['result']['status']['protocol']+")"  # in seconds

            my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_uptime'] = json_raw['result']['status']['uptime']  # in seconds

            my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_status_string'] = json_raw['result']['status']['status']
            if json_raw['result']['status']['status'] == "down":  # unsynchronized
                my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_status'] = 0
            elif json_raw['result']['status']['status'] == "training":  # synchronizing step 1/4
                my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_status'] = 1
            elif json_raw['result']['status']['status'] == "started":  # synchronizing step 2/4
                my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_status'] = 2
            elif json_raw['result']['status']['status'] == "chan_analysis":  # synchronizing step 3/4
                my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_status'] = 3
            elif json_raw['result']['status']['status'] == "msg_exchange":  # synchronizing step 4/4
                my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_status'] = 4
            elif json_raw['result']['status']['status'] == "showtime":  # ready
                my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_status'] = 5
            elif json_raw['result']['status']['status'] == "disabled":  # disabled
                my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_status'] = 6
            else:  # unknown
                my_data['xdsl_status'] = 999

            if 'es' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_es'] = json_raw['result']['down']['es']  # increment
            if 'attn' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_attn'] = json_raw['result']['down']['attn']  # in dB
            if 'snr' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_snr'] = json_raw['result']['down']['snr']  # in dB
            if 'rate' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_rate'] = json_raw['result']['down']['rate']  # ATM rate in kbit/s
            if 'hec' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_hec'] = json_raw['result']['down']['hec']  # increment
            if 'crc' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_crc'] = json_raw['result']['down']['crc']  # increment
            if 'ses' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_ses'] = json_raw['result']['down']['ses']  # increment
            if 'fec' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_fec'] = json_raw['result']['down']['fec']  # increment
            if 'maxrate' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_maxrate'] = json_raw['result']['down']['maxrate']  # ATM max rate in kbit/s
            if 'rtx_tx' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_rtx_tx'] = json_raw['result']['down']['rtx_tx']  # G.INP on/off
            if 'rtx_c' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_rtx_c'] = json_raw['result']['down']['rtx_c']  # G.INP corrected
            if 'rtx_uc' in json_raw['result']['down']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_down_rtx_uc'] = json_raw['result']['down']['rtx_uc']  # G.INP uncorrected
    
            if 'es' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_es'] = json_raw['result']['up']['es']
            if 'attn' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_attn'] = json_raw['result']['up']['attn']
            if 'snr' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_snr'] = json_raw['result']['up']['snr']
            if 'rate' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_rate'] = json_raw['result']['up']['rate']
            if 'hec' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_hec'] = json_raw['result']['up']['hec']
            if 'crc' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_crc'] = json_raw['result']['up']['crc']
            if 'ses' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_ses'] = json_raw['result']['up']['ses']
            if 'fec' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_fec'] = json_raw['result']['up']['fec']
            if 'maxrate' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_maxrate'] = json_raw['result']['up']['maxrate']
            if 'rtx_tx' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_rtx_tx'] = json_raw['result']['up']['rtx_tx']
            if 'rtx_c' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_rtx_c'] = json_raw['result']['up']['rtx_c']  # G.INP corrected
            if 'rtx_uc' in json_raw['result']['up']: my_data[tag1+"."+tag2+"."+tag3+"."+'xdsl_up_rtx_uc'] = json_raw['result']['up']['rtx_uc']  # G.INP uncorrected


# -4 4G lte xdsl tunnel
    if s_xdsl_tunnel and connection_media == "xdsl" :

        json_raw2 = get_lteconfig_status(headers)
        tag1="4G_lte"
        tag2="NULL"
        tag3="NULL"
        if 'result' in json_raw2: 

            if 'antenna' in json_raw2['result']: my_data[tag1+"."+tag2+"."+tag3+"."+'antenna_']=json_raw2['result']['antenna']
            if 'enabled' in json_raw2['result']: my_data[tag1+"."+tag2+"."+tag3+"."+'enabled_']=json_raw2['result']['enabled']
            if 'fsm_state' in json_raw2['result']: my_data[tag1+"."+tag2+"."+tag3+"."+'fsm_state_']=json_raw2['result']['fsm_state']
            if 'has_external_antennas' in json_raw2['result']: my_data[tag1+"."+tag2+"."+tag3+"."+'has_external_antennas_']=json_raw2['result']['has_external_antennas']
            if 'state' in json_raw2['result']: my_data[tag1+"."+tag2+"."+tag3+"."+'state']=json_raw2['result']['state']

            if 'network' in json_raw2['result']:
                tag2="network"
                if 'has_ipv4' in json_raw2['result']['network']: my_data[tag1+"."+tag2+"."+tag3+"."+'network_has_ipv4']=json_raw2['result']['network']['has_ipv4']
                if 'has_ipv6' in json_raw2['result']['network']: my_data[tag1+"."+tag2+"."+tag3+"."+'network_has_ipv6']=json_raw2['result']['network']['has_ipv6']
                if 'ipv4' in json_raw2['result']['network']: my_data[tag1+"."+tag2+"."+tag3+"."+'network_ipv4']=json_raw2['result']['network']['ipv4']
                if 'ipv4_dns' in json_raw2['result']['network']: my_data[tag1+"."+tag2+"."+tag3+"."+'network_ipv4_dns']=json_raw2['result']['network']['ipv4_dns']
                if 'ipv4_netmask' in json_raw2['result']['network']: my_data[tag1+"."+tag2+"."+tag3+"."+'network_ipv4_netmask']=json_raw2['result']['network']['ipv4_netmask']
                if 'ipv6' in json_raw2['result']['network']: my_data[tag1+"."+tag2+"."+tag3+"."+'network_ipv6']=json_raw2['result']['network']['ipv6']
                if 'ipv6_dns' in json_raw2['result']['network']: my_data[tag1+"."+tag2+"."+tag3+"."+'network_ipv6_dns']=json_raw2['result']['network']['ipv6_dns']
                if 'ipv6_netmask' in json_raw2['result']['network']: my_data[tag1+"."+tag2+"."+tag3+"."+'network_ipv6_netmask']=json_raw2['result']['network']['ipv6_netmask']
                if 'pdn_up' in json_raw2['result']['network']: my_data[tag1+"."+tag2+"."+tag3+"."+'network_pdn_up']=json_raw2['result']['network']['pdn_up']

            if 'radio' in json_raw2['result']: 
                tag2="radio"
                if 'associated' in json_raw2['result']['radio']: my_data[tag1+"."+tag2+"."+tag3+"."+'radio_associated']=json_raw2['result']['radio']['associated']
                if 'bands' in json_raw2['result']['radio']: # liste
                    l=len(json_raw2['result']['radio']['bands'])
                    i=0
                    while i<l:
                        tag3=("Band#%s" % i)
                        if 'band' in json_raw2['result']['radio']['bands'][i]: my_data[tag1+"."+tag2+"."+tag3+"."+'radio_bands_band']=json_raw2['result']['radio']['bands'][i]['band']
                        if 'bandwidth' in json_raw2['result']['radio']['bands'][i]: my_data[tag1+"."+tag2+"."+tag3+"."+'radio_bands_bandwidth']=json_raw2['result']['radio']['bands'][i]['bandwidth']
                        if 'enabled' in json_raw2['result']['radio']['bands'][i]: my_data[tag1+"."+tag2+"."+tag3+"."+'radio_bands_enabled']=json_raw2['result']['radio']['bands'][i]['enabled']
                        if 'pci' in json_raw2['result']['radio']['bands'][i]: my_data[tag1+"."+tag2+"."+tag3+"."+'radio_bands_pci']=json_raw2['result']['radio']['bands'][i]['pci']
                        if 'rsrp' in json_raw2['result']['radio']['bands'][i]: my_data[tag1+"."+tag2+"."+tag3+"."+'radio_bands_rsrp']=json_raw2['result']['radio']['bands'][i]['rsrp']
                        if 'rsrq' in json_raw2['result']['radio']['bands'][i]: my_data[tag1+"."+tag2+"."+tag3+"."+'radio_bands_rsrq']=json_raw2['result']['radio']['bands'][i]['rsrq']
                        if 'rssi' in json_raw2['result']['radio']['bands'][i]: my_data[tag1+"."+tag2+"."+tag3+"."+'radio_bands_rssi']=json_raw2['result']['radio']['bands'][i]['rssi']
                        i=i+1

            if 'sim' in json_raw2['result']:
                tag2="sim"
                tag3="NULL"
                if 'iccid' in json_raw2['result']['sim']: my_data[tag1+"."+tag2+"."+tag3+"."+'sim_iccid']=json_raw2['result']['sim']['iccid']
                if 'pin_locked' in json_raw2['result']['sim']: my_data[tag1+"."+tag2+"."+tag3+"."+'sim_pin_locked']=json_raw2['result']['sim']['pin_locked']
                if 'pin_remaining' in json_raw2['result']['sim']: my_data[tag1+"."+tag2+"."+tag3+"."+'sim_pin_remaining']=json_raw2['result']['sim']['pin_remaining']
                if 'present' in json_raw2['result']['sim']: my_data[tag1+"."+tag2+"."+tag3+"."+'sim_present']=json_raw2['result']['sim']['present']
                if 'puk_locked' in json_raw2['result']['sim']: my_data[tag1+"."+tag2+"."+tag3+"."+'sim_puk_locked']=json_raw2['result']['sim']['puk_locked']
                if 'puk_remaining' in json_raw2['result']['sim']: my_data[tag1+"."+tag2+"."+tag3+"."+'sim_puk_remaining']=json_raw2['result']['sim']['puk_remaining']

            if 'tunnel' in json_raw2['result']:
                tag2="tunnel"
                if 'lte' in json_raw2['result']['tunnel']:
                    tag3="lte"
                    if 'connected' in json_raw2['result']['tunnel']['lte']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_lte_connected']=json_raw2['result']['tunnel']['lte']['connected']
                    if 'last_error' in json_raw2['result']['tunnel']['lte']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_lte_last_error']=json_raw2['result']['tunnel']['lte']['last_error']
                    if 'rx_flows_rate' in json_raw2['result']['tunnel']['lte']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_lte_rx_flows_rate']=json_raw2['result']['tunnel']['lte']['rx_flows_rate']
                    if 'rx_max_rate' in json_raw2['result']['tunnel']['lte']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_lte_rx_max_rate']=json_raw2['result']['tunnel']['lte']['rx_max_rate']
                    if 'rx_used_rate' in json_raw2['result']['tunnel']['lte']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_lte_rx_used_rate']=json_raw2['result']['tunnel']['lte']['rx_used_rate']
                    if 'tx_flows_rate' in json_raw2['result']['tunnel']['lte']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_lte_tx_flows_rate']=json_raw2['result']['tunnel']['lte']['tx_flows_rate']
                    if 'tx_max_rate' in json_raw2['result']['tunnel']['lte']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_lte_tx_max_rate']=json_raw2['result']['tunnel']['lte']['tx_max_rate']
                    if 'tx_used_rate' in json_raw2['result']['tunnel']['lte']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_lte_tx_used_rate']=json_raw2['result']['tunnel']['lte']['tx_used_rate']
                if 'xdsl' in json_raw2['result']['tunnel']:
                    tag3="xdsl"
                    if 'connected' in json_raw2['result']['tunnel']['xdsl']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_xdsl_connected']=json_raw2['result']['tunnel']['xdsl']['connected']
                    if 'last_error' in json_raw2['result']['tunnel']['xdsl']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_xdsl_last_error']=json_raw2['result']['tunnel']['xdsl']['last_error']
                    if 'rx_flows_rate' in json_raw2['result']['tunnel']['xdsl']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_xdsl_rx_flows_rate']=json_raw2['result']['tunnel']['xdsl']['rx_flows_rate']
                    if 'rx_max_rate' in json_raw2['result']['tunnel']['xdsl']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_xdsl_rx_max_rate']=json_raw2['result']['tunnel']['xdsl']['rx_max_rate']
                    if 'rx_used_rate' in json_raw2['result']['tunnel']['xdsl']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_xdsl_rx_used_rate']=json_raw2['result']['tunnel']['xdsl']['rx_used_rate']
                    if 'tx_flows_rate' in json_raw2['result']['tunnel']['xdsl']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_xdsl_tx_flows_rate']=json_raw2['result']['tunnel']['xdsl']['tx_flows_rate']
                    if 'tx_max_rate' in json_raw2['result']['tunnel']['xdsl']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_xdsl_tx_max_rate']=json_raw2['result']['tunnel']['xdsl']['tx_max_rate']
                    if 'tx_used_rate' in json_raw2['result']['tunnel']['xdsl']: my_data[tag1+"."+tag2+"."+tag3+"."+'tunnel_xdsl_tx_used_rate']=json_raw2['result']['tunnel']['xdsl']['tx_used_rate']

# -Y static dhcp
    if s_static_dhcp:
        sys_json_raw = get_static_dhcp(headers)
        tag1="static"
        tag2="NULL"
        tag3="NULL"
        if 'result' in sys_json_raw:
            l=len(sys_json_raw['result'])
            i=0
            while i<l:
                tag2=("DHCP_S#%s" % i)
                tag3="NULL"
                if sys_json_raw['result'][i]['mac'] == sys_json_raw['result'][i]['hostname'] :
                    tag3=sys_json_raw['result'][i]['mac']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'mac']=tag3
                    my_data[tag1+"."+tag2+"."+tag3+"."+'comment']=sys_json_raw['result'][i]['comment']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'id']=sys_json_raw['result'][i]['id']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'ip_static']=sys_json_raw['result'][i]['ip']
                i=i+1

# -Z dynamic
    if s_dynamic_dhcp:
        sys_json_raw = get_dynamic_dhcp(headers)
        tag1="actif"
        tag2="NULL"
        tag3="NULL"
        if 'result' in sys_json_raw:
            l=len(sys_json_raw['result'])
            i=0
            while i<l:
                tag2=("DHCP_D#%s" % i)
                tag3="NULL"
                if sys_json_raw['result'][i]['mac'] == sys_json_raw['result'][i]['hostname'] :
                    tag3=sys_json_raw['result'][i]['mac']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'mac']=tag3
                    my_data[tag1+"."+tag2+"."+tag3+"."+'is_static']=sys_json_raw['result'][i]['is_static']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'ip_dyn']=sys_json_raw['result'][i]['ip']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'lease_remaining']=sys_json_raw['result'][i]['lease_remaining']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'assign_time']=sys_json_raw['result'][i]['assign_time']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'refresh_time']=sys_json_raw['result'][i]['refresh_time']
                i=i+1
        
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
# API V8

    if s_interfaces_hosts:
        # API V8
        # chercher la liste des interfaces
        sys_json_raw = get_lan_interfaces(headers) 

        if 'result' in sys_json_raw:
            l=len(sys_json_raw['result'])
            listeinterfaces=[]
            interf_objet = sys_json_raw['result']

            for intobject in interf_objet :
                listeinterfaces.append(intobject['name'])

            for interface in listeinterfaces :
                sys_json_raw = get_interfaces_hosts(headers, interface)
                if 'result' in sys_json_raw:
                    l=len(sys_json_raw['result'])
                    tag1="hosts_list"
                    k=0
                    while k<l :
                        tag2=interface
                        tag3="NULL"
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
# updated for V8
    if s_sys:
        sys_json_raw = get_system_config(headers)
        
        tag1="System"
        tag2="NULL"
        tag3="NULL"        

        if 'result' in sys_json_raw:
            if 'uptime_val' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'sys_uptime_val'] = sys_json_raw['result']['uptime_val']   # Uptime, in seconds
            if 'uptime' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'uptime'] = sys_json_raw['result']['uptime']           # uptime in readable format ?

            if 'firmware_version' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'firmware_version'] = sys_json_raw['result']['firmware_version']  # Firmware version  
            if 'board_name' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'board_name'] = sys_json_raw['result']['board_name']
            if 'disk_status' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'disk_status'] = sys_json_raw['result']['disk_status']
            if 'user_main_storage' in sys_json_raw['result']:my_data[tag1+"."+tag2+"."+tag3+"."+'user_main_storage'] = sys_json_raw['result']['user_main_storage']
            

            if 'mac' in sys_json_raw['result']:
                if 'model_info' in sys_json_raw['result']:
                    if 'has_ext_telephony' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'has_ext_telephony'] = sys_json_raw['result']['model_info']['has_ext_telephony']
                    if 'has_ext_telephony' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'has_ext_telephony'] = sys_json_raw['result']['model_info']['has_ext_telephony']
                    if 'has_speakers_jack' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'has_speakers_jack'] = sys_json_raw['result']['model_info']['has_speakers_jack']
                    if 'wifi_type' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'wifi_type'] = sys_json_raw['result']['model_info']['wifi_type']
                    if 'pretty_name' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'pretty_name'] = sys_json_raw['result']['model_info']['pretty_name']
                    if 'customer_hdd_slots' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'customer_hdd_slots'] = sys_json_raw['result']['model_info']['customer_hdd_slots']
                    if 'name' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'name'] = sys_json_raw['result']['model_info']['name']
                    if 'has_speakers' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'has_speakers'] = sys_json_raw['result']['model_info']['has_speakers']
                    if 'internal_hdd_size' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'internal_hdd_size'] = sys_json_raw['result']['model_info']['internal_hdd_size']
                    if 'has_femtocell_exp' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'has_femtocell_exp'] = sys_json_raw['result']['model_info']['has_femtocell_exp']
                    if 'has_internal_hdd' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'has_internal_hdd'] = sys_json_raw['result']['model_info']['has_internal_hdd']
                    if 'has_dect' in sys_json_raw['result']['model_info']:my_data[tag1+"."+tag2+"."+tag3+"."+'has_dect'] = sys_json_raw['result']['model_info']['has_dect']

            if 'fans' in sys_json_raw['result']: # c'est une liste
                i=1
                for fan_object in sys_json_raw['result']['fans']:
                    tag2 = "Fan"
                    my_data[tag1+"."+tag2+"."+tag3+"."+'id'] = fan_object['id']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'name'] = fan_object['name']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'value'] = fan_object['value']
                    i=i+1

            if 'sensors' in sys_json_raw['result']: # c'est une liste
                i=1
                for sensor_object in sys_json_raw['result']['sensors']:
                    tag2 = "Sensor"
                    tag3 = sensor_object['id']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'id'] = sensor_object['id']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'name'] = sensor_object['name']
                    my_data[tag1+"."+tag2+"."+tag3+"."+'value'] = sensor_object['value']
                    i=i+1
#
# option -S

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
                # Fbox POP : ?? pour port#3 2.5G  ??
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
# Switch ports status
    if s_ports:
                     
        tag1="Ports"
        tag2="NULL"
        tag3="NULL"

        switch_json_raw = get_switch_status(headers)
        listeid=[]
        if 'result' in switch_json_raw:
            for i in switch_json_raw['result']:
                listeid.append(i['id'])

        for i in listeid :  
            switch_port_stats = get_switch_port_stats(headers, i)
            tag1="Port#"+str(i)
            tag2="Rx"
            my_data[tag1+"."+tag2+"."+tag3+"."+'bytes_rate'] = switch_port_stats['result']['rx_bytes_rate']  # bytes/s (?)
#           my_data[tag1+"."+tag2+"."+tag3+"."+'bytes'] = switch_port_stats['result']['rx_bytes']            # pas de rx_bytes dans l'api !
            tag2="Tx"
            my_data[tag1+"."+tag2+"."+tag3+"."+'bytes_rate'] = switch_port_stats['result']['tx_bytes_rate']
            my_data[tag1+"."+tag2+"."+tag3+"."+'bytes'] = switch_port_stats['result']['tx_bytes']

#
# Option -D
# updated for V8 (liste de disque)
# Fetch internal disk stats
    if s_disk:
        json_raw = get_internal_disk_stats(headers)
        tag1="Disque"
        tag2="NULL"
        tag3="NULL"
        
        if json_raw['success'] :
            i=1
            if 'result' in json_raw:  # verifier la presence de 'result' car sur Fbox Mini4K pas de disque
                for disk_object in json_raw['result']:
                    tag2 = "dd-" + str(i)
                    if 'idle_duration' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'idle_duration'] = disk_object['idle_duration']
                    if 'read_error_requests' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'read_error_requests'] = disk_object['read_error_requests']
                    if 'read_requests' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'read_requests'] = disk_object['read_requests']
                    if 'spinning' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'spinning'] = disk_object['spinning']
                    if 'table_type' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'table_type'] = disk_object['table_type']
                    if 'firmware' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'firmware'] = disk_object['firmware']
                    if 'type' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'type'] = disk_object['type']
                    if 'idle' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'idle'] = disk_object['idle']
                    if 'connector' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'connector'] = disk_object['connector']
                    if 'id' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'dd_id'] = disk_object['id']
                    if 'write_error_requests' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'write_error_requests'] = disk_object['write_error_requests']
                    if 'state' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'state'] = disk_object['state']
                    if 'write_requests' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'write_requests'] = disk_object['write_requests']
                    if 'total_bytes' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'total_bytes'] = disk_object['total_bytes']
                    if 'model' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'model'] = disk_object['model']
                    if 'active_duration' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'active_duration'] = disk_object['active_duration']
                    if 'temp' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'temp'] = disk_object['temp']
                    if 'serial' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'serial'] = disk_object['serial']
                    if 'id' in disk_object:my_data[tag1+"."+tag2+"."+tag3+"."+'disk_id'] = disk_object['id']
                # partitions :
                #
                    if disk_object['partitions'] :
                       j=1
                       for partition in disk_object['partitions'] :
                           tag3="Part-"+str(j)
                           my_data[tag1+"."+tag2+"."+tag3+"."+'partition#'] = j
                           if 'fstype' in partition : my_data[tag1+"."+tag2+"."+tag3+"."+'fstype'] = partition['fstype']
                           if 'disk_id' in partition : my_data[tag1+"."+tag2+"."+tag3+"."+'part_disk_id'] = partition['disk_id']
                           if 'total_bytes' in partition : my_data[tag1+"."+tag2+"."+tag3+"."+'total_bytes'] = partition['total_bytes']
                           if 'free_bytes' in partition : my_data[tag1+"."+tag2+"."+tag3+"."+'free_bytes'] = partition['free_bytes']
                           if 'used_bytes' in partition : my_data[tag1+"."+tag2+"."+tag3+"."+'used_bytes'] = partition['used_bytes']
                           if 'label' in partition : my_data[tag1+"."+tag2+"."+tag3+"."+'label'] = partition['label']
                           if 'id' in partition : my_data[tag1+"."+tag2+"."+tag3+"."+'part_id'] = partition['id']
                           if 'disk_id' in partition : my_data[tag1+"."+tag2+"."+tag3+"."+'part_disk_id'] = partition['disk_id']
                       
                           j=j+1
                    i=i+1
#
# Option -W
# update for V8, prise en compte de la liste des AP.
# Wifi stats
#
    if s_wifi:
        
        sys_json_raw1 = get_wifi_statsx(headers)
        if sys_json_raw1['success'] :
            apwifilist = sys_json_raw1['result']
            for ap in apwifilist : 
                sys_json_raw = get_wifi_stats(headers, ap['id'])
                if 'result' in sys_json_raw:        
                    l=len(sys_json_raw['result'])
                    tag1="wifi_list"
                    tag2=ap['name']
                    # verifier qu'il n'y a pas de "." dans tag2 ! on les supprime
                    j=0
                    tagtemp = list(tag2)
                    while  j < len(tagtemp):    
                        if tagtemp[j] == ".": 
                            tagtemp[j] = ""
                        j=j+1 
                    tag2 = "".join(tagtemp)    
                    tag3="NULL" 
                    k=0

                    while k<l :
                       if 'mac' in sys_json_raw['result'][k]:
                          tag3=sys_json_raw['result'][k]['mac']
                          if 'host' in sys_json_raw['result'][k]:
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
                                                        # tx/rx bytes
                                                             my_data[tag1+"."+tag2+"."+tag3+"."+'rx_bytes']=sys_json_raw['result'][k]['rx_bytes']
                                                             my_data[tag1+"."+tag2+"."+tag3+"."+'rx_rate']=sys_json_raw['result'][k]['rx_rate']
                                                             my_data[tag1+"."+tag2+"."+tag3+"."+'tx_bytes']=sys_json_raw['result'][k]['tx_bytes']
                                                             my_data[tag1+"."+tag2+"."+tag3+"."+'tx_rate']=sys_json_raw['result'][k]['tx_rate']
                                                             lasttimeactivity=sys_json_raw['result'][k]['host']['l3connectivities'][m]['last_activity']
                                                             date_last_activity=datetime.fromtimestamp(lasttimeactivity)
                                                             my_data[tag1+"."+tag2+"."+tag3+"."+'last_activity_date']=date_last_activity.strftime("%c")
                                                             my_data[tag1+"."+tag2+"."+tag3+"."+'AP_ref']=ap['id']
                                                         m=m+1   
                       k=k+1
    
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
# je rajoute la suppression des accents
                my_data[i] = unidecode(my_data[i])
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
#    with open(cfg_file, "ab") as authFile:
    with open(cfg_file, "a") as authFile:
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
    parser.add_argument('-r', '--register', action='store_true', help="Register app with Freebox API")

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

    parser.add_argument('-Y', '--static-dhcp',
                        dest='static_dhcp',
                        action='store_true',
                        help="Get and show static dhcp")
                        
    parser.add_argument('-Z', '--dynamic-dhcp',
                        dest='dynamic_dhcp',
                        action='store_true',
                        help="Get and show dynamic dhcp")
                        
    parser.add_argument('-4', '--xdsl_tunnel',
                        dest='xdsl_tunnel',
                        action='store_true',
                        help="Get and show 4G/lte xdsl aggregation counters")
                        
    args = parser.parse_args()

    if args.app_id is not None:
      app_id=args.app_id

    if args.app_name is not None:
      app_name=args.app_name

    if args.device_name is not None:
      device_name=args.device_name

    ENDPOINT="http://"+args.Endpoint+"/api/v8/"
    auth = get_auth()

    if args.register:
        do_register(auth)
    elif args.status:
        register_status(auth)
    else:     
        get_and_print_metrics(auth, args.status_switch, args.status_ports, args.status_sys, args.disk_usage, args.lan_config, args.wifi_usage, args.lan_interfaces, args.interfaces_hosts, args.static_dhcp, args.dynamic_dhcp, args.xdsl_tunnel)
