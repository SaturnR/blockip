#!/usr/bin/env python3

import os
import json
import datetime as dt
import time

# cat iptable_ref
# block specific ip
# iptables -I INPUT -s 116.31.116.50 -j DROP
# view blocked ips
# iptables -L -v

# read blocked ips
blockips = {}

with open('/var/log/auth.log', 'r') as f:
    for line in f:
        sp = line.split('.')
        if(len(sp) > 3):
            try:
                stime = sp[0].split('gmapfish')[0].strip()
                tm = time.strptime(stime+' '+str(time.localtime().tm_year), '%b %d %X %Y')
                ip1 = int(sp[0][-3:].strip('='))
                ip2 = int(sp[1])
                ip3 = int(sp[2])
                ip4 = int(sp[3][:3].strip(':'))
            except ValueError as ve:
                print(ve)
            else:
                #print(tm, ip1, ip2, ip3, ip4)
                ip = '{}.{}.{}.{}'.format(ip1, ip2, ip3, ip4)
                if(ip in blockips):
                    blockips[ip] += 1
                else:
                    blockips[ip] = 1
                
                        
for n in blockips:
    print(blockips[n], ' --- ', n)                    
    if(blockips[n] > 100):
        #os.popen('iptables -I INPUT -s 116.31.116.50 -j DROP')
        print('---black listed---')
        
