# The main python script for the DNS proxy ad/malware/adult site filter
# an attempt to reduce network traffic, bandwidth and load time
# requires a block list file with a listing domains to block
# and a whitelisting file of string to allow in URLs


from multiprocessing import Process, Manager, Lock, Value
import multiprocessing
import socket

import configparser
import traceback
import timeit
import time
from dnslib import *
import sys
import re

REGEXLIST = ""
WHITELIST = ""

#a pair of host and count blocked. Initially it stays 0
BlockListDict = {'initialval':'initial'}

CilentMutex = Lock()
ServerMutex = Lock()

#Globals
PrintSummary = False

#function to open file and add contents
def addToFile(filename, data):
    target = open(filename, 'a')
    target.write(data)
    target.write("\n")
    target.close()

def readFile(filename):
    target = open(filename, 'r')
    data = target.read()
    target.close()
    return data

#function to load block list into dictionary
def loadBlockList(filename):
    i = 0
    data = readFile(filename)
    data = filter(None, data.split('\n'))
    for line in data:
        BlockListDict[line] = 0
        i = i + 1
    print(f"Loaded {str(i)} urls to block ")


#function to load domains to whitelist
def loadWhiteList(filename):
    global WHITELIST
    WHITELIST = readFile(filename)
    WHITELIST = filter(None, WHITELIST.split('\n'))
    print("Loaded White List")

#function to check if the host needs to be blocked
def isBlocked(host):
    if host.startswith("www."):
        host = host.replace("www.", "")
    
    #checking the cache for faster results
    if (checkCache(host)):
        if(checkWhiteList(host)):
            return False
        return True
    if(checkRegEx(host)):
        if(checkWhiteList(host)):
            return False
        return True
    return False


#function returns true if host contains a string match. We dont want to
#block those URLs
def checkWhiteList(host):
    for line in WHITELIST:
        if line in host:
            print(f"White List {line} matches {host} ")
            return True
    return False


# Check if it matches a regex
# if so, enter it into the block list
def checkRegEx(host):
    if re.match(REGEXLIST, host):
        print(f"Blocking Regex {host} ")
        BlockListDict[host] = 0
        addToFile("regexblock", host)
        return True
    return False

#function to check the host
def checkCache(host):
    #how far did we go
    ittr = host.count('.')
    if ittr > 10: # more than 10 dots in the request address, it will fail
        return True
    while ittr > 10:
        if BlockListDict.get(host) is not None:
            return True
        
        temp, host = host.split('.', 1)
        ittr = ittr - 1

    return False

#Craft the packet to send the UDP response of failure and send
def sendFailedLookup(s, datagram, addr):
    #temp = datagram.find('\x00', 12)
    temp = datagram.hex().find('\x00', 12)
    packet=datagram[:2] + b'\x81\x83' + datagram[4:6] +  b'\x00\x00\x00\x00\x00\x00' + datagram[12:temp+5]
    s.sendto(packet, addr)


# function to hanlde incoming DNS requests from clients
# first do the filter thing and route back to actual DNS

def handleClientSocket(client_socket, dns_socket, pending_requests_dict, blocked_urls, served_urls, counter_lock):
    totaltime = 0
    totaltrans = 0

    loadBlockList("blocklist")
    loadWhiteList("whitelist")

    clientmutex = CilentMutex

    status = ''

    while True:
        clientmutex.acquire()
        try:
            datagram, addr = client_socket.recvfrom(1024)
            starttime = timeit.default_timer()
            #release the mutex once you got the response
            clientmutex.release()
            host = str(DNSRecord.parse(datagram).q.qname)[0:-1]
            if (isBlocked(host)):
                printstring = "Blocked URL " + host
                sendFailedLookup(client_socket, datagram, addr)

                if PrintSummary:
                    with counter_lock:  # costly operation
                        blocked_urls.value += 1
            
            else:
                # unblocked packet send to the configured DNS server
                sent = dns_socket.send(datagram)
                printstring = "Served URL  " + host
                lookupval = datagram[0:2].hex() + host
                lookupvalip = lookupval + ":ip"
                lookupvalport = lookupval + ":port"
                ipport = addr[0] + "::" + str(addr[1])

                pending_requests_dict[lookupval] = ipport
                if PrintSummary:
                    with counter_lock:
                        served_urls.value += 1


            transactiontime = timeit.default_timer() - starttime
            print(f"{printstring} for {addr[0]} with transcation time of {transactiontime}")
        except Exception as e:
            print("Bad ERROR!!!", e, type(datagram))
            traceback.print_exc()

    clientmutex.release()
    return



def handleDNSSocket(client_socket, dns_socket, pending_requests_dict):

    servermutex = ServerMutex

    while True:
        #get mutex to process the DNS result
        servermutex.acquire()
        current = multiprocessing.current_process()

        try:
            #overkill the buffer size for DNS
            datagram, addr = dns_socket.recvfrom(1024)
        except Exception as e:
            servermutex.release()
            print("SYSTEM ERROR caught on handleDNSSocket.dns_socket.recvfrom ",e)
        else:
            # After getting data from the DNS socket, release mutex so others clinets can get DNS packets
            servermutex.release()
            # Get the DNS info
            host = str(DNSRecord.parse(datagram).q.qname)[0:-1]
            lookupval = datagram[0:2].hex() + host
            lookupvalip = lookupval + ":ip"
            lookupvalport = lookupval + ":port"

            returnaddr = pending_requests_dict.get(lookupval)
            if returnaddr is None:
                print("SYSTEM ERROR!!! No dict entry for ADDR", lookupval)
            else:
                try:
                    returnaddr = returnaddr.split('::')
                    addr = returnaddr[0], int(returnaddr[1])
                    client_socket.sendto(datagram, addr)
                    del pending_requests_dict[lookupval]
                except Exception as e:
                    del pending_requests_dict[lookupval]
                    print("SYSTEM ERROR. caught around handleDNSSocket.client_socket.sendto  ", e)

    servermutex.release()
    return  


def printStats(blocked_urls, served_urls):
    print(f'Served {str(served_urls)}  URLS, Blocked {str(blocked_urls)} attempts so far..')


# Main Function
if __name__ == "__main__":

    config = configparser.ConfigParser()
    config.read('config')
    # What IP Address to bind to
    listen_address = config.get('config', 'LOCALADDR').split(',', 1)
    # DNS server to use if a request isnt found
    target_address = config.get('config', 'TARGETDNS').split(',', 1)

    #handling threads
    client_proc_count = config.getint('config', 'INPROC')
    dns_proc_count = config.getint('config', 'OUTPROC')

    if (client_proc_count < 2) or (client_proc_count > 10):
        client_proc_count = 2
    if (dns_proc_count < 1) or (dns_proc_count > 5):
        dns_proc_count = 1

    print(f'{client_proc_count} {dns_proc_count}')
    #print(client_proc_count + " " + dns_proc_count)

    if 'True' in config.get('reporting', 'SUMMARY'):
        PrintSummary = True

    REGEXLIST = config.get('regex', 'REGEXLIST')

    # set up sync items for multi processes
    mgr = Manager()
    pending = mgr.dict()
    blocked_urls = Value('i', 0)
    served_urls = Value('i', 0)
    counter_lock = Lock()


    # make socket connections
    target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    target.connect((target_address[0], int(target_address[1])))
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        client.bind((listen_address[0], int(listen_address[1])))
    except Exception as e:
        print('Could not bind on server...')
        time.sleep(1)
        raise SystemExit

	# Launching processes results in a system running much faster than threads but need to clean up the launcher
    for i in range(0,client_proc_count):
	    process = Process(target=handleClientSocket, args=(client, target, pending, blocked_urls, served_urls, counter_lock))
	    process.start()

    for i in range(0, dns_proc_count):
        process = Process(target=handleDNSSocket, args=(client, target, pending))
        process.start()

    while True:
        if PrintSummary:
            printStats(blocked_urls.value, served_urls.value)
        time.sleep(30)

    print('Done')
