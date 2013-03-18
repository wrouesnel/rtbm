#! /usr/bin/env python
# -*- coding: utf-8 -*-
#/*
# *  This file is part of RTBM, Real-Time Bandwidth Monitor.
# *
# *  RTBM, Real-Time Bandwidth Monitor is free software: you can redistribute it and/or modify
# *  it under the terms of the GNU General Public License as published by
# *  the Free Software Foundation, either version 3 of the License, or
# *  (at your option) any later version.
# *
# *  RTBM, Real-Time Bandwidth Monitor is distributed in the hope that it will be useful,
# *  but WITHOUT ANY WARRANTY; without even the implied warranty of
# *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# *  GNU General Public License for more details.
# *
# *  You should have received a copy of the GNU General Public License
# *  along with RTBM, Real-Time Bandwidth Monitor.  If not, see <http://www.gnu.org/licenses/>.
# */

# Will's modified version of RTBM. Stripped out the "intelligent" parts to
# take advantage of that nice HTML5 canvas graph on the frontend. Also disabled
# the notifications system (we don't use it).
#
# Future improvements: let the daemon pipe to a WSGI process which serves
# stats.json on request rather then constantly writing to a file.

"""
"""

import pcap
import getopt, sys
import socket
import struct
import time
import threading
import thread
import copy
import cjson
import fcntl
import math
import signal
import os
import ConfigParser

import logging
from logging import debug, info, warning, error

import netifaces

# Built-in HTTP server
import SocketServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

import collections

protocols={socket.IPPROTO_ICMP:'icmp',
    socket.IPPROTO_TCP:'tcp',
    socket.IPPROTO_UDP:'udp'}

BIDIRECTIONAL, INCOMING, OUTGOING = range(3)

class PacketDetails:
    def __init__(self, address, size):
        self.address = address
        self.size = size

    def getAddress(self):
        return self.address

    def getSize(self):
        return self.size

    def __str__(self):
        return '%s : %s' % (self.address, self.size)

class PacketCounter:
    """A thread-safe wrapper of an underlying collections.Counter object"""
    def __init__(self):
        self.lock=thread.allocate_lock()
        self.counter = collections.Counter()
        self.aggregate=0
    def addPacket(self, packetDetails):
        self.lock.acquire()
        if self.counter.has_key(packetDetails.getAddress()):
            self.counter[packetDetails.getAddress()] += packetDetails.getSize()
        else:
            self.counter[packetDetails.getAddress()] = packetDetails.getSize()
        self.aggregate += packetDetails.getSize()
        self.lock.release()
    """Returns the internal data members of the counter (the counter object and aggregated size)"""
    def getCounter(self):
        self.lock.acquire()
        counter_copy = self.counter
        aggregate_copy = self.aggregate
        self.counter=collections.Counter()
        self.aggregate=0
        self.lock.release()
        return (counter_copy, aggregate_copy)
    """Direct merge the given PC's counter and stats into our one in an additive way
    This is the same as getCounter, but resets the counter we merge from"""
    def mergeAndResetCounter(self, otherPacketCounter):
        self.lock.acquire()
        otherPacketCounter.lock.acquire()
        
        # Merge other counter to this one
        self.counter.update(otherPacketCounter.counter)    
        self.aggregate += otherPacketCounter.aggregate
        
        # Clear other counter state
        otherPacketCounter.aggregate=0
        otherPacketCounter.counter.clear()
        
        otherPacketCounter.lock.release()
        self.lock.release()
    def __str__(self):
        return str(self.counter)

#TODO: Add ports information:
#def decode_tcp_udp_packet(pkt,d):
    #d['source_port']=socket.ntohs(struct.unpack('H',pkt[0:2])[0])
    #d['destination_port']=socket.ntohs(struct.unpack('H',pkt[2:4])[0])

def decode_ip_packet(d,s):
    d['src']=socket.inet_ntoa(s[12:16])
    d['dst']=socket.inet_ntoa(s[16:20])
    return d

def is_addressed_to_here(dst):
    for addr,netmask in local_addresses:
        if (dst == addr) or (~netmask & dst == (0xFFFFFFFF & ~netmask)):
            return True
    return False

class StoppableThread(threading.Thread):
    """ Thread that can be stopped. Thread must check regularly if it should
    stop"""
    def __init__(self):
        super(StoppableThread, self).__init__()
        self._stop = threading.Event()
    
    def stop(self):
        self._stop.set()
    
    def stopped(self):
        return self._stop.isSet()    

class Capture( StoppableThread ):
    def __init__( self, iface ):
        super(Capture, self).__init__()
        self.pc = pcap.pcap(iface, 65535, False)
        #self.pc.setdirection(direction);
        self.pc.setfilter("proto 6 or 17")
        self.incomingcounter = PacketCounter()
        self.outgoingcounter = PacketCounter()

    def run( self ):
        for ts, pkt in self.pc:
            if self._stop.isSet():
                break
            if pkt is not None:
                global ignore_local_machine
                global local_subnets
                global local_addresses
                global broadcast_addresses
                global show_subnet_usage_only
                
                # Get the src and destination IP addresses as ints
                src = struct.unpack("!I", (pkt[14:])[12:16])[0]
                dst = struct.unpack("!I", (pkt[14:])[16:20])[0]
                
                # ignore-local-machine == true ?
                # ignore packets destined for this machine (this will internet traffic pre-natting, and traffic
                # destined for this machine).
                if ignore_local_machine:
                    if is_addressed_to_here(dst):
                        continue
                
                # determine packet direction
                # true = outbound
                # false = inbound
                direction = False
                for addr,subnet in local_subnets:
                    if (addr & subnet) == (src & subnet):
                        direction = True
                
                # We need to decode the packet now before sticking it in a counter
                d={}
                d['size']=len(pkt) #length of packet as captured, in bytes
                decoded=decode_ip_packet(d, pkt[14:])
                
                if direction:
                    self.outgoingcounter.addPacket(PacketDetails(decoded['src'], decoded['size']))
                else:
                    self.incomingcounter.addPacket(PacketDetails(decoded['dst'], decoded['size']))
    
    def getStats( self ):
        return self.pc.stats()

class Report( StoppableThread ):
    def __init__( self ):
        super(Report, self).__init__()

    def run( self ):
        global cycle_time
        global ifaces

        # Setup all the PacketCounters here
        for k in ifaces:
            ifaces[k] = Capture(k)
            ifaces[k].start()

        while True:
            # Setup some master counters (we merge the other counters into these)
            # TODO: should these be persisted?
            icounterMaster = PacketCounter()
            ocounterMaster = PacketCounter()
            
            # Initialize packet count aggregators
            nrecv = 0
            ndrop = 0
            nifdrop = 0
            
            # Sum all the individual counters into the master counters
            for v in ifaces.values():
                # Merge the counter copies
                icounterMaster.mergeAndResetCounter(v.incomingcounter)
                ocounterMaster.mergeAndResetCounter(v.outgoingcounter)
                # aggregate getstats from the different interfaces
                a, b, c = v.getStats()
                nrecv += a
                ndrop += b
                nifdrop += c
            
            # TODO: separate out the return data per interface, have front end plot it
            # properly
            f = open(stat_file, mode='w')
            response={}
            #nrecv, ndrop, nifdrop = (0,0,0) #incoming.getStats()
            response['nifdrop'] = nifdrop
            response['ndrop'] = ndrop
            response['nrecv'] = nrecv
            #nrecv, ndrop, nifdrop = (0,0,0) #outgoing.getStats()
            response['nifdrop'] += nifdrop
            response['ndrop'] += ndrop
            response['nrecv'] += nrecv
            response['time'] = time.time()
            response['outgoing'] = ocounterMaster.counter
            response['incoming'] = icounterMaster.counter
            response['iface'] = " ".join(ifaces.keys())
            f.write(cjson.encode(response))
            f.close()        
            if self._stop.isSet():
                break
            time.sleep(cycle_time)

def usage():
    print 'Usage: ' + sys.argv[0] + \
    " --config-file=<path to the file that holds the configuration for rtbm> \n" + \
    "--pid-file=<the file that will be used to hold the process id of the service> \n" + \
    "--self-server=<port to start the internal webserver on>\n"

class InternalHttpServerHandler(SimpleHTTPRequestHandler):
    """Handler class for the internal http server which implements the post
    method so we can use AJAX requests"""
    def do_GET(self):
        SimpleHTTPRequestHandler.do_GET(self)
        
    def do_POST(self):
        SimpleHTTPRequestHandler.do_GET(self)

    def log_request(self, message):
        return

def main(argv):
    global pid_file
    pid_file = None
    global config_file
    config_file = None
    try:
        opts, args = getopt.getopt(argv, "c:p:s:hd", ["config-file=", "pid-file=", "self-serve=", "help", "debug"])
    except getopt.GetoptError:
        usage()
        sys.exit(-1)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-p", "--pid-file"):
            pid_file = arg
        elif opt in ("-c", "--config-file"):
            config_file = arg
        elif opt in ("-s", "--self-serve"):
            http_port = int(arg)
        elif opt in ("-d", "--debug"):
            logging.basicConfig(level=logging.DEBUG)

    debug("pid_file: %s", pid_file)
    debug("config_file: %s", config_file)
    debug("http_port: %s", http_port)

    if config_file is None or pid_file is None:
        usage()
        sys.exit(-1)

    config = ConfigParser.RawConfigParser()
    config.read(config_file)

    global stat_file
    global cycle_time
    global ifaces
    global local_subnets
    global ignore_local_machine
    global show_subnet_usage_only
    global local_addresses
    global broadcast_addresses
    
    local_subnets = []
    local_addresses = []
    broadcast_addresses = []
    ignore_local_machine = False
    show_subnet_usage_only = False

    # Read configs
    stat_file = config.get("general", "stat_file")
    cycle_time = float(config.get("general", "cycle_time"))
    www_dir = config.get("general", "www_dir")    
    ignore_local_machine = config.getboolean("general", "ignore-local-machine")
    show_subnet_usage_only = config.getboolean("general", "show-subnet-usage-only")
    
    for net in config.get("general", "local-subnets").split(' '):
        addr = struct.unpack("!I", socket.inet_aton(net.split('/')[0]))[0]
        netmask = struct.unpack("!I", socket.inet_aton(net.split('/')[1]))[0] 
        local_subnets.append( (addr,netmask) )

    info("stat_file: %s", stat_file)
    info("cycle_time: %s", cycle_time)
    info("www_dir: %s", www_dir)
    info("ignore-local-machine: %s", ignore_local_machine)
    info("show-subnet-usage-only: %s", show_subnet_usage_only)
    info("local subnets %s" % (local_subnets,))

    # get a list of local ip addresses we need to ignore (include broadcast addresses)
    for loif in netifaces.interfaces():
        addresses = netifaces.ifaddresses(loif)
        if netifaces.AF_INET not in addresses:
            continue
        # TODO: IPv6 support maybe?
        for address in addresses[netifaces.AF_INET]:
            if "addr" in address:
                addr = struct.unpack("!I", socket.inet_aton(address["addr"]))[0]
                netmask = struct.unpack("!I", socket.inet_aton(address["netmask"]))[0]
                local_addresses.append( (addr, netmask) )

    debug("detected local addresses: %s" % (local_addresses,) )
    debug("detected broadcast addresses: %s" % (broadcast_addresses) )

    # Initialize the dictionary of interface monitoring threads
    # Dictionary is key = iface, tuple Capture-obj, incoming counter, outgoing counter
    ifaces = dict((iface, None) for iface in config.get("general", "iface").split(' '))

    debug("iface capture threads spawned: %s" % (ifaces.keys(),) )

    f = open(pid_file, mode='w')
    f.write(str(os.getpid()))
    f.close()
    
    # Start the capture/reporting thread
    report = Report()
    report.start()

    info("report thread started")

    # Wait for http_server in main thread, else wait for report thread to end
    http_server = None
    try:
        if http_port is not None:
            os.chdir(www_dir)  # set current dir to web root
            Handler = InternalHttpServerHandler
            http_server = SocketServer.TCPServer(("", http_port), Handler)
            info("serving on port %i" % (http_port,))
            
            http_server.serve_forever()
        else:
            while threading.activeCount() > 1:
                time.sleep(1)                
    except KeyboardInterrupt:
        print "Interrupted, stopping threads."
        pass
    finally:
        if http_server:
            http_server.server_close()
        report.stop()
        report.join()

if __name__ == '__main__':
    main(sys.argv[1:])
