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

import SocketServer
from SimpleHTTPServer import SimpleHTTPRequestHandler

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

class Counter:
    def __init__(self):
        self.lock=thread.allocate_lock()
        self.counter={}
        self.aggregate=0
    def addPacket(self, packetDetails):
        self.lock.acquire()
        if self.counter.has_key(packetDetails.getAddress()):
            self.counter[packetDetails.getAddress()] += packetDetails.getSize()
        else:
            self.counter[packetDetails.getAddress()] = packetDetails.getSize()
        self.aggregate += packetDetails.getSize()
        self.lock.release()
    def getCounter(self):
        self.lock.acquire()
        counter_copy = self.counter
        aggregate_copy = self.aggregate
        self.counter={}
        self.aggregate=0
        self.lock.release()
        return (counter_copy, aggregate_copy)
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
    def __init__( self, direction ):
        super(Capture, self).__init__()
        self.direction = direction
        self.pc = pcap.pcap(iface, 65535, False)
        #self.pc.setdirection(direction);
        self.pc.setfilter("proto 6 or 17")
        self.counter = Counter()

    def run( self ):
        for ts, pkt in self.pc:
            if self._stop.isSet():
                break
            if pkt is not None:
                d={}
                d['size']=len(pkt) #length of packet as captured, in bytes
                #print d['size']
                decoded=decode_ip_packet(d, pkt[14:])
                # Assuming this is a TCP/UDP packet, from the filter.
                #decode_tcp_udp_packet(pkt[4*decoded['header_len']+14:(4*decoded['header_len'])+4+14], decoded)
                if self.direction == INCOMING:
                    self.counter.addPacket(PacketDetails(decoded['src'], decoded['size']))
                elif self.direction == OUTGOING:
                    self.counter.addPacket(PacketDetails(decoded['dst'], decoded['size']))
    
    def getStats( self ):
        return self.pc.stats()

class Report( StoppableThread ):
    def __init__( self ):
        super(Report, self).__init__()

    def run( self ):
        global cycle_time
        incoming = Capture(INCOMING)
        incoming.start()
        outgoing = Capture(OUTGOING)
        outgoing.start()
        
        while True:
            (icounter, iaggregated)=incoming.counter.getCounter()
            (ocounter, oaggregated)=outgoing.counter.getCounter()
            f = open(stat_file, mode='w')
            response={}
            nrecv, ndrop, nifdrop = incoming.getStats()
            response['nifdrop'] = nifdrop
            response['ndrop'] = ndrop
            response['nrecv'] = nrecv
            nrecv, ndrop, nifdrop = outgoing.getStats()
            response['nifdrop'] += nifdrop
            response['ndrop'] += ndrop
            response['nrecv'] += nrecv
            response['time'] = time.time()
            response['outgoing'] = ocounter
            response['incoming'] = icounter
            response['iface'] = iface
            f.write(cjson.encode(response))
            f.close()
                
            if self._stop.isSet():
                incoming.stop()
                outgoing.stop()
                incoming.join()
                outgoing.join()
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

def main(argv):
    global pid_file
    pid_file = None
    global config_file
    config_file = None
    try:
        opts, args = getopt.getopt(argv, "c:p:s:h", ["config-file=", "pid-file=", "self-serve=", "help"])
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

    if config_file is None or pid_file is None:
        usage()
        sys.exit(-1)

    config = ConfigParser.RawConfigParser()
    config.read(config_file)

    global stat_file
    global cycle_time
    global iface
    stat_file = config.get("general", "stat_file")
    iface = config.get("general", "iface")
    cycle_time = float(config.get("general", "cycle_time"))
    www_dir = config.get("general", "www_dir")

    f = open(pid_file, mode='w')
    f.write(str(os.getpid()))
    f.close()
    
    # Start the capture/reporting thread
    report = Report()
    report.start()

    # Wait for http_server in main thread, else wait for report thread to end
    http_server = None
    try:
        if http_port is not None:
            os.chdir(www_dir)  # set current dir to web root
            Handler = InternalHttpServerHandler
            http_server = SocketServer.TCPServer(("", http_port), Handler)
            print "serving on port %i" % (http_port,)
            
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
