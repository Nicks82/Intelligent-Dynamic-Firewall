
from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.revent import *
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr
import pox.lib.packet as pkt
from collections import namedtuple

import os
import time

log = core.getLogger()

class Firewall (EventMixin):
	def __init__ (self):
		self.listenTo(core.openflow)
		log.debug("Enabling Firewall Module")

def _handle_flowstats_received (event):
	for f in event.stats:
		if f.packet_count >= 20:
			#Controller asks the switch to add a flow for packet count greater than 20
			deleteVar = of.ofp_flow_mod()
			deleteVar.match = of.ofp_match()
			deleteVar.command=of.OFPFC_DELETE
			#Sends flow mod for flow                                        
			event.connection.send(deleteVar)
			#refuses the flow mod  
			refuseVar = of.ofp_flow_mod()
			refuseVar.match.dl_src = f.match.dl_src                                          
			refuseVar.hard_timeout = 5
			#Sends flow mod for refusing connection
			event.connection.send(refuseVar)
			log.debug("Firewall rules installed on %s", dpidToStr(event.dpid))
			

def timer_func ():
	'''
	This is the Timer Function. It gets the stats
	'''

	for connection in core.openflow._connections.values():
		connection.send(of.ofp_stats_request(body=of.ofp_flow_stats_request()))
	log.debug("Sent %i flow/port stats request(s)", len(core.openflow._connections))


def launch ():
	'''
	Starting the Firewall module
	'''
	from pox.lib.recoco import Timer
	core.registerNew(Firewall)

	core.openflow.addListenerByName("FlowStatsReceived", _handle_flowstats_received)	#Adds listener for flow stats received
	Timer(1, timer_func, recurring =True)	#Sets timer to check flow stats every 1 second
