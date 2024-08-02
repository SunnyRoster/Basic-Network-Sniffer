from scapy.all import *
interface= 'wlane' 
probeReqs = []

def sniffProves (p):
   if p.haslayer (Dot11ProbeReq):
      netName= p.getlayer (Dot11ProbeReq).info
      if netName not in probeReqs:
         probeReqs.append(netName)
         print('[+] Detected New Probe Request: +netN.
               
sniff (iface-interface, prn=sniff Proves)
