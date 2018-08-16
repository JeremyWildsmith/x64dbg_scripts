from x64dbgpy.pluginsdk import *
import x64dbgpy
import distorm3
import struct
import time
import math

def mergeSection(address, size, num):
    x64dbg._plugin_logputs("Start: " + hex(address))
    bufferSet = []

    alignment = int(0x10000 * math.ceil(float(size) / 0x10000))
    
    x64dbg._plugin_logputs("End: " + hex(address + alignment * num))

    for x in range(0, num):
        addr = address + x * alignment
        bufferSet.append(Read(addr, size))
        x64dbg._plugin_logputs("Free: " + hex(addr))
        RemoteFree(addr)

    lastAddress = 0
    while lastAddress < address:
        lastAddress = RemoteAlloc(0x10000)

    RemoteFree(lastAddress)

    lastAddress = RemoteAlloc(alignment*num)
    if lastAddress != address:
        x64dbg._plugin_logputs("Could not align allocation to previous allocated space.")
        return

    for x in range(0, num):
        addr = address + alignment * x
        Write(addr, bufferSet[x])

        
            
def main():
    global continueTracing
    global traceLog
    
    x64dbg._plugin_logputs("Memory Page Merger. Tool merges adjacent Memory Pages of the same size. Script by Jeremy Wildsmith. Use command python mergeSection(address, pageSize, numOfSections)")

main()
