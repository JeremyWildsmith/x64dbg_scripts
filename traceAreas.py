import x64dbgpy
import networkx as nx
import re
import fileinput
import os
import distorm3
import time
import threading

from x64dbgpy.pluginsdk import *

class TA(object):
    def __init__(self, address):
        self.address = address
        self.jumpAddress = 0
        self.branches = []
        self.hitCount = 0
        self.hitUnchanged = 0
        self.size = 0

class Label(object):
    def __init__(self, labelText):
        self.labelText = labelText

UNCHANGED_IGNORE_THRESHOLD = 3

queryStop = False

traceAreaArray = [
        TA(0x9bc113),
        TA(0x9707e4),
        TA(0x91ae8e),
        TA(0x999130),
    ]

installAddr = 0x00A250CD

def read_buffer(addr, size):
    read_bytes = bytearray(size)
    result, read_size = x64dbgpy.pluginsdk.x64dbg.Memory_Read(addr, read_bytes, size)
    return bytes(read_bytes[:read_size])

def findBranch(ta, size):
    memory = read_buffer(ta.address, size)
    decomposedInstructions = distorm3.Decompose(ta.address, memory)
        
    for inst in decomposedInstructions:
        if (inst.flowControl == "FC_UNC_BRANCH") and (inst.operands[0].type == "Register"):
            ta.jumpAddress = inst.address
            return True
        elif (inst.flowControl == "FC_RET"):
            ta.jumpAddress = inst.address
            return True

    return False

def resolveTraceAreas():
    global traceAreaArray

    for ta in traceAreaArray:
        longestAddress = 0
        if not findBranch(ta, 2000):
            if not findBranch(ta, 50000):
                raise Exception("Unable to resolve TA: " + hex(ta.address))

        ta.size = ta.jumpAddress - ta.address
    
    return
        
def installBreakpoints():    
    global traceAreaArray
    global installAddr

    resolveTraceAreas()
    
    for ta in traceAreaArray:
        debug.SetBreakpoint(ta.jumpAddress)

def findOwnerTa(address):
    for ta in traceAreaArray:
        if address > ta.address and address < ta.address + ta.size:
            return ta

    return None

def bphit():
    
    global traceAreaArray
    global installAddr

    for ta in traceAreaArray:
        if ta.jumpAddress == Register.EIP:
            debug.StepIn()
            branchAddr = Register.EIP
            ownerTa = findOwnerTa(branchAddr)

            if ownerTa is not None:
                branchAddr = ownerTa.address

            branchAddressStr = hex(branchAddr)
            ta.hitCount = ta.hitCount + 1
            if branchAddressStr not in ta.branches:
                ta.hitUnchanged = 0
                ta.branches.append(branchAddressStr)
            else:
                ta.hitUnchanged = ta.hitUnchanged + 1 

            if ta.hitUnchanged >= UNCHANGED_IGNORE_THRESHOLD:
                debug.DeleteBreakpoint(ta.jumpAddress)
                
            return True

    return False
    
def talist():
    global traceAreaArray
    for ta in traceAreaArray:
        print "TA(" + hex(ta.address) + "), #Jumps To:"

        ta.branches.sort()
        for address in ta.branches:
            print "IA(" + address + "),"

def nodelist():
    global traceAreaArray

    nodeNames = []
    
    for ta in traceAreaArray:
        taAddressName = hex(ta.address)
        if taAddressName not in nodeNames: 
            nodeNames.append(taAddressName)

        for address in ta.branches:
            if address not in nodeNames:
                nodeNames.append(address)    

    for name in nodeNames:
        print("TA(" + name + "),")

def hitcount():
    global traceAreaArray

    traceAreaArray.sort(key=lambda x: x.hitCount, reverse=True)

    
    for ta in traceAreaArray:
        print(hex(ta.address) + ", " + str(ta.hitCount))

def fixGraphLabels(graphSavePath):
    lines = []

    file = open(graphSavePath)
    for line in file:
        m = re.match(r'\s*<node\sid="([A-Za-z0-9x]*)"\s\/>', line, re.I)
        if m:
            nodeName = m.group(1)
            line = "<node id=\"" + nodeName + "\">"
            line += '<data key="d1">'
            line += '<y:ShapeNode><y:NodeLabel>'
            line += nodeName
            line += '</y:NodeLabel></y:ShapeNode>'
            line += "</data>"
            line += "</node>"
        else:
            m = re.match(r'\s*<graphml', line)
            if m:
                line = '<graphml xmlns="http://graphml.graphdrawing.org/xmlns"'
                line += ' xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"'
                line += ' xsi:schemaLocation="http://graphml.graphdrawing.org/xmlns http://graphml.graphdrawing.org/xmlns/1.0/graphml.xsd"'
                line += ' xmlns:y="http://www.yworks.com/xml/graphml">'
                line += ' <key for="node" id="d1" yfiles.type="nodegraphics"/>'
                
        lines.append(line)

        print(line)

    file.close()

    file = open(graphSavePath, "w")

    for l in lines:
        file.write(l)

    file.close()
    
    return
    
def plotgraph():
    global traceAreaArray

    nodeNames = []
    edgesTo = []
    
    for ta in traceAreaArray:
        taAddressName = hex(ta.address)
        if taAddressName not in nodeNames: 
            nodeNames.append(taAddressName)

        taIndex = nodeNames.index(taAddressName)
        
        for address in ta.branches:
            if address not in nodeNames:
                nodeNames.append(address)

            branchIndex = nodeNames.index(address)
            edgesTo.append( (taIndex, branchIndex) )
            
                
    graph = nx.DiGraph()

    labelDictionary = {}
    for i in range(0, len(nodeNames)):
        labelDictionary[i] = nodeNames[i]
        graph.add_node(i)

    graph.add_edges_from(edgesTo)

    graphSavePath = os.path.dirname(os.path.realpath(__file__)) + "\\flow.graphml"
    
    nx.write_graphml(nx.relabel_nodes(graph, labelDictionary), graphSavePath)

    fixGraphLabels(graphSavePath)

    print "Graph saved to: " + graphSavePath

def stop():
    global queryStop
    queryStop = True;
    print("Stopping");
    
def main():
    global queryStop
    global installAddr
    
    x64dbg.DbgCmdExecDirect("bc")
    SetHardwareBreakpoint(installAddr)
    debug.Run();
    DeleteHardwareBreakpoint(installAddr)
                
    if Register.EIP != installAddr:
        print("Debugger stopped at unexpected location.")
        return;

    print("Installing Breakpoints...");
    installBreakpoints();

    while True:
        if not queryStop:
            debug.Run()
        else:
            break;
        
        if not bphit():
            print("Debugger stopped at unexpected location.")
            queryStop = True

main()
