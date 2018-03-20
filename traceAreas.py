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

UNCHANGED_IGNORE_THRESHOLD = 30

queryStop = False

traceAreaArray = [
    TA(0x866f2c),
    TA(0x92d42c),
    TA(0x91c5d4),
    TA(0x8e2946),
    TA(0x98b285),
    TA(0x8f83ac),
    TA(0x882199),
    TA(0x8c1b18),
    TA(0x90975f),
    TA(0x99d866),
    TA(0xa0a4a7),
    TA(0x9707e4),
    TA(0x9a0b4e),
    TA(0x87c1aa),
    TA(0x99a292),
    TA(0x98ef6a),
    TA(0x8ee7ea),
    TA(0x9e9c99),
    TA(0xa3e60e),
    TA(0x8d0adb),
    TA(0x929159),
    TA(0x89b01d),
    TA(0x928d09),
    TA(0xa0bf0d),
    TA(0x98a28a),
    TA(0x972fe8),
    TA(0xa3210e),
    TA(0x9acbdd),
    TA(0x8ba1c5),
    TA(0xa3f5de),
    TA(0x8a670c),
    TA(0x911d94),
    TA(0x932587),
    TA(0x971970),
    TA(0x9c5bd6),
    TA(0x8e521c),
    TA(0x98dbe0),
    TA(0x8868dc),
    TA(0x8c9bed),
    TA(0x8673a2),
    TA(0xa3df9c),
    TA(0x953e3f),
    TA(0x926a9d),
    TA(0x97c57b),
    TA(0x9ec97c),
    TA(0x9c2abd),
    TA(0xa210b3),
    TA(0x998822),
    TA(0x992afb),
    TA(0x88c0a0),
    TA(0x8ac217),
    TA(0x8c30b4),
    TA(0x9daf55),
    TA(0x9db3f1),
    TA(0x8d0f58),
    TA(0x88c21a),
    TA(0x8ac3a9),
    TA(0x8c3219),
    TA(0x8e3e6a),
    TA(0x99f09b),
    TA(0x8e560a),
    TA(0x926c07),
    TA(0x971e22),
    TA(0x9328c7),
    TA(0xa25c5d),
    TA(0xa2603c),
    ]

installAddr = 0x00A250CD

def read_buffer(addr, size):
    read_bytes = bytearray(size)
    result, read_size = x64dbgpy.pluginsdk.x64dbg.Memory_Read(addr, read_bytes, size)
    return bytes(read_bytes[:read_size])

def resolveTraceAreas():
    global traceAreaArray

    for ta in traceAreaArray:
        longestAddress = 0
        memory = read_buffer(ta.address, 2000)
        decomposedInstructions = distorm3.Decompose(ta.address, memory)
        
        for inst in decomposedInstructions:
            if (inst.flowControl == "FC_UNC_BRANCH") or (inst.flowControl == "FC_RET"):
                ta.jumpAddress = inst.address
                break

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
                print("Eyy I did something.")
                branchAddr = ownerTa.address
                return False
            
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
