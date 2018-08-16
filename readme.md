# Jeremy's x64dbg Scripts Collection
This repository is a list of x64db python scripts for use with the x64dbg Python plugin.

These scripts can be used to analyze executable binaries and help reverse engineering their behavior.

### combine_pages.py

#### Description
An x64dbg script that combines adjacent memory pages of the same size into a single memory page of larger size. This is very useful when attempting to dump an unpacked or injected program. Typically, multiple sections will be allocated using VirtualAllocEx and when you go to dump the injected program or unpacked program using OllyDumpEx, you can encounter issues with the maximum number of sections allowed per PE Image on Windows XP (Upper limit of 92 sections for PE32 images.)

This tool is to specifically target issues with running dumped PE Images with more than 92 sections on Windows XP. On Windows Vista, 10 etc you can use more sections and this is not an issue.

#### Useage
Load the Python script into x64dbg and use the command line to invoke the mergeSection function:

The below command will 4 adjacent pages starting at 0x50000, where each page is 0x1000 bytes in length.
````
python mergeSection(0x50000, 0x1000, 4)
````



### traceAreas.py

#### Description
This script is for logging the control flow of an obfuscated application utilizing Control-Flow flattening. For example:

````
0x123456:
[x86 Instructions]
jmp esi
````

If you open this application and conduct static analysis (i.e via IDA Pro or x64dbg graph view) it will not be able to resolve the control flow of the application.

The approach that traceAreas takes is to monitor these branching instructions during run-time and generate a graph of where it detects control flow is transfered towards.

Below is a sample of a control flow graph that is generated and viewed in yEd Live:
![alt text](https://i.imgur.com/kL4USza.png "Logo Title Text 1")

#### Usage / Configuration

##### Useage
To use traceAreas, open the target and, after making the below configurations, run the python script from x64dbg.

Branching instructions have been thoroughly traced (usually after 2 - 3 minutes of execution) or you encounter the end of the program, you can open the Log tab on x64dbg and enter the following command to stop the tracing:
````
Python "stop()"
````

Then, you can graph out the control flow by typing
````
Python "plotgraph()"
````

The location of the graphml file that details the control flow will be printed to the log. You can open this graphml file in yEd Live and run a layout to visualize the control flow.

If you see the control flow graph and would like to go a level deeper and trace the branching of the subroutines that were branched to, you can run the following command:

````
Python "nodelist()"
````
This will print out a list of subroutines that were detected through the traceArea method. You can replace the contents of the traceAreaArray with what is printed out via the log (Ctrl-C, Ctrl-V) and run the trace areas again.

###### traceAreaArray
A list of subroutines that you would like to monitor the control flow of.

###### UNCHANGED_IGNORE_THRESHOLD
The number of times that a branching instruction can transfer control flow to a previously logged location in a row before it is no longer monitored. This is to make the tracing quicker. If there control flow behavior hasn't changed 40 times in a row, it has probably been mostly / fully documented. This value can be fine-tuned based on the application.

###### installAddr
If the application is packed / obfuscated such that code sections are not valid until later into execution, it is required to install the software breakpoints that monitor execution after those code sections become valid. The installAddr is a location where a hardware breakpoint is installed which, once hit, the software breakpoints to monitor the branching instructions will be installed. After this, the hardware breakpoint is deleted.

If your target is not obfuscated in this manner, you can simply set this to the address of the function immediately after OEP.

