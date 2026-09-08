Currently, there is ransomware.py, which will work as a basic simulation for encryption in the project.

We can run this in a virtual machine to start encryption. We can train the model on different types of encryption methods to get a wide range of results to train the machine.

Idea 1:
Create an external device (RP 2040 one) which needs to be physically plugged in to start the decryption and delete the program/fle which is the ransomware.

Reason: It will save resources, and also we can specialise this device in decryption and resolving the problem.

Issues:
How will the hardware identify the issues ( can work on some special code to help the hardware identify the issue, encryption method, keys, etc ).
Can be misplaced and misused by everyone if they get their hands on the key device of the person ( can allow the user to create a spare USB into the key resolver )

Idea 2:
Create the above mentioned fuction into the program itself and generate a key to identify if it's the right computer, also to prevent this file/folder from being encrypted first/beforehand.

Reason: using any external device is very untrustworthy and installing kernel-level programs is a major red flag for any person.

Issues:
    Major drawback is that since there is constant monitoring from the ML program, simultaneous searching and decryption/isolation can consume way more resources,s and the program can have very poor optimisation.

27/08/2026:

Basic ideas are laid out and thought through; will start working on the machine learning project from tomorrow.

    
Task for Machine learning:
    1: basic ML model 
    2: multiple encryption programs
    3: Simulate the action and record data; also get a dataset if available.
    4: proper dataset
    5: Train the model and test
    6: Run simulations of a ransomware attack to extract more data
    7: application which monitors the whole fileset of the entrie pc and keeps record of all the files that are being installed, etc.

Task for Resolver:
    1: isolate the device from the network
    2: identify encryption model
    3: store a backup of imp files
    4: research the RAM to identify the file which started it; delete the file(s) 
    5: run a basic scan to search for risk elements
    6: must communicate with the isolation program to identify what the actions must be taken.

    
28/08/2026

For the machine learning project major privacy concern is that the user can't delete it's data with breaking the whole model. To counter this we will use "Machine Unlearning". Though this concept is new certain projects have attained 99.94% AUC for a Dataset of 2000 instances , 1000 Ransomware and 1000 renigns.

Basic ideas for the projects are coming. In a week or so will start with building the project. 

31/08/2026

creating a dataset.

collecting features such as:
Timestamp
ProcessID
ProcessName
FileReadCount
FileWriteCount
FileCreateCount
FileRenameCount
FileDeleteCount
FilesModifiedPerMinute
CPUUsage
MemoryUsage
NetworkBytes
FileEntropy
ExtensionChanges
ProcessLifetime
Label

This custom dataset allows us to train our ML model to our liking.
most importantly using unreliable data and wasting time filtering out useless data etc. is hard enough and we cant get desired dataset for the same.

Using a python program we are going to record the above mentioned data. can collect real ransomware data by running them in virtual machines. Goal is to collect 1000 Benigns and 1000 Ransomware ans 200-500 false alerts.

02/09/2026

starting with machine learning programing. creating a program to collect data in different scenarios of ransomware attack, and multiple renigns.