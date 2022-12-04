#!/bin/python
#Inspired by Cristi Zot's Udemy course, "Python for Penetration Testers"
#MAC address spoofer.  The MAC address will revert to original after reboot.
#It may take two inital tries due to the interface going down/up

import random
import os
import subprocess

#function that defines the random values
def get_rand():
    return random.choice("abcdef0123456789")

#function that generates the values using a for loop.
def new_mac():
    new_ = ""
    for i in range(0,5):
        new_+=get_rand()+get_rand()+":"
    
    new_+get_rand()+get_rand()
    return new_

#prints the current MAC address
print("Current MAC Address")
print(os.system("ifconfig eth0 | grep ether | grep -oE [0-9abcdef:]{17}"))

#turns off interface (eth0 in this case)
subprocess.call(["sudo","ifconfig","eth0","down"])

#creates a randomly generated MAC address
new_m = new_mac()

#assigns the new MAC address
subprocess.call(["sudo","ifconfig","eth0","hw","ether","%s"%new_m])

#turns on the interface (eth0)
subprocess.call(["sudo","ifconfig","eth0","up"])

#prints the newly created MAC address
print("New MAC Address")
print(os.system("ifconfig eth0 | grep ether | grep -oE [0-9abcdef:]{17}"))

print("\nNote that the original MAC will return after a system reboot.")






