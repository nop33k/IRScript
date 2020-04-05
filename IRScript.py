# Name          :   IRScript
# Author        :   nop33k
# Last edited   :   April 2020
# Purpose       :   This is intended as an Incident Response tool that can be run from a
#               :   USB drive and does not need any type of installation. The script uses
#               :   Sysinternals for Windows from the live site (so no download and unzip is needed).
#               :   It also uses one downloaded tool from Nirsoft. that will need to be saved
#               :   in the same location on the USB as the location of the Python script itself.
#               :   Linux systems will use internally available tools directly on the system being
#               :   investigated and no further installation is required.
#               :   Script results will be stored in a file with name: <currenttimestamp>-<machine-name>-IRdetails.txt.


import subprocess
import argparse
import time
import socket
import os
import hashlib

# set global variable for output file (if needed). This keeps it out of any for loops.
# First get timestamp
timestr = time.strftime("%Y%m%d-%H%M%S")

# Next get the hostname (catch error, just in case)
try:
    hostname = socket.gethostname()
except socket.error:
    hostname = "NoHostName"

# Use timestamp and hostname to build outputfile name to be used for all output.
outputfile = timestr + "-" + hostname + "-IRdetails.txt"


def parse_arguments():

    # Create initial parser and arguments. This is used to determine whether we grab data from a Windows
    # or Linux system.

    # Create the parser
    parser = argparse.ArgumentParser(prog="IRScript",
                                     description="Grab forensic information from a suspicious system")

    # Add arguments, set as variable, and start using them
    parser.add_argument("-w", "--windows", action="store_true", help="Forensics on Windows system")
    parser.add_argument("-l", "--linux", action="store_true", help="Forensics on Linux system")
    args = parser.parse_args()
    use_arguments(args)


def use_arguments(args):

    # Take action on the arguments based on selection (Windows or Linux)

    # Check if windows argument
    if args.windows:

        # Grab details from Windows system using Windows tools, live Sysinternals, and Nirsoft tools
        print("Getting forensics data from Windows System\n")
        windows_forensics()

    # Check if Linux argument
    if args.linux:

        # Grab details from Linux system using local tools
        print("Getting forensics data from Linux System\n")
        linux_forensics()

    # Handle error if no flag is selected
    elif not args.windows:
        if not args.linux:
            print("Improper usage. Type -h or --help for details.")


def windows_forensics():

    # Quick check if truly windows
    if os.name == "nt":

        # Get logged on user(s) via and print to output file (live sysinternals)
        print("Getting current logged on user details\n")
        write_to_file("\nDetails from PSLOGGEDON\n*************************************************\n")
        subprocess.call("cmd /c \\\\live.sysinternals.com\\\\tools\\\\psloggedon /accepteula -l >> {}".format(outputfile))
        write_to_file("*************************************************\n\n")

        # Get Network configuration details (local tool)
        print("Getting current ipconfig details\n")
        write_to_file("\nDetails from IPCONFIG\n*************************************************\n")
        subprocess.call("cmd /c ipconfig >> {}".format(outputfile))
        write_to_file("*************************************************\n\n")

        # List current network connections (local tool)
        print("Getting current network connection (netstat) details\n")
        write_to_file("\nDetails from NETSTAT\n*************************************************\n")
        subprocess.call("cmd /c netstat -abno >> {}".format(outputfile))
        write_to_file("*************************************************\n\n")

        # Get process details and print them to output file (live sysinternals)
        print("Getting process details\n")
        write_to_file("\nDetails from PSLIST\n*************************************************\n")
        subprocess.call("cmd /c \\\\live.sysinternals.com\\\\tools\\\\pslist /accepteula -d >> {}".format(outputfile))
        write_to_file("*************************************************\n\n")

        # Get process details and print them to output file (Nirsoft)
        print("Getting last browser searches details from Windows machine\n")
        write_to_file("\nDetails from MYLASTSEARCH\n*************************************************\n")
        write_to_file("\nResults in {}\n".format(timestr + "-" + hostname + "-SearchDetails.txt"))
        subprocess.call("cmd /c MyLastSearch.exe /stext {} /sort "
                        "~Search Time".format(timestr + "-" + hostname + "-SearchDetails.txt"))
        write_to_file("*************************************************\n\n")

        print_sha_hash(outputfile)
        print_sha_hash(timestr + "-" + hostname + "-SearchDetails.txt")

    # Graceful exit if not Windows
    else:
        print("Not a Windows system. The -w argument is only for Windows.")
        exit()


def linux_forensics():

    # Quick check if this is Windows system instead
    if os.name == "nt":
        # Graceful exit
        print("This appears to be a Windows system. The -l argument is only for Linux systems")
        exit()

    # This appears to be Linux, carry on.
    else:

        # Get system name (local tool)
        print("Getting system name details\n")
        write_to_file("\nDetails from UNAME command\n*************************************************\n")
        subprocess.call(["uname -a >> {}".format(outputfile)], shell=True)
        write_to_file("*************************************************\n\n")

        # Get listing of currently logged in users (local tool)
        print("Getting name(s) of logged in users\n")
        write_to_file("\nDetails from LAST command\n*************************************************\n")
        subprocess.call(["last >> {}".format(outputfile)], shell=True)
        write_to_file("*************************************************\n\n")

        # Get network details (local tool)
        print("Getting current ifconfig details\n")
        write_to_file("\nDetails from IFCONFIG command\n*************************************************\n")
        subprocess.call(["ifconfig >> {}".format(outputfile)], shell=True)
        write_to_file("*************************************************\n\n")

        # Get network connection details (local tool)
        print("Getting current netstat details\n")
        write_to_file("\nDetails from NETSTAT command\n*************************************************\n")
        subprocess.call(["netstat -natp >> {}".format(outputfile)], shell=True)
        write_to_file("*************************************************\n\n")

        # Get current process details (local tool)
        print("Getting current process details\n")
        write_to_file("\nDetails from PS command\n*************************************************\n")
        subprocess.call(["ps >> {}".format(outputfile)], shell=True)
        write_to_file("*************************************************\n\n")

        # Print hash of output file to screen when done
        print_sha_hash(outputfile)


def write_to_file(details):

    # Write to default file name
    with open(outputfile, "a+") as outfile:
        outfile.write(details)
        outfile.close()


def print_sha_hash(file):

    # Open output file
    with open(file, "rb") as f:

        # Read file as bytes
        bytes = f.read()

        # Create hash
        hash_value = hashlib.sha256(bytes).hexdigest()
        print("The hash value for {} is: {}\n". format(file, hash_value))


# Program start
if __name__ == '__main__': parse_arguments()
