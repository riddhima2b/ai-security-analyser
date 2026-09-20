import subprocess

command = input("Enter command to run : ")
subprocess.run(command, shell=True)