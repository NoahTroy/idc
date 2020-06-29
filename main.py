#!/usr/bin/python3

import subprocess , os

from colorama import Fore , Style

try:
	from bcc import BPF
except:
	print(Fore.RED + 'Error!\nPlease make sure you have bpfcc-tools installed.' + Style.RESET_ALL , end = '\n\n')
	exit()


##################### MAIN VARIABLES #####################
configFileFullPath = '/etc/idc.conf'

targetDiskMode = 'master'
targetDisk = 'sdb'

targetDiskPath = '/dev'
targetDiskFullPath = '/dev/sdb'
################## END OF MAIN VARIABLES #################


def startupSequence():
	# Make sure the program is being run by root:
	if (not(os.getuid() == 0)):
		print(Fore.RED + 'Error!\nThis program must be run as the root user.\nExiting...' + Style.RESET_ALL , end = '\n\n')
		exit()

	# Load the config file, or create it with default values if it doesn't exist:
	if (os.path.isfile(configFileFullPath)):
		with open(configFileFullPath , 'r') as idcConfFile:
			for line in idcConfFile.readlines():
				if (not((len(line) < 2) or (line[0] == '#'))):
					lineParts = line.split()
					if ('Target Disk Mode: ' in line):
						if ('master' in lineParts):
							targetDiskMode = 'master'
							print(Fore.GREEN + 'Target Disk Mode set to "master"' + Style.RESET_ALL , end = '\n\n')
						elif ('clone' in lineParts):
							targetDiskMode = 'clone'
							print(Fore.GREEN + 'Target Disk Mode set to "clone"' + Style.RESET_ALL , end = '\n\n')
						else:
							print(Fore.RED + 'Error!\nA proper entry for "Target Disk Mode" could not be found in the configuration file.\nExiting...' + Style.RESET_ALL , end = '\n\n')
							exit()
					if ('Target Disk: ' in line):
						try:
							location = (lineParts.index('Disk:') + 1)
							targetDisk = lineParts[location]
							targetDiskFullPath = os.path.join(targetDiskPath , targetDisk)

							if (os.path.exists(targetDiskFullPath)):
								print(Fore.GREEN + 'Target Disk set to ' + targetDiskFullPath + Style.RESET_ALL , end = '\n\n')
							else:
								print(Fore.RED + 'Error!\nThe target disk (' + targetDiskFullPath + ') could not be found!\nYou probably forgot to attach the disk,\nor entered an incorrect disk name.\n\nIf your device is not located at /dev/,\nyou will need to modify the "targetDiskPath" variable\nfound in the "MAIN VARIABLES" section of this program.\nThis program should be located in "/usr/sbin/" on your system.\n\nExiting...' + Style.RESET_ALL , end = '\n\n')
								exit()
						except:
							print(Fore.RED + 'Error!\nA proper entry for "Target Disk" could not be found in the configuration file.\nExiting...' + Style.RESET_ALL , end = '\n\n')
							exit()
	else:
		print(Fore.YELLOW + 'Warning!\nNo configuration file was found at ' + configFileFullPath + '\nA configuration file will be automatically created for you\nand populated with default values.' + Style.RESET_ALL , end = '\n\n')
		with open(configFileFullPath , 'w') as idcConfFile:
			idcConfFile.write('###################### idc Configuration File ######################\n\n# The target disk mode indicates whether the target disk is to be\n# read from or written to. This is a very important setting, and\n# can lead to data loss if improperly set. The two options for\n# this setting are "master" and "clone":\n#\n# "master" : If set, the target disk will have all write operations\n#            to it logged, and will be marked the disk to be cloned.\n#            This disk will only be read from by idc, and idc will\n#            never modify its contents. This is the "local" disk.\n#\n# "clone" :  If set, the target disk will be marked as the clone of\n#            a separate, "master" disk. Any changes made to the master\n#            disk will be written to this disk. Any changes made\n#            locally to this disk will be ignored, and overwritten.\n#            This is the "remote", backup disk.\n\nTarget Disk Mode: master\n\n\n# The target disk is the disk with which idc is to interact. Depending\n# on the target disk mode, this disk will either be the disk being\n# tracked, or the disk being written-to. Please make sure that this\n# is a block-level device, and do not include any leading directory\n# information. For example, "/dev/sdb" should be written as "sdb".\n\nTarget Disk: sdb\n')
		print(Fore.YELLOW + 'A default configuration file has been created.\nExiting...' + Style.RESET_ALL , end = '\n\n')
		exit()


##################### MAIN EXECUTION #####################
startupSequence()
################## END OF MAIN EXECUTION #################
