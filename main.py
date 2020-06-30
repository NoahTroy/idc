#!/usr/bin/python3

import os , socket , queue , threading , time , uuid

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

socketLocation = '/tmp'

writeProcessQueue = queue.Queue()
sendQueue = queue.Queue()
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
								print(Fore.GREEN + 'Target Disk set to "' + targetDiskFullPath + '"' + Style.RESET_ALL , end = '\n\n')
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


def processEvents():
	def handleEvent(cpu, data, size):
		event = bpfInst['events'].event(data)

		if ((event.readOrWrite == 1) and (event.diskName.decode('utf-8' , 'replace') == targetDisk)):
			writeProcessQueue.put([event.sector , event.length])


	bpfText = '#include <uapi/linux/ptrace.h>\n#include <linux/blkdev.h>\n\nstruct mainData {char diskName[DISK_NAME_LEN];u64 readOrWrite;u64 sector;u64 length;};BPF_HASH(start , struct request *);BPF_PERF_OUTPUT(events);int traceCompletedRequests(struct pt_regs *ctx , struct request *req){struct mainData data = {};struct gendisk *rq_disk = req->rq_disk;bpf_probe_read(&data.diskName , sizeof(data.diskName) , rq_disk->disk_name);data.sector = req->__sector;data.length = req->__data_len;\n#ifdef REQ_WRITE\n    data.readOrWrite = !!(req->cmd_flags & REQ_WRITE);\n#elif defined(REQ_OP_SHIFT)\n    data.readOrWrite = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);\n#else\n    data.readOrWrite = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);\n#endif\nevents.perf_submit(ctx , &data , sizeof(data));start.delete(&req);return 0;}'

	bpfInst = BPF(text = bpfText)
	bpfInst.attach_kprobe(event = 'blk_account_io_completion' , fn_name = 'traceCompletedRequests')
	bpfInst['events'].open_perf_buffer(handleEvent , page_cnt = 64)

	while (True):
		bpfInst.perf_buffer_poll()


def processWriteData():
	#uniqueID = str(uuid.uuid4()).encode('utf-8')
	pass


def masterSocket():
	with socket.socket(socket.AF_UNIX , socket.SOCK_STREAM) as s:
		s.connect(os.path.join(socketLocation , 'idcMasterSocket.sock'))

	while (True):
		#s.sendall()
		pass


def cloneSocket():
	pass


##################### MAIN EXECUTION #####################
startupSequence()

if (targetDiskMode == 'master'):
	socketThread = threading.Thread(target = masterSocket , args = ())
	socketThread.start()

	processThread = threading.Thread(target = processWriteData , args = ())
	processThread.start()

	processEvents()
elif (targetDiskMode == 'clone'):
	pass
else:
	print(Fore.RED + 'A valid Target Disk Mode could not be established.\nExiting...' + Style.RESET_ALL)
################## END OF MAIN EXECUTION #################
