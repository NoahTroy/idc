#!/usr/bin/python3

import os , socket , queue , threading , time , uuid , subprocess , pickle , pathlib

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
fetchDelay = 300
remoteServerIP = '10.0.0.2'
remoteServerPort = 22
identityFile = '/root/.idc/privKey.pem'

targetDiskPath = '/dev'
targetDiskFullPath = '/dev/sdb'

pendingWritesFilePath = '/root/.idc'
pendingWritesFileFullPath = '/root/.idc/cachedData.dat'

socketLocation = '/tmp'

targetDiskLogicalSectorSize = 512

writeProcessQueue = queue.Queue()
sendQueue = queue.Queue()

lastWriteTime = 0
pendingWrites = []
pendingWritesFile = False

cloneSocketError = False
################## END OF MAIN VARIABLES #################


def startupSequence():
	# Make sure the program is being run by root:
	if (not(os.getuid() == 0)):
		print(Fore.RED + 'Error!\nThis program must be run as the root user.\nExiting...' + Style.RESET_ALL , end = '\n\n')
		exit()

	# Load the config file, or create it with default values if it doesn't exist:
	if (os.path.isfile(configFileFullPath)):
		if (not(os.path.exists(pendingWritesFilePath))):
			pathlib.Path(pendingWritesFilePath).mkdir(parents = True , exist_ok = True)
			print(Fore.CYAN + 'The default cache directory was not found,\nso a new one was created, here: ' + pendingWritesFilePath + Style.RESET_ALL , end = '\n\n')

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

							try:
								targetDiskLogicalSectorSize = int(subprocess.Popen(['lsblk' , targetDiskFullPath , '--output' , 'LOG-SEC'] , stdout = subprocess.PIPE).stdout.read().decode('utf-8').split()[1])
								print(Fore.GREEN + 'Target Disk logical sector size detected as ' + str(targetDiskLogicalSectorSize) + ' bytes.' + Style.RESET_ALL , end = '\n\n')
							except:
								print(Fore.RED + 'Error!\nThe logical sector size of the target disk could\nnot be determined. If "lsblk" is not installed on your\nsystem, that could be the cause of this error.\nExiting...' + Style.RESET_ALL , end = '\n\n')
								exit()
						except:
							print(Fore.RED + 'Error!\nA proper entry for "Target Disk" could not be found in the configuration file.\nExiting...' + Style.RESET_ALL , end = '\n\n')
							exit()
					if ('Fetch Delay: ' in line):
						try:
							location = (lineParts.index('Delay:') + 1)
							fetchDelay = int(lineParts[location])
							if (fetchDelay < 0):
								fetchDelay = 300
								print(Fore.YELLOW + 'Warning!\nA fetch delay value of less than zero was used.\nThis value is invalid. Please choose a value greater than zero.\nThe default value of 300 will be used for now...' + Style.RESET_ALL , end = '\n\n')
							else:
								print(Fore.GREEN + 'Fetch Delay set to: ' + str(fetchDelay) + Style.RESET_ALL , end = '\n\n')
						except:
							fetchDelay = 300
							print(Fore.YELLOW + 'Warning!\nAn invalid fetch delay value was set in the configuration file.\nPlease choose an integer value greater than zero.\nThe default value of 300 will be used for now...' + Style.RESET_ALL , end = '\n\n')
					if ('Remote Server IP: ' in line):
						try:
							location = (lineParts.index('IP:') + 1)
							remoteServerIP = lineParts[location]
							print(Fore.GREEN + 'Remote Server IP set to: ' + remoteServerIP + Style.RESET_ALL , end = '\n\n')
						except:
							print(Fore.YELLOW + 'Warning!\nThe remote server IP address could not be detected.\nThe default value of "10.0.0.2" will be used for now...' + Style.RESET_ALL , end = '\n\n')
							remoteServerIP = '10.0.0.2'
					if ('Remote Server Port: ' in line):
						try:
							location = (lineParts.index('Port:') + 1)
							remoteServerPort = int(lineParts[location])
							if ((remoteServerPort < 65536) and (remoteServerPort > 0)):
								print(Fore.GREEN + 'Remote Server Port set to: ' + str(remoteServerPort) + Style.RESET_ALL , end = '\n\n')
							else:
								print(Fore.YELLOW + 'Warning!\nAn invalid remote server port was provided.\nPlease make sure the port number is between 0 and 65536.\nThe default value of 22 will be used for now...' + Style.RESET_ALL , end = '\n\n')
								remoteServerPort = 22
						except:
							print(Fore.YELLOW + 'Warning!\nAn invalid (non-integer) remote server port was provided.\nThe default value of 22 will be used for now...' + Style.RESET_ALL , end = '\n\n')
							remoteServerPort = 22
					if ('Identity File: ' in line):
						try:
							location = (lineParts.index('File:') + 1)
							identityFile = lineParts[location]
							if (os.path.isfile(identityFile)):
								print(Fore.GREEN + 'The identity file was found. Please make sure that it has\nthe proper permissions set, and that the fingerprint\nof the remote host has already been saved in the "known_hosts" file.\nThis program will assume that the previous has already\nbeen done, and will continue running...' + Style.RESET_ALL , end = '\n\n')
							else:
								print(Fore.RED + 'Error!\nAn identity file was not found in the location provided.\nExiting...' + Style.RESET_ALL , end = '\n\n')
								exit()
						except:
							print(Fore.RED + 'Error!\nA valid identity file entry could not be found.\nExiting...' + Style.RESET_ALL , end = '\n\n')
							exit()
	else:
		print(Fore.YELLOW + 'Warning!\nNo configuration file was found at ' + configFileFullPath + '\nA configuration file will be automatically created for you\nand populated with default values.' + Style.RESET_ALL , end = '\n\n')
		with open(configFileFullPath , 'w') as idcConfFile:
			idcConfFile.write('###################### idc Configuration File ######################\n\n# The target disk mode indicates whether the target disk is to be\n# read from or written to. This is a very important setting, and\n# can lead to data loss if improperly set. The two options for\n# this setting are "master" and "clone":\n#\n# "master" : If set, the target disk will have all write operations\n#            to it logged, and will be marked the disk to be cloned.\n#            This disk will only be read from by idc, and idc will\n#            never modify its contents. This is the "local" disk.\n#\n# "clone" :  If set, the target disk will be marked as the clone of\n#            a separate, "master" disk. Any changes made to the master\n#            disk will be written to this disk. Any changes made\n#            locally to this disk will be ignored, and overwritten.\n#            This is the "remote", backup disk.\n\nTarget Disk Mode: master\n\n\n# The target disk is the disk with which idc is to interact. Depending\n# on the target disk mode, this disk will either be the disk being\n# tracked, or the disk being written-to. Please make sure that this\n# is a block-level device, and do not include any leading directory\n# information. For example, "/dev/sdb" should be written as "sdb".\n\nTarget Disk: sdb\n\n\n# The fetch delay is the amount of time (in seconds) that the\n# program will wait after the last detected write operation\n# to the target disk, before reading the new data on the disk\n# and forwarding it to the clone. This setting is only\n# applicable if the target disk mode is set to "master".\n\nFetch Delay: 300\n\n\n# The remote server IP is the IP address of the remote server with\n# which data is to be transmitted. If this server is the master\n# server, then the remote server IP address would be the IP\n# address of the clone server, and vice versa.\n\nRemote Server IP: 10.0.0.2\n\n\n# The remote server port is the network port of the remote server\n# on which the sshd daemon is listening for incoming connections.\n# The default value is 22.\n\nRemote Server Port: 22\n\n\n# The identity file is the private key required in order to connect\n# with the remote server via SSH. Please provide the full path to\n# this file.\n\nIdentity File: /root/.idc/privKey.pem\n')
		print(Fore.YELLOW + 'A default configuration file has been created.\nExiting...' + Style.RESET_ALL , end = '\n\n')
		exit()


def processEvents():
	def handleEvent(cpu, data, size):
		event = bpfInst['events'].event(data)

		if ((event.readOrWrite == 1) and (event.diskName.decode('utf-8' , 'replace') == targetDisk)):
			lastWriteTime = time.time()
			writeProcessQueue.put([event.sector , event.length])


	bpfText = '#include <uapi/linux/ptrace.h>\n#include <linux/blkdev.h>\n\nstruct mainData {char diskName[DISK_NAME_LEN];u64 readOrWrite;u64 sector;u64 length;};BPF_HASH(start , struct request *);BPF_PERF_OUTPUT(events);int traceCompletedRequests(struct pt_regs *ctx , struct request *req){struct mainData data = {};struct gendisk *rq_disk = req->rq_disk;bpf_probe_read(&data.diskName , sizeof(data.diskName) , rq_disk->disk_name);data.sector = req->__sector;data.length = req->__data_len;\n#ifdef REQ_WRITE\n    data.readOrWrite = !!(req->cmd_flags & REQ_WRITE);\n#elif defined(REQ_OP_SHIFT)\n    data.readOrWrite = !!((req->cmd_flags >> REQ_OP_SHIFT) == REQ_OP_WRITE);\n#else\n    data.readOrWrite = !!((req->cmd_flags & REQ_OP_MASK) == REQ_OP_WRITE);\n#endif\nevents.perf_submit(ctx , &data , sizeof(data));start.delete(&req);return 0;}'

	bpfInst = BPF(text = bpfText)
	bpfInst.attach_kprobe(event = 'blk_account_io_completion' , fn_name = 'traceCompletedRequests')
	bpfInst['events'].open_perf_buffer(handleEvent , page_cnt = 64)

	while (True):
		bpfInst.perf_buffer_poll()


def processWriteData():
	while (True):
		if (writeProcessQueue.qsize() > 0):
			if ((time.time() - lastWriteTime) >= fetchDelay):
				try:
					with open(targetDiskFullPath , 'rb') as disk:
						sector , length = writeProcessQueue.get()
						seekBytes = (int(sector) * targetDiskLogicalSectorSize)
						disk.seek(seekBytes)
						data = disk.read(int(length))
				except:
					print(Fore.RED + 'ERROR!\nDATA COULD NOT BE READ FROM THE TARGET DISK,\nAND THEREFORE WILL NOT BE CLONED. PLEASE START A FULL\nDISK CLONE FROM SCRATCH!\n\nExiting...' + Style.RESET_ALL , end = '\n\n')
					exit()
				uniqueID = str(uuid.uuid4()).encode('utf-8')

				data = (uniqueID + b' ' + str(seekBytes).encode('utf-8') + b' ' + data + b' ' + uniqueID)

				sendQueue.put(data)
		else:
			time.sleep(3)


def dataFetcher(returnedData = None):
	if (returnedData):
		pendingWrites.insert(0 , returnedData)
		if (len(pendingWrites) > 1000):
			if (pendingWritesFile):
				with open(pendingWritesFileFullPath , 'rb') as writesFile:
					pendingWritesFileContents = pickle.load(writesFile)

				for i in range((len(pendingWrites) - 1) , 999 , -1):
					pendingWritesFileContents.append(pendingWrites.pop(i))

				with open(pendingWritesFileFullPath , 'wb') as writesFile:
					pickle.dump(pendingWritesFileContents , writesFile)
			else:
				print(Fore.MAGENTA + 'PLEASE READ THE FOLLOWING WARNING:\n' + Fore.YELLOW + 'WARNING\nMORE THAN 1,000 WRITE OPERATIONS HAVE BEEN NOT BEEN\nRECEIVED BY THE CLONE SERVER. THESE OPERATIONS WILL NOW\nBE CACHED IN A PHYSICAL FILE WRITTEN TO THIS SERVER\'S\nLOCAL STORAGE. WE RECOMMEND HALTING FURTHER WRITE OPERATIONS\nTO THE TARGET DISK UNTIL A CONNECTION IS ESTABLISHED WITH\nTHE CLONE SERVER, AND ALL WRITE OPERATIONS HAVE BEEN SENT\nAND CLEARED FROM THE LOCAL CACHE.\nUNTIL THIS CAN HAPPEN, YOU MAY EXPERIENCE SOME\nSIGNIFICANT PERFORMANCE DETRIMENTS.' + Style.RESET_ALL , end = '\n\n')

				pendingWritesFile = True

				pendingWritesFileContents = []

				for i in range((len(pendingWrites) - 1) , 999 , -1):
					pendingWritesFileContents.append(pendingWrites.pop(i))

				with open(pendingWritesFileFullPath , 'wb') as writesFile:
					pickle.dump(pendingWritesFileContents , writesFile)
	else:
		if (len(pendingWrites) == 0):
			if (pendingWritesFile):
				with open(pendingWritesFileFullPath , 'rb') as writesFile:
					pendingWrites = pickle.load(writesFile)
				os.remove(pendingWritesFileFullPath)
				pendingWritesFile = False
				return pendingWrites.pop(0)
			else:
				return sendQueue.get()
		else:
			return pendingWrites.pop(0)


def handleWriting(recvSocket):
	while (True):
		if (cloneSocketError):
			cloneSocketError = False
			return
		try:
			connection , address = recvSocket.accept()

			# data = (uniqueID + b' ' + str(seekBytes).encode('utf-8') + b' ' + data + b' ' + uniqueID)
			dataChunk = b''
			chunkID = b''
			seekBytes = -1
			dataToWrite = b''
			while (True):
				if (cloneSocketError):
					cloneSocketError = False
					return

				dataChunk += connection.recv(1024)

				if ((dataChunk.find(b' ') == 36) and (not(chunkID))):
					chunkID = dataChunk[0:36]

				if (chunkID):
					if (dataChunk.count(chunkID) > 1):
						dataChunk = dataChunk[37:]
						nextSeparator = dataChunk.find(b' ')
						if (nextSeparator == -1):
							print(Fore.YELLOW + 'Warning!\nAn error occurred attempting to extract the write location\nfrom the master server\'s message. This may cause some data loss...' + Style.RESET_ALL , end = '\n\n')
							## Reset values here I think... look into this.
						else:
							seekBytes = int(dataChunk[:nextSeparator])
							dataChunk = dataChunk[(nextSeparator + 1):]

							indexOfSecondID = dataChunk.find(chunkID)
							dataToWrite = dataChunk[:(indexOfSecondID - 1)]

							dataChunk = dataChunk[(indexOfSecondID + 36):]

							try:
								with open(targetDiskFullPath , 'rb+') as diskToWriteTo:
									diskToWriteTo.seek(seekBytes)
									diskToWriteTo.write(dataToWrite)
							except:
								print(Fore.RED + 'Error!\nUnable to write data to target disk!\nThis will cause data loss!\nWill move on in 30 seconds...' + Style.RESET_ALL , end = '\n\n')
								time.sleep(30)

							chunkID = b''
							seekBytes = -1
							dataToWrite = b''
					else:
						continue
		except:
			print(Fore.YELLOW + 'Warning!\nAn error occurred while attempting to receive data\nfrom the forwarded unix domain socket.\nTrying again in 10 seconds...' + Style.RESET_ALL , end = '\n\n')
			time.sleep(10)


def masterSocket():
	while (True):
		try:
			os.remove(os.path.join(socketLocation , 'idcMasterSocket.sock'))
			print(Fore.CYAN + 'Successfully removed old unix domain socket.' + Style.RESET_ALL , end = '\n\n')
		except:
			print(Fore.CYAN + 'No old unix domain socket to remove.' + Style.RESET_ALL , end = '\n\n')
		with socket.socket(socket.AF_UNIX , socket.SOCK_STREAM) as s:
			try:
				s.connect(os.path.join(socketLocation , 'idcMasterSocket.sock'))
				print(Fore.GREEN + 'A connection with the clone server has\nbeen successfully established.' + Style.RESET_ALL , end = '\n\n')
			except:
				print(Fore.YELLOW + 'Warning!\nA connection could not be established with the clone server.\nAny changes made to the target disk will be cached,\nand sent once a connection is established.\nTrying again in one minute...' + Style.RESET_ALL , end = '\n\n')
				time.sleep(60)
				continue

		while (True):
			try:
				dataToSend = dataFetcher()
				s.sendall(dataToSend)
			except:
				print(Fore.YELLOW + 'Warning!\nSome data could not be successfully sent to the clone server.\nPlease check the connection, and make sure that no\ndisruptions have occurred. The unsent data has been cached, and\nwill be automatically resent soon.\nIf this message only appears a couple of times, you probably\nhave nothing to worry about.\nTrying again in 20 seconds...' + Style.RESET_ALL , end = '\n\n')
				dataFetcher(dataToSend)
				time.sleep(20)
				continue


def cloneSocket():
	forwardSocket = None
	while (True):
		try:
			try:
				if (forwardSocket):
					forwardSocket.terminate()
			except:
				try:
					forwardSocket.kill()
				except:
					print(Fore.RED + 'Unable to stop socket forwarding.' + Style.RESET_ALL , end = '\n\n')
			os.remove(os.path.join(socketLocation , 'idcCloneSocket.sock'))
			print(Fore.CYAN + 'Successfully removed old unix domain socket.' + Style.RESET_ALL , end = '\n\n')
		except:
			print(Fore.CYAN + 'No old unix domain socket to remove.' + Style.RESET_ALL , end = '\n\n')

		with socket.socket(socket.AF_UNIX , socket.SOCK_STREAM) as s:
			try:
				s.bind(os.path.join(socketLocation , 'idcCloneSocket.sock'))
				s.listen()
				print(Fore.GREEN + 'Successfully connected to the clone server socket.' + Style.RESET_ALL , end = '\n\n')
			except:
				print(Fore.YELLOW + 'Warning!\nUnable to bind to the local unix domain socket\nforwarded between this (clone) server and the master server.\nTrying again in one minute...' + Style.RESET_ALL , end = '\n\n')
				time.sleep(60)
				continue

			forwardSocket = subprocess.Popen(['ssh' , '-NnT' , '-i' , identityFile , '-p' , str(remoteServerPort) , '-R' , (os.path.join(socketLocation , 'idcMasterSocket.sock') + ':' + os.path.join(socketLocation , 'idcCloneSocket.sock')) , ('root@' + remoteServerIP)] , stderr = subprocess.PIPE)

			handleReceivedDataThread = threading.Thread(target = handleWriting , args = (s))
			handleReceivedDataThread.start()

			forwardSocketError = forwardSocket.stderr.readline()
			cloneSocketError = True
			print(Fore.YELLOW + 'Error!\nUnable to forward the unix domain socket to the remote server.\nThis was the error message returned:\n' + forwardSocketError + '\nAnother attempt at forwarding will be made in one minute...' + Style.RESET_ALL , end = '\n\n')
			time.sleep(60)


##################### MAIN EXECUTION #####################
startupSequence()

if (targetDiskMode == 'master'):
	socketThread = threading.Thread(target = masterSocket , args = ())
	socketThread.start()

	processThread = threading.Thread(target = processWriteData , args = ())
	processThread.start()

	processEvents()
elif (targetDiskMode == 'clone'):
	socketThread = threading.Thread(target = cloneSocket , args = ())
	socketThread.start()
else:
	print(Fore.RED + 'A valid Target Disk Mode could not be established.\nExiting...' + Style.RESET_ALL)
################## END OF MAIN EXECUTION #################
