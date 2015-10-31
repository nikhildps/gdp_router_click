#include <click/config.h>
#include "gdp_router_nat.hh"
#include <click/args.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/handlercall.hh>

#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <assert.h>
#include <netinet/ip_icmp.h>
#include <jansson.h>

CLICK_DECLS
		
GDPRouterNat::GDPRouterNat(): _pingTimer(this), _joinTimer(this), _logTimer(this), _task(this) {
	nodeJoined = false;
	_myType = 'N';
	_localFD = -1;
	_bootStrapFD = -1;
	_isFirstNode = false;
	
	_proxyFD = -1;
	_proxyIndex = 0;
				 
	for (int i = 0; i < 16; i++) {
		_GDPRouterAddress += (char)(0xff);
		_GDPRouterAddress += (char)(0x00);
	}
	
	_logDisplayCounter = 0;
	
	struct timeval tv;
	gettimeofday(&tv, NULL);
	_prevTimeInstant = (1000000 * tv.tv_sec + tv.tv_usec) / 1000000.0; //sec
	
	//web interface
	_webFD = -1;
	_webPort = 0;
}

GDPRouterNat::~GDPRouterNat()
{}

int GDPRouterNat::configure(Vector<String> &conf, ErrorHandler *errh) {
	 if (Args(conf, this, errh)
		.read_mp("SRC", _myInfo.privateIP)
		.read_mp("SPORT", IPPortArg(IP_PROTO_TCP), _myInfo.port)
		.read_mp("DST", _bootStrap.publicIP)
		.read_mp("DPORT", IPPortArg(IP_PROTO_TCP), _bootStrap.port)
		.read_mp("CANBEPROXY", _myInfo.canBeProxy)
		.read_mp("WPORT", IPPortArg(IP_PROTO_TCP), _webPort)
		.complete() < 0)
		return -1;
	
	
	_bootStrap.privateIP = _bootStrap.publicIP;
	_myInfo.publicIP = _myInfo.privateIP;
	_bootStrap.canBeProxy = false; //will just assume bootstrap cant serve as proxy
	
	if (_myInfo == _bootStrap) {
		// I am the first node to join the network and i am a 'P' node
		
		if (PRINT) {
			click_chatter("I am first node in the network\n");
		}
		_myType = 'P';
		_isFirstNode = true;
	}
	return 0;
}

int GDPRouterNat::initialize(ErrorHandler *errh) {
	// create socket
	_localFD = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	_localServer.sin_family = AF_INET;
	_localServer.sin_port = htons(_myInfo.port);
	_localServer.sin_addr.s_addr = INADDR_ANY;
	int localLen = sizeof(_localServer);

	socklen_t sockOptLen = sizeof(int);
	int sendBufSize;
	int err = getsockopt(_localFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);
	if (err < 0) {
		perror("Error in obtaining recv buffer size: \n");
	}

	sendBufSize= sendBufSize * 5;
	err = setsockopt(_localFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize,
							 sizeof(sendBufSize));


	if (bind(_localFD, (struct sockaddr *) &_localServer, localLen) < 0) {
		perror("error binding socket: \n");
		exit(EXIT_FAILURE);
	}
	
	listen(_localFD,5);

	err = getsockopt(_localFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);

	// nonblocking I/O and close-on-exec for the socket
	fcntl(_localFD, F_SETFL, O_NONBLOCK);
	fcntl(_localFD, F_SETFD, FD_CLOEXEC);

	add_select(_localFD, SELECT_READ);
	
	 _pingTimer.initialize(this);   // Initialize timer object (mandatory).
     _pingTimer.schedule_after_sec(5);
     
     if (LOG) {
    	_logTimer.initialize(this);   // Initialize timer object (mandatory).
     	_logTimer.schedule_after_sec(LOG_SAMPLE_RATE);
     }
     
     //web interface
     initialize_webServer();
	
   	ScheduleInfo::initialize_task(this, &_task, errh);
    return 0;
 }
 
 void GDPRouterNat::calculateThroughput(int fd, double _curTimeInstant) {
	map<int, unsigned long>::iterator curRecvIt = _curRecvBytes.find(fd);
	map<int, unsigned long>::iterator curSendIt = _curSendBytes.find(fd);
	
	unsigned long curRecvBytes = 0;
	if (curRecvIt != _curRecvBytes.end()) {
		curRecvBytes = curRecvIt->second;
	}
	
	unsigned long curSendBytes = 0;
	if (curSendIt != _curSendBytes.end()) {
		curSendBytes = curSendIt->second;
	}
	
	double rthroughput = (curRecvBytes) / (_curTimeInstant - _prevTimeInstant);
	double sthroughput = (curSendBytes) / (_curTimeInstant - _prevTimeInstant);
	_recvThroughput[fd] = rthroughput;
	_sendThroughput[fd] = sthroughput;
	
	if (curRecvIt != _curRecvBytes.end()) {
		curRecvIt->second = 0;
	} else {
		_curRecvBytes[fd] = 0;
	}
	
	if (curSendIt != _curSendBytes.end()) {
		curSendIt->second = 0;
	} else {
		_curSendBytes[fd] = 0;
	}
 
 }
 
 void GDPRouterNat::run_timer(Timer *timer) {
     // This function is called when the timer fires.
    if (timer == &_pingTimer) {
    	char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, 0);
		
		char* pingOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* pingPacket = (routePacket *)(pingOffset);
		pingPacket->type = PING;
		pingPacket->src = _myInfo;
		pingPacket->dst = _myInfo;
		pingPacket->numClientAdvertisments = 0;
		pingPacket->numSecondaryAdvertisments = 0;
		pingPacket->numSecondary = 0;
		pingPacket->numPrimary = 0;
		pingPacket->isTypeAssigned = false;
		
		for (map<routeTableEntry, int>::iterator it = _routeTable.begin(); it != _routeTable.end(); it++) {
			int sendFD = it->second;
			if (LOG) {
				_logSendPingNumber[sendFD] = _logSendPingNumber[sendFD] + 1;
				_logSendPingBytes[sendFD] = _logSendPingBytes[sendFD] + sendPacket->length();
			}
			int sentPacket = regulatedWrite(sendFD, sendPacket->data(), sendPacket->length());
			if (sentPacket < 0) {
				perror("Error sending Ping message: ");
			}
		}
		sendPacket->kill();
		_pingTimer.reschedule_after_sec(PING_INTERVAL);  // Fire again PING_INTERVAL seconds later.
	} else if (timer == &_joinTimer) {
		if (nodeJoined == false) {
			click_chatter("The node didn't receive a JOIN_ACK message within the Timeout, EXITING\n");
			exit(EXIT_FAILURE);
		}
	} else if (timer == &_logTimer) {
		struct timeval tv;
		gettimeofday(&tv, NULL);
		double _curTimeInstant = (1000000 * tv.tv_sec + tv.tv_usec) / 1000000.0; //sec
	
		if (_myType == 'P') {
			int numP= _primaryNodes.size();
			for (int i = 0; i < numP; i++) {
				map<routeTableEntry, int>::iterator findFD = _routeTable.find(_primaryNodes[i]);
				if (findFD != _routeTable.end()) {
					calculateThroughput(findFD->second, _curTimeInstant);
				}
			}
		
			for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
				int numS = (it->second).size();
				for (int i = 0; i < numS; i++) {
					map<routeTableEntry, int>::iterator findFD = _routeTable.find((it->second)[i]);
					if (findFD != _routeTable.end()) {
						calculateThroughput(findFD->second, _curTimeInstant);
					}
				}
			}
		} else if (_myType == 'S') {
			for (map<routeTableEntry, int>::iterator it = _routeTable.begin(); it != _routeTable.end(); it++) {
				if ((it->first).publicIP.s_addr != (it->first).privateIP.s_addr) {
					calculateThroughput(it->second, _curTimeInstant);
				}
			}
			calculateThroughput(_proxyFD, _curTimeInstant);
		}
		_prevTimeInstant = _curTimeInstant;
		_logTimer.reschedule_after_sec(LOG_SAMPLE_RATE);
		
	}
 }
 
 
WritablePacket* GDPRouterNat::createGDPPacket(char version, 
										   char cmd,
										   string dst,
										   string src,
										   int packetDataSize) {
	size_t hsz = GDP_HEADER_SIZE;
	WritablePacket *q = Packet::make(hsz + sizeof(routePacket) + packetDataSize);
    memset(q->data(), '\0', hsz);
     
    // Preparing PDU header
    string header;
    
    // adding version
    header += version;
    
    // Adding two more parameters
    for (int i = 0; i < 2; i++) {
    	header += (char)(0x00);
    }
    
    // Adding cmd/ack
    header += cmd;
    
    // Adding dst
    header += dst.substr(0, 32); 
    
    // Adding src
    header += src.substr(0, 32);
    
    // Adding signal
    for (int i = 0; i < 4; i++) {
    	header += (char)(0x00);
    }
    
    // Adding unknown
    for (int i = 0; i < 4; i++) {
    	header += (char)(0x00);
    }
    
    // Adding data len
    unsigned int dataLen = sizeof(routePacket) + packetDataSize;
    for (int i = 4; i > 0; i--) {
    	char d = dataLen >> ((i - 1) * 8);
    	d = d & 0xff;
    	header += d;
    }
    
    memcpy((void *)(q->data()), (void *)(header.c_str()), hsz);
 	return q;
}

bool GDPRouterNat::run_task(Task *) {
	 if (!_isFirstNode) {

		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		WritablePacket* sendPacket = createGDPPacket(version, cmd, dst, src, 0);
		
		char* joinPacketOffset = (char *)(sendPacket->data() + GDP_HEADER_SIZE);
  		routePacket* joinPacket = (routePacket *)(joinPacketOffset);
  		joinPacket->type = JOIN;
  		joinPacket->src = _myInfo;
  		joinPacket->dst = _bootStrap;
  		joinPacket->numClientAdvertisments = 0;
  		joinPacket->numSecondaryAdvertisments = 0;
  		joinPacket->numPrimary = 0;
  		joinPacket->numSecondary = 0;
  		joinPacket->isTypeAssigned = false;
    
    	// socket to bootstrap node
		struct sockaddr_in remoteServer;
     	int clientFD = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
     	remoteServer.sin_family = AF_INET;
     	remoteServer.sin_port = htons(_bootStrap.port);
     	remoteServer.sin_addr = _bootStrap.publicIP;
     	int remoteLen = sizeof(remoteServer);
     	
     	socklen_t sockOptLen = sizeof(int);
		int sendBufSize;
		int err = getsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);
		if (err < 0) {
			perror("Error in obtaining recvBuffer size for socket: \n");
		}

		sendBufSize= sendBufSize * 5;
		err = setsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize,
								 sizeof(sendBufSize));
     	
     	if (connect(clientFD,(struct sockaddr *) &remoteServer, remoteLen) < 0) {
     		perror("Error connecting to remote Bootstrap node: \n");
     		exit(EXIT_FAILURE);
     	}
     	
     	err = getsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);
     	
     	// nonblocking I/O and close-on-exec for the socket
  		fcntl(clientFD, F_SETFL, O_NONBLOCK);
  		fcntl(clientFD, F_SETFD, FD_CLOEXEC);	
		   	
		 _isFDReady[clientFD] = true;
		int sentPacket = regulatedWrite(clientFD, sendPacket->data() , sendPacket->length());
		if (sentPacket < 0) {
			perror("Error sending Join packet to remote socket: \n");
			exit(EXIT_FAILURE);
		}
		
 		add_select(clientFD, SELECT_READ);
 		_bootStrapFD = clientFD;
 		
 		_primaryNodes.push_back(_bootStrap);
 		_routeTable[_bootStrap] = _bootStrapFD;
 		_type[_bootStrapFD] = 'P';
 		
 		_isFDReady[_bootStrapFD] = true;
 		
 		sendPacket->kill();
 		
 		_joinTimer.initialize(this);   // Initialize timer object (mandatory).
     	_joinTimer.schedule_after_sec(JOIN_TIMEOUT);
 		
 		if (PRINT) {
			click_chatter("Sent Join Message to Node: (%s, %d)\n", inet_ntoa(_bootStrap.publicIP), _bootStrap.port);
		}
     } else {
     	//I am First Node will wait for other nodes to join
     }
     
     return true;  // the task did useful work
 }
 
unsigned char GDPRouterNat::_get_byte(int pos, unsigned int seekPtr, const string& bufferData, const string& readData) {
	if (seekPtr + pos < bufferData.length()) {
        return bufferData[seekPtr + pos];
    } else {
    	return readData[seekPtr + pos - bufferData.length()];
    }
}

void GDPRouterNat::selected(int fd, int mask) {

	if (mask & SELECT_WRITE) {
		int BytesToSend = _tempSendBuffer[fd].length();
		string temp = _tempSendBuffer[fd];
		int sentPacket = write(fd, temp.c_str(), temp.length());
		if (sentPacket > 0) {
			if (LOG) {
				_logSendBytes[fd] = _logSendBytes[fd] + sentPacket;
				_curSendBytes[fd] = _curSendBytes[fd] + sentPacket;
			}
			if (sentPacket == BytesToSend) {
				string empty;
				_tempSendBuffer[fd] = empty;
				remove_select(fd, SELECT_READ|SELECT_WRITE);
				add_select(fd, SELECT_READ);
				_isFDReady[fd] = true;
			} else {
				string remainBytes = _tempSendBuffer[fd].substr(sentPacket, BytesToSend - sentPacket);
				_tempSendBuffer[fd] = remainBytes;
			}
		}
	}
	
	if (mask & SELECT_READ) {
		// web server requesting for log
		if (fd == _webFD) {
			struct sockaddr_in clientAddr;
			socklen_t clientAddrLen = sizeof(clientAddr);
			int processFD = accept(_webFD, (struct sockaddr* )&clientAddr, &clientAddrLen);
			if (processFD < 0) {
				perror("Error accepting incoming WEB client connection: ");
				close(processFD);
				return;
			} else {
				int len = read(processFD, _readBuffer, READ_BUF_SIZE);
				sendLogBytes(processFD);
				close(processFD);
				return;
			}
		}
		
		unsigned int bufferDataLen = 0;
		unsigned int readDataLen = 0;
		string readData;
		string bufferData;
		int processFD = -1;
		struct sockaddr_in clientAddr;
		if (fd == _localFD) {
			//Received a new incoming connection
			socklen_t clientAddrLen = sizeof(clientAddr);
			int serverFD = accept(_localFD, (struct sockaddr* )&clientAddr, &clientAddrLen);
			
			if (serverFD < 0) {
				perror("Error accepting incoming client connection: ");
				close(serverFD);
				return;
			} else {
				// nonblocking I/O and close-on-exec for the socket
				fcntl(serverFD, F_SETFL, O_NONBLOCK);
				fcntl(serverFD, F_SETFD, FD_CLOEXEC);
				add_select(serverFD, SELECT_READ);
				int len = read(serverFD, _readBuffer, READ_BUF_SIZE);
				if (len < 0 && errno != EAGAIN) {
					perror("J: ");
					remove_select(serverFD, SELECT_READ);
					close(serverFD);
					return;
				}
				if (len <= 0) {
					if (PRINT) {
						click_chatter("Number of bytes read from a new connection %d\n", len);
					}
					return;
				}
				string bufferTempData(_readBuffer, len);
				_recvBuffer[serverFD] = bufferTempData; 
				bufferDataLen = len;
				readDataLen = 0;
				processFD = serverFD;
				readData = "";
				bufferData = bufferTempData;
				
				if (LOG) {
					_logRecvBytes[processFD] = _logRecvBytes[processFD] + len;
					_curRecvBytes[processFD] = _curRecvBytes[processFD] + len;
				}
			}
		} else {
			int len = read(fd, _readBuffer, READ_BUF_SIZE);
			if (len <= 0) {
				if (PRINT) {
					click_chatter("Number of bytes read from an existing connection %d\n", len);
				}
				handleConnectionFailure(fd);
				return;
			}
			string tempDataBuffer(_readBuffer, len);
			readData = tempDataBuffer;
			readDataLen = len;
			bufferDataLen = _recvBuffer[fd].length();
			bufferData =  _recvBuffer[fd];
			processFD = fd;
			
			if (LOG) {
				_logRecvBytes[processFD] = _logRecvBytes[processFD] + len;
				_curRecvBytes[processFD] = _curRecvBytes[processFD] + len;
			}
		}
	
		//create GDP PDU from buffer and newly read data (TCP reassembly)
		if (PRINT) {
			click_chatter("Number of bytes read and existing in the connection buffer: %d, %d\n", readDataLen, bufferDataLen);
		}
		
		unsigned int seekPtr = 0;
		int status = 0;
		while (seekPtr < bufferDataLen + readDataLen) {
		
			int version = (unsigned int)(_get_byte(0, seekPtr, bufferData, readData));
		
			if (version != 0x02 && version != 0x03) {//bogus version
				if (PRINT) {
					click_chatter("bogus version");
				}
				handleConnectionFailure(processFD);
				status = -1;
				break;
			} 
		
			if ((seekPtr + 80) > (bufferDataLen + readDataLen)) {
				if (PRINT) {
					click_chatter("Incomplete PDU, need atleast 80 bytes\n");
				}
				break;
			}
		
			unsigned int sigLen = (((unsigned int)(_get_byte(72, seekPtr, bufferData, readData)) & 0x0f) << 8) 
									+ (unsigned int)(_get_byte(73, seekPtr, bufferData, readData));
			unsigned int optLen = 4 * (unsigned int)(_get_byte(74, seekPtr, bufferData, readData));
		
			int dataLenIndex = 76;
			unsigned int dataLen = 0;
			for (int i = 0; i < 4; i++) {
				dataLen = (dataLen << 8) + (unsigned int)(_get_byte(dataLenIndex, seekPtr, bufferData, readData));
				dataLenIndex++;
			}
		
			unsigned int pduLen = 80 + dataLen + optLen + sigLen;
			if (PRINT) {
				click_chatter("Recvied packet of length: %d\n", pduLen);
			}
		
			if ((seekPtr + pduLen) > (readDataLen + bufferDataLen)) {
				if (PRINT) {
					click_chatter("Incomplete message\n");
				}
				break;
			}
		
			string message;
			if ((seekPtr + pduLen) <= bufferDataLen) {//entire message in buffer
				//Entire message in buffer;
				message = bufferData.substr(seekPtr, pduLen);
			} else if (seekPtr >= bufferDataLen) { //entire message in newly read data
				//Entire message read newly;
				message = readData.substr(seekPtr - bufferDataLen, pduLen);
			} else {
				//Entire message was split between buffer and newly read data;
				message = bufferData.substr(seekPtr, bufferDataLen - seekPtr);
				message += readData.substr(0, pduLen - (bufferDataLen - seekPtr));
			}
		
			seekPtr += pduLen;
			
			status = processPacket(processFD, message, dataLen, optLen, sigLen, clientAddr.sin_addr);
			if (status < 0) {
				if (PRINT) {
					click_chatter("Something went wrong in packet processing for connection: %d\n", processFD);
				}
			}
		}
	
		// Now update buffer
		string newBufferData;
		if (seekPtr > bufferDataLen) {
			newBufferData = readData.substr(seekPtr - bufferDataLen, (bufferDataLen + readDataLen) - seekPtr);
			_recvBuffer[processFD] = newBufferData;
		} else {
			newBufferData = bufferData.substr(seekPtr, bufferDataLen - seekPtr);
			newBufferData += readData.substr(0, readDataLen);
			_recvBuffer[processFD] = newBufferData;
		}
	}
}

int GDPRouterNat::handleJoinPacket(int recvFD, routePacket* recvPacket, struct in_addr& srcPublicIP) {
	
	struct in_addr srcPrivateIP = (recvPacket->src).privateIP;
	char srcType = 'N';
	if (srcPrivateIP.s_addr == srcPublicIP.s_addr) {
		srcType = 'P';
	} else {
		srcType = 'S';
	}
	(recvPacket->src).publicIP = srcPublicIP;
	
	if (PRINT) {
		click_chatter("Received a Join Message from an %c node: (%s, %d)\n", srcType, inet_ntoa((recvPacket->src).privateIP), (recvPacket->src).port);	
	}
	
	if (srcType == 'P') {
	
		// Create JOIN ACK PACKET
		int numSecondary = 0;
  		for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
  			numSecondary += (it->second).size();
    	}
    	
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = _clientAdvertisments.size() * 32 +
							 _secondaryAdvertisments.size() * sizeof(advertismentEntry) + 
							 numSecondary * sizeof(routeTableEntry) +
							 _primaryNodes.size() * sizeof(routeTableEntry);
							
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		char* joinAckOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* joinAckPacket = (routePacket *)(joinAckOffset);
  		joinAckPacket->type = JOIN_ACK;
  		joinAckPacket->src = _myInfo;
  		joinAckPacket->dst = recvPacket->src;
  		joinAckPacket->numClientAdvertisments = _clientAdvertisments.size();
  		joinAckPacket->numSecondaryAdvertisments = _secondaryAdvertisments.size();
    
  		joinAckPacket->numSecondary = numSecondary;
  		joinAckPacket->numPrimary = _primaryNodes.size();
  		joinAckPacket->isTypeAssigned = true;
  		joinAckPacket->typeAssigned = 'P';
			  
		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
		if (joinAckPacket->numClientAdvertisments > 0) {
			string concatAdvertisments;
			for(map<string, int>::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
					concatAdvertisments += (it->first).substr(0,32);
			}
			memcpy((void *)(sendPacket->data() 
					+ totalHeaderSize), 
				   (void *)concatAdvertisments.c_str(), concatAdvertisments.length());
		}
		
		//Add the Secondary advertisments of all 'S' nodes
		if (joinAckPacket->numSecondaryAdvertisments > 0) {
			char *nsaOffset = (char *)(sendPacket->data() + 
										totalHeaderSize + 
										joinAckPacket->numClientAdvertisments * 32);
			advertismentEntry* nsa = (advertismentEntry *)nsaOffset;
			int i = 0;
			for(map<string, routeTableEntry>::iterator it = _secondaryAdvertisments.begin(); it != _secondaryAdvertisments.end(); it++) {
				strncpy(nsa[i].ID, (it->first).c_str(), 32);
				nsa[i].ID[32] = '\0';
				nsa[i].node = it->second;
				i++; 
			}
		}
		
		// Add all the secondary nodes directly connected to me
		if (joinAckPacket->numSecondary > 0) {
			char *secOffset = (char *)(sendPacket->data() +
										totalHeaderSize +
										joinAckPacket->numClientAdvertisments * 32 +
										joinAckPacket->numSecondaryAdvertisments * sizeof(advertismentEntry));
			routeTableEntry* sec = (routeTableEntry *)secOffset;
			int j = 0;
			for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
				int size  = (it->second).size();
				for (int i = 0; i < size; i++) {
  					sec[j] = (it->second)[i];
  					j++;
  				}
    		}
		}
		
		//Add all the primary nodes
		if (joinAckPacket->numPrimary > 0) {
			char *priOffset = (char *)(sendPacket->data() +
										totalHeaderSize +
										joinAckPacket->numClientAdvertisments * 32 +
										joinAckPacket->numSecondaryAdvertisments * sizeof(advertismentEntry) +
										joinAckPacket->numSecondary * sizeof(routeTableEntry));
			routeTableEntry* pri = (routeTableEntry *)priOffset;
			for (int i = 0; i < joinAckPacket->numPrimary; i++) {
				pri[i] = _primaryNodes[i];
			}
		}
		
		// Nonblocking I/O and close-on-exec for the socket
		fcntl(recvFD, F_SETFL, O_NONBLOCK);
		fcntl(recvFD, F_SETFD, FD_CLOEXEC);
	
		// Sending the Join Ack Packet
		_isFDReady[recvFD] = true;
		int sentPacket = regulatedWrite(recvFD, sendPacket->data() , sendPacket->length());
		if (sentPacket < 0) {
			perror("Error writing Join Ack packet to remote socket: \n");
			remove_select(recvFD, SELECT_READ);
			close(recvFD);
			_isFDReady.erase(recvFD);
			if (LOG) {
				eraseStats(recvFD);
			}
			return -1;
		}
		
		add_select(recvFD, SELECT_READ);
		_primaryNodes.push_back(recvPacket->src);
		_routeTable[recvPacket->src] = recvFD;
		_type[recvFD] = 'P';
		
		sendPacket->kill();
		
		if ((recvPacket->src).canBeProxy == true) {
			// If the new P node can serve as proxy, only then we would inform
			// directly connected S nodes about the new P node
			
			// creating NEW_PRIMARY for directly connected secondary nodes
			packetDataSize = sizeof(routeTableEntry);
			sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
			char* newPrimaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
			routePacket* newPrimaryPacket = (routePacket *)(newPrimaryOffset);
			newPrimaryPacket->type = NEW_PRIMARY;
			newPrimaryPacket->src = _myInfo;
			newPrimaryPacket->numClientAdvertisments = 0;
			newPrimaryPacket->numSecondaryAdvertisments = 0;
			newPrimaryPacket->numSecondary = 0;
			newPrimaryPacket->numPrimary = 1;
			newPrimaryPacket->isTypeAssigned = false;
			memcpy((void *)(sendPacket->data() + totalHeaderSize), &(recvPacket->src), sizeof(routeTableEntry));
	
			//Sending NEW_PRIMARY to all directly connected secondary nodes
			for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
				int size = (it->second).size();
				for (int i = 0; i < size; i++) {
					routeTableEntry s = (it->second)[i];
			
					routePacket* r = (routePacket *)(sendPacket->data());
					r->dst = s;
				
					map<routeTableEntry, int>::iterator findFD = _routeTable.find(s);
					if (findFD != _routeTable.end()) {
						int sendFD = findFD->second;
						int sentPacket = regulatedWrite(sendFD, sendPacket->data() , sendPacket->length());
						if (PRINT) {
							string pubIP(inet_ntoa(s.publicIP));
							string priIP(inet_ntoa(s.privateIP));
							click_chatter("Sending NEW_PRIMARY to node (%s, %s, %d)\n", pubIP.c_str(), priIP.c_str(), s.port);
						}
				
						if (sentPacket < 0) {
							perror("Error writing New Primary packet to remote socket: \n");
						}
					} else {
						string pubIP(inet_ntoa(s.publicIP));
						string priIP(inet_ntoa(s.privateIP));
						click_chatter("I dont have the file descriptor for the secondary node (%s, %s, %d) \n", 
										pubIP.c_str(), priIP.c_str(), s.port);
					}
				}
			}
			sendPacket->kill();
		}
		
		if (PRINT) {
			click_chatter("Sent JOIN_ACK to Primary Node\n");
		}

	} else if (srcType == 'S') {
		// create Join Packet
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		
		//int packetDataSize = _primaryNodes.size() * sizeof(routeTableEntry);
		int numProxies = 0;
		int numP = _primaryNodes.size();
		for (int i = 0; i < numP; i++) {
			if (_primaryNodes[i].canBeProxy == true) {
				numProxies++;
			}
		}
		int packetDataSize = numProxies * sizeof(routeTableEntry);
		
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char *joinAckOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* joinAckPacket = (routePacket *)(joinAckOffset);
  		joinAckPacket->type = JOIN_ACK;
  		joinAckPacket->src = _myInfo;
  		joinAckPacket->dst = recvPacket->src;
  		joinAckPacket->numClientAdvertisments = 0;
  		joinAckPacket->numSecondaryAdvertisments = 0;
  		joinAckPacket->numSecondary = 0;
  		joinAckPacket->numPrimary = numProxies;
  		joinAckPacket->isTypeAssigned = true;
  		joinAckPacket->typeAssigned = 'S';
  		
  		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
				
		// Add all the primary nodes
		if (joinAckPacket->numPrimary > 0) {
			char* priOffset = (char *)(sendPacket->data() +
										totalHeaderSize);
			routeTableEntry* pri = (routeTableEntry *)priOffset;
			for (int i = 0; i < numP; i++) {
				if (_primaryNodes[i].canBeProxy == true) {
					pri[i] = _primaryNodes[i];
				}
				
				if (PRINT) {
					click_chatter("placing node inside ack message(%s, %d)\n", inet_ntoa(pri[i].publicIP), pri[i].port);
				}
			}
		}
		
		// Nonblocking I/O and close-on-exec for the socket
		fcntl(recvFD, F_SETFL, O_NONBLOCK);
		fcntl(recvFD, F_SETFD, FD_CLOEXEC);
	
		// Sending the Join Ack Packet
		_isFDReady[recvFD] = true;
		int sentPacket = regulatedWrite(recvFD, sendPacket->data() , sendPacket->length());
		if (sentPacket < 0) {
			perror("Error writing Join Ack packet to remote socket: \n");
			remove_select(recvFD, SELECT_READ);
			close(recvFD);
			_isFDReady.erase(recvFD);
			if (LOG) {
				eraseStats(recvFD);
			}
			return -1;
		}
		
		// close the connection and forget about the node
		if (PRINT) {
			string pubIP(inet_ntoa((joinAckPacket->dst).publicIP));
			string priIP(inet_ntoa((joinAckPacket->dst).privateIP));
			click_chatter("sent JOIN_ACK to Secondary Node (%s, %s, %d)\n", pubIP.c_str(), priIP.c_str(), (joinAckPacket->dst).port);
		}
		remove_select(recvFD, SELECT_READ);
		close(recvFD);
		_isFDReady.erase(recvFD);
		if (LOG) {
			eraseStats(recvFD);
		}
		sendPacket->kill();
	}
	return 0;
}

int GDPRouterNat::handleJoinAckPacket(int recvFD, routePacket* recvPacket) {
	nodeJoined = true;
	if (recvPacket->isTypeAssigned == true) {
		_myType = recvPacket->typeAssigned;
		_myInfo = recvPacket->dst;
	}
	
	if (PRINT) {
		click_chatter("Received a JOIN_ACK message\n");
		click_chatter("I AM NOW a %c NODE\n", _myType);	
		string pubIP(inet_ntoa(_myInfo.publicIP));
		string priIP(inet_ntoa(_myInfo.privateIP));
		click_chatter("MY info: PUBLIC IP: %s, PRIVATE IP: %s, PORT: %d\n", pubIP.c_str(), priIP.c_str(), _myInfo.port);
	}
	
	if (_myType == 'P') {
		// determine if the bootstrap can serve as proxy and update
		// this is important as we initially assume bootstrap is not proxy
		if ((recvPacket->src).canBeProxy == true) {
			_bootStrap.canBeProxy = true;
			
			// at present, there is only one entry in the _primaryNodes
			// the bootstrap
			_primaryNodes[0].canBeProxy = true;
		}
		
		int numClientAdvertisments = recvPacket->numClientAdvertisments;
		int numSecondaryAdvertisments = recvPacket->numSecondaryAdvertisments;
		int numSecondary = recvPacket->numSecondary;
		int numPrimary = recvPacket->numPrimary;
		
		//Update _primaryAdvertisments
		if (numClientAdvertisments > 0) {
			char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
				
			// for each advertisement sent by bootstrap create an entry in _primaryAdvertisments
			for (int i = 0; i < numClientAdvertisments; i++) {
				string key(seekPtr, 32);
				_primaryAdvertisments[key] = recvPacket->src;
				seekPtr += 32;
			}
		}
		
		//Update _secondaryAdvertisments
		if (numSecondaryAdvertisments > 0) {
			const char *SecAdvOffset = (char *)recvPacket 
										+ sizeof(routePacket) 
										+ 32 * numClientAdvertisments;
			advertismentEntry* sec = (advertismentEntry *)SecAdvOffset;
			for (int i = 0; i < numSecondaryAdvertisments; i++) {
				string key(sec[i].ID);
				_secondaryAdvertisments[sec[i].ID] = sec[i].node;
			}
		}
		
		//Update _routeTable for the secondary nodes sent
		if (numSecondary > 0) {
			const char *secOffset = (char *)recvPacket 
										+ sizeof(routePacket) 
										+ 32 * numClientAdvertisments
										+ numSecondaryAdvertisments * sizeof(advertismentEntry);
			routeTableEntry* sec = (routeTableEntry *)secOffset;
			for (int i = 0; i < numSecondary; i++) {
				_routeTable[sec[i]] = recvFD;
			}
		}
		
		//Connect to all other primary
		if (numPrimary > 0) {
			const char *priOffset = (char *)recvPacket 
										+ sizeof(routePacket) 
										+ 32 * numClientAdvertisments
										+ numSecondaryAdvertisments * sizeof(advertismentEntry)
										+ numSecondary * sizeof(routeTableEntry);
			routeTableEntry* pri = (routeTableEntry *)priOffset;
			
			//Create an ADD_PRIMARY message
			char version = (char)(VERSION);
			char cmd = (char)(ROUTE_PROTOCOL);
			string dst = _GDPRouterAddress;
			string src = _GDPRouterAddress;
			int packetDataSize = _clientAdvertisments.size() * 32;
			WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
			
			char *addPrimaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
			routePacket* addPrimaryPacket = (routePacket *)(addPrimaryOffset);
			addPrimaryPacket->type = ADD_PRIMARY;
			addPrimaryPacket->src = _myInfo;
			addPrimaryPacket->numClientAdvertisments = _clientAdvertisments.size();
			addPrimaryPacket->numSecondaryAdvertisments = 0;
			addPrimaryPacket->numSecondary = 0;
			addPrimaryPacket->numPrimary = 0;
			addPrimaryPacket->isTypeAssigned = false;
			
			int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
			if (addPrimaryPacket->numClientAdvertisments > 0) {
				string concatAdvertisments;
				for(map<string, int>::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
						concatAdvertisments += (it->first).substr(0,32);
				}
				memcpy((void *)(sendPacket->data() 
						+ totalHeaderSize), 
					   (void *)concatAdvertisments.c_str(), concatAdvertisments.length());
			}
			
			// send ADD_PRIMARY to each 'P' node
			for (int i = 0; i < numPrimary; i++) {
				routePacket* routePacketOffset = (routePacket *)(sendPacket->data());
				routePacketOffset->dst = pri[i];
				
				struct sockaddr_in remoteServer;
				int clientFD = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
				remoteServer.sin_family = AF_INET;
				remoteServer.sin_port = htons(pri[i].port);
				remoteServer.sin_addr = pri[i].publicIP;
				int remoteLen = sizeof(remoteServer);
	
				socklen_t sockOptLen = sizeof(int);
				int sendBufSize;
				int err = getsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);
				if (err < 0) {
					perror("Error in obtaining recvbuffer size for socket\n");
				}


				sendBufSize= sendBufSize * 5;
				err = setsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize,
										 sizeof(sendBufSize));

				if (connect(clientFD,(struct sockaddr *) &remoteServer, remoteLen) < 0) {
					perror("error connecting to remote socket: \n");
					//exit(EXIT_FAILURE);
					continue;
				}
	
				err = getsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);


				// nonblocking I/O and close-on-exec for the socket
				fcntl(clientFD, F_SETFL, O_NONBLOCK);
				fcntl(clientFD, F_SETFD, FD_CLOEXEC);	

				//sending ADD packet
				_isFDReady[clientFD] = true;
				int sentPacket = regulatedWrite(clientFD, sendPacket->data() , sendPacket->length());
				if (sentPacket < 0) {
					perror("Error writing packet to remote socket: \n");
					_isFDReady.erase(clientFD);
				} else {
					add_select(clientFD, SELECT_READ);
					_primaryNodes.push_back(pri[i]);
					_routeTable[pri[i]] = clientFD;
					_type[clientFD] = 'P';
					
					if (PRINT) {
						click_chatter("Sent ADD_PRIMARY to node (%s, %d) \n", inet_ntoa(pri[i].publicIP), pri[i].port);
					}
				}
				
			}
			
			sendPacket->kill();
		}
	} else if (_myType == 'S') {
		
		// close connection to bootstrap
		_routeTable.erase(_bootStrap);
 		_type.erase(recvFD);
 		
 		_isFDReady.erase(recvFD);
 		remove_select(recvFD, SELECT_READ);
 		if (LOG) {
			eraseStats(recvFD);
		}
		close(recvFD);
		
		if ((recvPacket->src).canBeProxy == false) {
			// removing the bootstrap from the _primaryNodes list
			// as it may not be able to serve as a proxy
			// currently the _primaryNodes holds only one entry (bootstrap)
			_primaryNodes.clear();
		}
		
		int numPrimary = recvPacket->numPrimary;
		const char *priOffset = (char *)(recvPacket) + sizeof(routePacket);
		routeTableEntry* pri = (routeTableEntry *)priOffset;
		for (int i = 0; i < numPrimary; i++) {
			_primaryNodes.push_back(pri[i]);
			
			if (PRINT) {
				click_chatter("placing node in primary list (%s, %d)\n", inet_ntoa(pri[i].publicIP), pri[i].port);
			}
		}
		
		//Create an JOIN_SECONDARY message
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = _clientAdvertisments.size() * 32;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char* joinSecondaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* joinSecondaryPacket = (routePacket *)(joinSecondaryOffset);
		joinSecondaryPacket->type = JOIN_SECONDARY;
		joinSecondaryPacket->src = _myInfo;
		joinSecondaryPacket->numClientAdvertisments = _clientAdvertisments.size();
		joinSecondaryPacket->numSecondaryAdvertisments = 0;
		joinSecondaryPacket->numSecondary = 0;
		joinSecondaryPacket->numPrimary = 0;
		joinSecondaryPacket->isTypeAssigned = false;
		
		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
		if (joinSecondaryPacket->numClientAdvertisments > 0) {
			string concatAdvertisments;
			for(map<string, int >::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
					concatAdvertisments += (it->first).substr(0,32);
			}
			memcpy((void *)(sendPacket->data() 
					+ totalHeaderSize), 
				   (void *)concatAdvertisments.c_str(), concatAdvertisments.length());
		}
		
		// chose a proxy 
		findProxyAndConnect(sendPacket);
		
		if (PRINT) {
			click_chatter("Chosen Proxy is (%s, %d)\n", inet_ntoa(_primaryNodes[_proxyIndex].publicIP), _primaryNodes[_proxyIndex].port);
		}
		sendPacket->kill();
	}
	return 0;
}

int GDPRouterNat::handleAddPrimary(int recvFD, routePacket* recvPacket) {
	if (PRINT) {
		click_chatter("Received an ADD_PRIMARY message from: (%s, %d)\n", inet_ntoa((recvPacket->src).publicIP), (recvPacket->src).port);	
	}
	int numClientAdvertisments = recvPacket->numClientAdvertisments;
	
	// Update _primaryAdvertisments
	if (numClientAdvertisments > 0) {
		char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
			
		// for each advertisement sent by new primary node, create an entry in _primaryAdvertisments
		for (int i = 0; i < numClientAdvertisments; i++) {
			string key(seekPtr, 32);
			_primaryAdvertisments[key] = recvPacket->src;
			seekPtr += 32;
		}
	}
	
	//Create ADD_PRIMARY_ACK Packet
	int numSecondary = 0;
	for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
		numSecondary += (it->second).size();
	}
	char version = (char)(VERSION);
	char cmd = (char)(ROUTE_PROTOCOL);
	string dst = _GDPRouterAddress;
	string src = _GDPRouterAddress;
	int packetDataSize = _clientAdvertisments.size() * 32
						  + _secondaryAdvertisments.size() * sizeof(advertismentEntry)
						  + numSecondary * sizeof(routeTableEntry)
						  + _primaryNodes.size() * sizeof(routeTableEntry);
	WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
	
	char *addPrimaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
	routePacket* addPrimaryAckPacket = (routePacket *)(addPrimaryOffset);
	addPrimaryAckPacket->type = ADD_PRIMARY_ACK;
	addPrimaryAckPacket->src = _myInfo;
	addPrimaryAckPacket->dst = recvPacket->src;
	addPrimaryAckPacket->numClientAdvertisments = _clientAdvertisments.size();
	addPrimaryAckPacket->numSecondaryAdvertisments = _secondaryAdvertisments.size();

	addPrimaryAckPacket->numSecondary = numSecondary;
	addPrimaryAckPacket->numPrimary = _primaryNodes.size();
	addPrimaryAckPacket->isTypeAssigned = false;
	
	int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
				
	//Add the number of directly connected client advertisments to the message							  
	if (addPrimaryAckPacket->numClientAdvertisments > 0) {
		string concatAdvertisments;
		for(map<string, int >::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
				concatAdvertisments += (it->first).substr(0,32);
		}
		memcpy((void *)(sendPacket->data() 
				+ totalHeaderSize), 
			   (void *)concatAdvertisments.c_str(), concatAdvertisments.length());
	}
		
	//Add the Secondary advertisments of all 'S' nodes
	if (addPrimaryAckPacket->numSecondaryAdvertisments > 0) {
		char* nsaOffset = (char *)(sendPacket->data() +
									totalHeaderSize +
									addPrimaryAckPacket->numClientAdvertisments * 32);
		advertismentEntry* nsa = (advertismentEntry *)nsaOffset;
		int i = 0;
		for(map<string, routeTableEntry>::iterator it = _secondaryAdvertisments.begin(); it != _secondaryAdvertisments.end(); it++) {
			strncpy(nsa[i].ID, (it->first).c_str(), 32);
			nsa[i].ID[32] = '\0';
			nsa[i].node = it->second;
			i++; 
		}
	}
		
	// Add all the secondary nodes directly connected to me
	if (addPrimaryAckPacket->numSecondary > 0) {
		char* secOffset = (char *)(sendPacket->data() +
									totalHeaderSize +
									addPrimaryAckPacket->numClientAdvertisments * 32 +
									addPrimaryAckPacket->numSecondaryAdvertisments * sizeof(advertismentEntry));
		routeTableEntry* sec = (routeTableEntry *)secOffset;
		int j = 0;
		for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
			int size = (it->second).size();
			for (int i = 0; i < size; i++) {
				sec[j] = (it->second)[i];
				j++;
			}
		}
	}
		
	//Add all the primary nodes
	if (addPrimaryAckPacket->numPrimary > 0) {
		char* priOffset = (char *)(sendPacket->data() +
									totalHeaderSize +
									addPrimaryAckPacket->numClientAdvertisments * 32 +
									addPrimaryAckPacket->numSecondaryAdvertisments * sizeof(advertismentEntry) +
									addPrimaryAckPacket->numSecondary * sizeof(routeTableEntry));
		routeTableEntry* pri = (routeTableEntry *)priOffset;
		for (int i = 0; i < addPrimaryAckPacket->numPrimary; i++) {
			pri[i] = _primaryNodes[i];
		}
	}
	
	// Nonblocking I/O and close-on-exec for the socket
	fcntl(recvFD, F_SETFL, O_NONBLOCK);
	fcntl(recvFD, F_SETFD, FD_CLOEXEC);
	
	// Sending the ADD_PRIMARY_ACK Packet
	_isFDReady[recvFD] = true;
	int sentPacket = regulatedWrite(recvFD, sendPacket->data() , sendPacket->length());
	if (sentPacket < 0) {
		perror("Error writing ADD Primary Ack packet to remote socket: \n");
		remove_select(recvFD, SELECT_READ);
		close(recvFD);
		_isFDReady.erase(recvFD);
		if (LOG) {
			eraseStats(recvFD);
		}
		return -1;
	}
	
	if (PRINT) {
		click_chatter("Sent ADD_PRIMARY_ACK back to node\n");	
	}
	sendPacket->kill();
	
	if ((recvPacket->src).canBeProxy == true) {
		// Inform all directly connected S nodes about the new P node
		// if the new P node can serve as a proxy
		
		// creating NEW_PRIMARY for directly connected secondary nodes
		version = (char)(VERSION);
		cmd = (char)(ROUTE_PROTOCOL);
		dst = _GDPRouterAddress;
		src = _GDPRouterAddress;
		packetDataSize = sizeof(routeTableEntry);
		sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
	
		char *newPrimaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* newPrimaryPacket = (routePacket *)(newPrimaryOffset);
		newPrimaryPacket->type = NEW_PRIMARY;
		newPrimaryPacket->src = _myInfo;
		newPrimaryPacket->numClientAdvertisments = 0;
		newPrimaryPacket->numSecondaryAdvertisments = 0;
		newPrimaryPacket->numSecondary = 0;
		newPrimaryPacket->numPrimary = 1;
		newPrimaryPacket->isTypeAssigned = false;
	
		memcpy((void *)(sendPacket->data() + totalHeaderSize), &(recvPacket->src), sizeof(routeTableEntry));
	
		//Sending NEW_PRIMARY to all directly connected secondary nodes
		for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
			int size = (it->second).size();
			for (int i = 0; i < size; i++) {
				routeTableEntry s = (it->second)[i];
			
				routePacket* r = (routePacket *)(sendPacket->data());
				r->dst = s;
			
				map<routeTableEntry, int>::iterator findFD = _routeTable.find(s);
				if (findFD != _routeTable.end()) {
					int sendFD = findFD->second;
					int sentPacket = regulatedWrite(sendFD, sendPacket->data() , sendPacket->length());
					if (PRINT) {
						string pubIP(inet_ntoa(s.publicIP));
						string priIP(inet_ntoa(s.privateIP));
						click_chatter("Sending NEW_PRIMARY to node (%s, %s, %d), %d\n", pubIP.c_str(), priIP.c_str(), s.port, _routeTable[s]);
					}
				
					if (sentPacket < 0) {
						perror("Error writing New Primary packet to remote socket: \n");
					}
				} else {
					string pubIP(inet_ntoa(s.publicIP));
					string priIP(inet_ntoa(s.privateIP));
					click_chatter("I dont have the file descriptor for secondary node (%s, %s, %d), %d\n", pubIP.c_str(), priIP.c_str(), s.port);
				}
			}
		}
		sendPacket->kill();
	}
		
	routeTableEntry newPrimary = recvPacket->src;
	
	//Update _primaryNodes
	_primaryNodes.push_back(newPrimary);
	
	//Update _routeTables
	_routeTable[newPrimary] = recvFD;
	
	// Update type
	_type[recvFD] = 'P';
	
	add_select(recvFD, SELECT_READ);
	return 0;
}

int GDPRouterNat::handleAddPrimaryAck(int recvFD, routePacket* recvPacket) {
	if (PRINT) {
		click_chatter("Received ADD_PRIMARY_ACK from node (%s, %d) \n", inet_ntoa((recvPacket->src).publicIP), (recvPacket->src).port);	
	}
	int numClientAdvertisments = recvPacket->numClientAdvertisments;
	int numSecondaryAdvertisments = recvPacket->numSecondaryAdvertisments;
	int numSecondary = recvPacket->numSecondary;
	int numPrimary = recvPacket->numPrimary;
	
	//Update _primaryAdvertisments
	if (numClientAdvertisments > 0) {
		char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
			
		// for each advertisement sent by bootstrap create an entry in _primaryAdvertisments
		for (int i = 0; i < numClientAdvertisments; i++) {
			string key(seekPtr, 32);
			_primaryAdvertisments[key] = recvPacket->src;
			seekPtr += 32;
		}
	}
	
	//Update _secondaryAdvertisments
	if (numSecondaryAdvertisments > 0) {
		const char *SecAdvOffset = (char *)recvPacket 
									+ sizeof(routePacket) 
									+ 32 * numClientAdvertisments;
		advertismentEntry* sec = (advertismentEntry *)SecAdvOffset;
		for (int i = 0; i < numSecondaryAdvertisments; i++) {
			string key(sec[i].ID);
			_secondaryAdvertisments[key] = sec[i].node;
		}
	}
	
	//Update _routeTable for the secondary nodes sent
	if (numSecondary > 0) {
		const char *secOffset = (char *)recvPacket 
									+ sizeof(routePacket) 
									+ 32 * numClientAdvertisments
									+ numSecondaryAdvertisments * sizeof(advertismentEntry);
		routeTableEntry* sec = (routeTableEntry *)secOffset;
		for (int i = 0; i < numSecondary; i++) {
			_routeTable[sec[i]] = recvFD;
		}
	}
	
	//Connect to all other primary nodes not in my _routeTable
	if (numPrimary > 0) {
		const char *priOffset = (char *)recvPacket 
									+ sizeof(routePacket) 
									+ 32 * numClientAdvertisments
									+ numSecondaryAdvertisments * sizeof(advertismentEntry)
									+ numSecondary * sizeof(routeTableEntry);
		routeTableEntry* pri = (routeTableEntry *)priOffset;
		
		//Create an ADD_PRIMARY message
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = _clientAdvertisments.size() * 32;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char *addPrimaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* addPrimaryPacket = (routePacket *)(addPrimaryOffset);
		addPrimaryPacket->type = ADD_PRIMARY;
		addPrimaryPacket->src = _myInfo;
		addPrimaryPacket->numClientAdvertisments = _clientAdvertisments.size();
		addPrimaryPacket->numSecondaryAdvertisments = 0;
		addPrimaryPacket->numSecondary = 0;
		addPrimaryPacket->numPrimary = 0;
		addPrimaryPacket->isTypeAssigned = false;
		
		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
		if (addPrimaryPacket->numClientAdvertisments > 0) {
			string concatAdvertisments;
			for(map<string, int >::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
					concatAdvertisments += (it->first).substr(0,32);
			}
			memcpy((void *)(sendPacket->data() 
					+ totalHeaderSize), 
				   (void *)concatAdvertisments.c_str(), concatAdvertisments.length());
		}
		
		// send ADD_PRIMARY to each 'P' node not already connected to
		for (int i = 0; i < numPrimary; i++) {
			std::map<routeTableEntry,int>::iterator it;
			
			// check wether the primary node is already present in _routeTable
  			it = _routeTable.find(pri[i]);
  			
  			// Send ADD PRIMARY to only those P nodes not present in _routeTable
 			if (it == _routeTable.end()) {
				routePacket* routePacketOffset = (routePacket *)(sendPacket->data());
				routePacketOffset->dst = pri[i];
		
				struct sockaddr_in remoteServer;
				int clientFD = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
				remoteServer.sin_family = AF_INET;
				remoteServer.sin_port = htons(pri[i].port);
				remoteServer.sin_addr = pri[i].publicIP;
				int remoteLen = sizeof(remoteServer);

				socklen_t sockOptLen = sizeof(int);
				int sendBufSize;
				int err = getsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);
				if (err < 0) {
					perror("Error in obtaining recvBuffer size for socket: \n");
				}


				sendBufSize= sendBufSize * 5;
				err = setsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize,
										 sizeof(sendBufSize));

				if (connect(clientFD,(struct sockaddr *) &remoteServer, remoteLen) < 0) {
					perror("error connecting to remote socket: \n");
					//exit(EXIT_FAILURE);
					continue;
				}

				err = getsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);


				// nonblocking I/O and close-on-exec for the socket
				fcntl(clientFD, F_SETFL, O_NONBLOCK);
				fcntl(clientFD, F_SETFD, FD_CLOEXEC);	

				//sending ADD packet
				_isFDReady[clientFD] = true;
				int sentPacket = regulatedWrite(clientFD, sendPacket->data() , sendPacket->length());
				if (sentPacket < 0) {
					perror("Error writing packet to remote socket: \n");
					_isFDReady.erase(clientFD);
				} else {
					add_select(clientFD, SELECT_READ);
					_primaryNodes.push_back(pri[i]);
					_routeTable[pri[i]] = clientFD;
					_type[clientFD] = 'P';
					
					if (PRINT) {
						click_chatter("Sent ADD_PRIMARY to node (%s, %d) \n", inet_ntoa(pri[i].publicIP), pri[i].port);
					}
				}
			}
		}
		
		sendPacket->kill();
	}
	return 0;
}

int GDPRouterNat::handleNewPrimary(routePacket* recvPacket) {
	if (PRINT) {
		click_chatter("Received a NEW_PRIMARY from (%s, %d) \n", inet_ntoa((recvPacket->src).publicIP), (recvPacket->src).port);
	}
	char* rOffset = (char *)(recvPacket) + sizeof(routePacket);
	routeTableEntry* r = (routeTableEntry *)(rOffset);
	
	if (PRINT) {
		click_chatter("Added NEW PRIMARY node (%s, %d) \n", inet_ntoa(r->publicIP), r->port);	
	}
	_primaryNodes.push_back(*r);
	return 0;
}

int GDPRouterNat::handleWithdrawPrimary(routePacket* recvPacket) {
	if (PRINT) {
		click_chatter("Received a WITHDRAW_PRIMARY from (%s, %d) \n", inet_ntoa((recvPacket->src).publicIP), (recvPacket->src).port);
	}
	
	char* rOffset = (char *)(recvPacket) + sizeof(routePacket);
	routeTableEntry* r = (routeTableEntry *)(rOffset);
	
	if (PRINT) {
		click_chatter("REMOVING PRIMARY node (%s, %d) \n", inet_ntoa(r->publicIP), r->port);	
	}
	
	int findIndex = -1;
	int numP = _primaryNodes.size();
	for (int i = 0; i < numP; i++) {
		if (_primaryNodes[i] == *r) {
			findIndex = i;
			break;
		}
	}
	
	if (findIndex >= 0) {
		_primaryNodes.erase(_primaryNodes.begin() + findIndex);
	} else {
		click_chatter("Error, The failed P node is not my _primaryNodes list\n");
	}
	return 0;
}

int GDPRouterNat::handleJoinSecondary(int recvFD, routePacket* recvPacket) {
	if (PRINT) {
		string pubIP(inet_ntoa((recvPacket->src).publicIP));
		string priIP(inet_ntoa((recvPacket->src).privateIP));
		click_chatter("Received a JOIN_SECONDARY from node (%s, %s, %d) , %d \n", 
						pubIP.c_str(), priIP.c_str(), (recvPacket->src).port, recvFD);	
	}
	if (_myType =='P') {
	
		//Update Route Table
		add_select(recvFD, SELECT_READ);
		
		int one = 1;
		setsockopt(recvFD, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
		
		routeTableEntry newSecondary = recvPacket->src;
		_routeTable[newSecondary] = recvFD;
		
		// Update type
		_type[recvFD] = 'S';
		
		// Update _secondaryAdvertisments
		int numClientAdvertisments = recvPacket->numClientAdvertisments;
		if (numClientAdvertisments > 0) {
			char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
				
			// for each advertisement sent by bootstrap create an entry in _primaryAdvertisments
			for (int i = 0; i < numClientAdvertisments; i++) {
				string key(seekPtr, 32);
				_secondaryAdvertisments[key] = newSecondary;
				seekPtr += 32;
			}
		}
		
		//create NEW SECONDARY to inform other 'P' nodes, a new 'S' node joined in
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = numClientAdvertisments * 32
							 + sizeof(routeTableEntry);
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char *newSecondaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* newSecondaryPacket = (routePacket *)(newSecondaryOffset);
		newSecondaryPacket->type = NEW_SECONDARY;
		newSecondaryPacket->src = _myInfo;
		newSecondaryPacket->numClientAdvertisments = 0;
		newSecondaryPacket->numSecondaryAdvertisments = numClientAdvertisments;
		newSecondaryPacket->numSecondary = 1;
		newSecondaryPacket->numPrimary = 0;
		newSecondaryPacket->isTypeAssigned = 0;
		
		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
		char* advPtr = (char *)(recvPacket) + sizeof(routePacket);
		
		if (newSecondaryPacket->numSecondaryAdvertisments > 0) {
			memcpy((void *)(sendPacket->data() + totalHeaderSize),
					(void *)(advPtr), newSecondaryPacket->numSecondaryAdvertisments * 32);
		}
		
		memcpy((void *)(sendPacket->data()
						+ totalHeaderSize
						+ newSecondaryPacket->numSecondaryAdvertisments * 32),
				(void *)(&newSecondary), sizeof(routeTableEntry));
				
		// Send NEW SECONDARY PACKET to all primary nodes
		int numPnodes = _primaryNodes.size();
		for (int i = 0; i < numPnodes; i++) {
		 	routePacket* routePacketOffset = (routePacket *)(sendPacket->data());
			routePacketOffset->dst = _primaryNodes[i];
			
			map<routeTableEntry, int>::iterator findFD = _routeTable.find(_primaryNodes[i]);
			
			if (findFD != _routeTable.end()) {
				int sendFD = findFD->second;
				int sentPacket = regulatedWrite(sendFD, sendPacket->data() , sendPacket->length());
			
				if (PRINT) {
					click_chatter("Sending NEW_SECONDARY to primary node (%s, %d) \n", inet_ntoa(_primaryNodes[i].publicIP),
									_primaryNodes[i].port);
				}
				
				if (sentPacket < 0) {
					perror("Error writing packet to remote socket: \n");
				}
			} else {
				click_chatter("I dont have the file descriptor for primary node (%s, %d) \n", inet_ntoa(_primaryNodes[i].publicIP),
									_primaryNodes[i].port);
			}
		}
		
		// Send NEW SECONDARY to all secondary nodes directly connected to me and
		// with same public IP as the new node
		std::map<unsigned long, vector<routeTableEntry> >::iterator it;

  		it = _publicToPrivate.find(newSecondary.publicIP.s_addr);
  		if (it != _publicToPrivate.end()) {
  			int numSnodes = (it->second).size();
  			for (int i = 0; i < numSnodes; i++) {
  				routePacket* routePacketOffset = (routePacket *)(sendPacket->data());
				routePacketOffset->dst = (it->second)[i];
				
				map<routeTableEntry, int>::iterator findFD = _routeTable.find((it->second)[i]);
				
				if (findFD != _routeTable.end()) {
					int sendFD = findFD->second;
					int sentPacket = regulatedWrite(sendFD, sendPacket->data() , sendPacket->length());
				
					if (PRINT) {
						string pubIP(inet_ntoa((routePacketOffset->dst).publicIP));
						string priIP(inet_ntoa((routePacketOffset->dst).privateIP));
						click_chatter("Sending NEW_SECONDARY to secondary node (%s, %s, %d) \n",
										pubIP.c_str(), priIP.c_str(), (routePacketOffset->dst).port);
					}
				
					if (sentPacket < 0) {
						perror("Error writing packet to remote socket: \n");
					}
				} else {
					string pubIP(inet_ntoa((routePacketOffset->dst).publicIP));
					string priIP(inet_ntoa((routePacketOffset->dst).privateIP));
					click_chatter("I dont have the file descriptor for the secondary node (%s, %s, %d) \n",
									pubIP.c_str(), priIP.c_str(), (routePacketOffset->dst).port);
				}
  			}
  		}
  		
		sendPacket->kill();
		
		// Update _publicToPrivate
		_publicToPrivate[newSecondary.publicIP.s_addr].push_back(newSecondary);
		
		// Create JOIN_SECONDARY_ACK packet containing all the primary nodes
		// The new Secondary node has to be made aware of all new primary nodes
		// that joined the network after the secondary node had received a JOIN message from
		// its bootstrap node
		version = (char)(VERSION);
		cmd = (char)(ROUTE_PROTOCOL);
		dst = _GDPRouterAddress;
		src = _GDPRouterAddress;
		
		int numP = _primaryNodes.size();
		int numProxies = 0;
		for (int i = 0; i < numP; i++) {
			if (_primaryNodes[i].canBeProxy == true) {
				numProxies++;
			}
		}
		
		packetDataSize = numProxies * sizeof(routeTableEntry);
		sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char *joinSecondaryAckOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* joinSecondaryAckPacket = (routePacket *)(joinSecondaryAckOffset);
		joinSecondaryAckPacket->type = JOIN_SECONDARY_ACK;
		joinSecondaryAckPacket->src = _myInfo;
		joinSecondaryAckPacket->dst = newSecondary;
		joinSecondaryAckPacket->numClientAdvertisments = 0;
		joinSecondaryAckPacket->numSecondaryAdvertisments = 0;
		joinSecondaryAckPacket->numSecondary = 0;
	    joinSecondaryAckPacket->numPrimary = numProxies;
	    joinSecondaryAckPacket->isTypeAssigned = false;
		
		//Add all the primary nodes
		if (joinSecondaryAckPacket->numPrimary > 0) {
			char *priOffset = (char *)(sendPacket->data() + totalHeaderSize);
			routeTableEntry* pri = (routeTableEntry *)priOffset;
			for (int i = 0; i < numP; i++) {
				if (_primaryNodes[i].canBeProxy == true) {
					pri[i] = _primaryNodes[i];
				}
			}
		}
		
		_isFDReady[recvFD] = true;
		int sentPacket = regulatedWrite(recvFD, sendPacket->data() , sendPacket->length());
		
		if (PRINT) {
			string pubIP(inet_ntoa(newSecondary.publicIP));
			string priIP(inet_ntoa(newSecondary.privateIP));
			click_chatter("Sending JOIN_SECONDARY_ACK to node (%s, %s, %d) \n", pubIP.c_str(),
							priIP.c_str(), newSecondary.port);
		}
		if (sentPacket < 0) {
			perror("Error writing packet to remote socket: \n");
		}
		
		sendPacket->kill();
		
	} else {
		// CREATE JOIN SECONDARY NACK, Since I dont know if i am a P node
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, 0);
		
		char *joinSecondaryNakOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* joinSecondaryNakPacket = (routePacket *)(joinSecondaryNakOffset);
		joinSecondaryNakPacket->type = JOIN_SECONDARY_NAK;
		joinSecondaryNakPacket->src = _myInfo;
		joinSecondaryNakPacket->dst = recvPacket->src;
		
		if (PRINT) {
			string pubIP(inet_ntoa((recvPacket->src).publicIP));
			string priIP(inet_ntoa((recvPacket->src).privateIP));
			click_chatter("Sending JOIN_SECONDARY_Nak to node (%s, %s, %d) \n", pubIP.c_str(),
							priIP.c_str(), (recvPacket->src).port);
		}
		
		int sentPacket = write(recvFD, sendPacket->data() , sendPacket->length());
		if (sentPacket < 0) {
			perror("Error writing packet to remote socket: \n");
		}
		
		sendPacket->kill();
		remove_select(recvFD, SELECT_READ);
		close(recvFD);
		if (LOG) {
			eraseStats(recvFD);
		}
	}
	return 0;
}

int GDPRouterNat::handleUpdateSecondary(int recvFD, routePacket* recvPacket) {
	routeTableEntry packetSrc = recvPacket->src;
	if (PRINT) {
		string pubIP(inet_ntoa((recvPacket->src).publicIP));
		string priIP(inet_ntoa((recvPacket->src).privateIP));
		click_chatter("Received a UPDATE_SECONDARY from node (%s, %s, %d) , %d \n", 
						pubIP.c_str(), priIP.c_str(), (recvPacket->src).port, recvFD);	
	}
	map<int, char>::iterator findFD = _type.find(recvFD);
	if (packetSrc.publicIP.s_addr != packetSrc.privateIP.s_addr && findFD == _type.end() && _myType == 'P') {
		// packet is coming from a secondary node
		// choosing me as its new proxy;
		
		if (PRINT) {
			click_chatter("The src node wants me to be its new proxy\n");
		}
		
		//Update Route Table
		add_select(recvFD, SELECT_READ);
	
		int one = 1;
		setsockopt(recvFD, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
	
		_routeTable[packetSrc] = recvFD;
	
		// Update type
		_type[recvFD] = 'S';
	
		// Update _secondaryAdvertisments with those that dont exist already
		int numClientAdvertisments = recvPacket->numClientAdvertisments;
		string newAdvertisments;
		int numNewAdvertisments = 0;
		if (numClientAdvertisments > 0) {
			char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
			
			// for each advertisement sent by bootstrap create an entry in _primaryAdvertisments
			for (int i = 0; i < numClientAdvertisments; i++) {
				string key(seekPtr, 32);
				map<string, routeTableEntry>::iterator findID = _secondaryAdvertisments.find(key);
				
				// If the ID doesnt already exist in the _secondaryAdvertisments list
				if (findID == _secondaryAdvertisments.end()) {
					if (PRINT) {
						click_chatter("I didn't have this client connected to the S node: %s\n", key.c_str());
					}
					_secondaryAdvertisments[key] = packetSrc;
					newAdvertisments += key;
					numNewAdvertisments++;	
				}
				seekPtr += 32;
			}
		}
		
		//Create UPDATE_SECONDARY to inform other 'P' nodes, that the S node has changed proxy
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = numNewAdvertisments * 32 + sizeof(routeTableEntry);
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char *updateSecondaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* updateSecondaryPacket = (routePacket *)(updateSecondaryOffset);
		updateSecondaryPacket->type = UPDATE_SECONDARY;
		updateSecondaryPacket->src = _myInfo;
		updateSecondaryPacket->numClientAdvertisments = 0;
		updateSecondaryPacket->numSecondaryAdvertisments = numNewAdvertisments;
		updateSecondaryPacket->numSecondary = 1;
		updateSecondaryPacket->numPrimary = 0;
		updateSecondaryPacket->isTypeAssigned = 0;
	
		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
		if (updateSecondaryPacket->numSecondaryAdvertisments > 0) {
			memcpy((void *)(sendPacket->data() + totalHeaderSize),
					(void *)(newAdvertisments.c_str()), updateSecondaryPacket->numSecondaryAdvertisments * 32);
		}
	
		memcpy((void *)(sendPacket->data()
						+ totalHeaderSize
						+ updateSecondaryPacket->numSecondaryAdvertisments * 32),
				(void *)(&packetSrc), sizeof(routeTableEntry));
			
		// Send UPDATE SECONDARY PACKET to all primary nodes
		int numPnodes = _primaryNodes.size();
		for (int i = 0; i < numPnodes; i++) {
			routePacket* routePacketOffset = (routePacket *)(sendPacket->data());
			routePacketOffset->dst = _primaryNodes[i];
		
			map<routeTableEntry, int>::iterator findFD = _routeTable.find(_primaryNodes[i]);
		
			if (findFD != _routeTable.end()) {
				int sendFD = findFD->second;
				int sentPacket = regulatedWrite(sendFD, sendPacket->data() , sendPacket->length());
		
				if (PRINT) {
					click_chatter("Sending UPDATE_SECONDARY to primary node (%s, %d) \n", inet_ntoa(_primaryNodes[i].publicIP),
									_primaryNodes[i].port);
				}
			
				if (sentPacket < 0) {
					perror("Error writing packet to remote socket: \n");
				}
			} else {
				click_chatter("I dont have the file descriptor for primary node (%s, %d) \n", inet_ntoa(_primaryNodes[i].publicIP),
									_primaryNodes[i].port);
			}
		}
		
		sendPacket->kill();
		
		// Update _publicToPrivate
		_publicToPrivate[packetSrc.publicIP.s_addr].push_back(packetSrc);
		
		// Create UPDATE_SECONDARY_ACK packet containing all the primary nodes
		// The Secondary node has to be made aware of all new primary nodes
		packetDataSize = _primaryNodes.size() * sizeof(routeTableEntry);
		sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char* updateSecondaryAckOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* updateSecondaryAckPacket = (routePacket *)(updateSecondaryAckOffset);
		updateSecondaryAckPacket->type = UPDATE_SECONDARY_ACK;
		updateSecondaryAckPacket->src = _myInfo;
		updateSecondaryAckPacket->dst = packetSrc;
		updateSecondaryAckPacket->numClientAdvertisments = 0;
		updateSecondaryAckPacket->numSecondaryAdvertisments = 0;
		updateSecondaryAckPacket->numSecondary = 0;
		updateSecondaryAckPacket->numPrimary = _primaryNodes.size();
		updateSecondaryAckPacket->isTypeAssigned = false;
	
		//Add all the primary nodes
		if (updateSecondaryAckPacket->numPrimary > 0) {
			char *priOffset = (char *)(sendPacket->data() + totalHeaderSize);
			routeTableEntry* pri = (routeTableEntry *)priOffset;
			for (int i = 0; i < updateSecondaryAckPacket->numPrimary; i++) {
				pri[i] = _primaryNodes[i];
			}
		}
	
		_isFDReady[recvFD] = true;
		int sentPacket = regulatedWrite(recvFD, sendPacket->data() , sendPacket->length());
	
		if (PRINT) {
			string pubIP(inet_ntoa(packetSrc.publicIP));
			string priIP(inet_ntoa(packetSrc.privateIP));
			click_chatter("Sending UPDATE_SECONDARY_ACK to node (%s, %s, %d) \n", pubIP.c_str(),
							priIP.c_str(), packetSrc.port);
		}
		if (sentPacket < 0) {
			perror("Error writing packet to remote socket: \n");
		}
	
		sendPacket->kill();
	} else if (packetSrc.publicIP.s_addr == packetSrc.privateIP.s_addr && findFD != _type.end() && findFD->second == 'P' && _myType == 'P') {
		
		if (PRINT) {
			click_chatter("The src node is a P node informing me an S node has made the src node its proxy\n");
		}
		// packet coming from a P node 
		// and hence I just need to update my state
		int numSecondaryAdvertisments = recvPacket->numSecondaryAdvertisments;
		char* updateSecondaryOffset = (char *)(recvPacket) + sizeof(routePacket) + numSecondaryAdvertisments*32;
		routeTableEntry* updateSecondary = (routeTableEntry *)(updateSecondaryOffset);
		
		//Update routeTable
		_routeTable[*updateSecondary] = recvFD;
		
		if (PRINT) {
			string pubIP(inet_ntoa(updateSecondary->publicIP));
			string priIP(inet_ntoa(updateSecondary->privateIP));
			click_chatter("I am a P node and the UPDATE SECONDARY node is (%s, %s, %d)\n",
							pubIP.c_str(), priIP.c_str(), updateSecondary->port);
		}
		
		//Update _secondaryAdvertisments
		if (numSecondaryAdvertisments > 0) {
			char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
				
			// for each advertisement sent by bootstrap create an entry in _primaryAdvertisments
			for (int i = 0; i < numSecondaryAdvertisments; i++) {
				string key(seekPtr, 32);
				if (PRINT) {
					click_chatter("I didn't have this client connected to the S node: %s\n", key.c_str());
				}
				_secondaryAdvertisments[key] = *updateSecondary;
				seekPtr += 32;
			}
		}	
	} else {
		// in all other cases send an UPDATE_SECONDARY_NAK
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, 0);
		
		char *updateSecondaryNakOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* updateSecondaryNakPacket = (routePacket *)(updateSecondaryNakOffset);
		updateSecondaryNakPacket->type = UPDATE_SECONDARY_NAK;
		updateSecondaryNakPacket->src = _myInfo;
		updateSecondaryNakPacket->dst = recvPacket->src;
		
		if (PRINT) {
			string pubIP(inet_ntoa((recvPacket->src).publicIP));
			string priIP(inet_ntoa((recvPacket->src).privateIP));
			click_chatter("Sending UPDATE_SECONDARY_NAK to node (%s, %s, %d) \n", pubIP.c_str(),
							priIP.c_str(), (recvPacket->src).port);
		}
		
		int sentPacket = write(recvFD, sendPacket->data() , sendPacket->length());
		if (sentPacket < 0) {
			perror("Error writing packet to remote socket: \n");
		}
		
		sendPacket->kill();
		remove_select(recvFD, SELECT_READ);
		close(recvFD);
		if (LOG) {
			eraseStats(recvFD);
		}
	}
	return 0;
}

int GDPRouterNat::handleJoinSecondaryAck(int recvFD, routePacket* recvPacket) {
	//Update proxy;
	_proxy = recvPacket->src;
	
	//Update Proxy FD;
	_proxyFD = recvFD;
	
	if (PRINT) {
		if (recvPacket->type == JOIN_SECONDARY_ACK) {
			click_chatter("Received JOIN_SECONDARY_ACK from node (%s, %d) \n", inet_ntoa(_proxy.publicIP), _proxy.port);
		} else if (recvPacket->type == UPDATE_SECONDARY_ACK) {
			click_chatter("Received UPDATE_SECONDARY_ACK from node (%s, %d) \n", inet_ntoa(_proxy.publicIP), _proxy.port);
		}
	}
	
	// Obtain all the primaryNodes from the message
	// Update _primaryNodes list
	_primaryNodes.clear();
	int numPrimary = recvPacket->numPrimary;
	
	if (numPrimary > 0) {
		char* priOffset = (char *)(recvPacket) + sizeof(routePacket);
		routeTableEntry* pri = (routeTableEntry *)priOffset;
		for (int i = 0; i < numPrimary; i++) {
			if (PRINT) {
				click_chatter("Placing primary node (%s, %d) inside _primaryNodes\n", 
								inet_ntoa(pri[i].publicIP), pri[i].port);
			}
			_primaryNodes.push_back(pri[i]);
		}
	}
	_primaryNodes.push_back(_proxy);
	
	return 0;
}

int GDPRouterNat::handleJoinSecondaryNak(int recvFD, routePacket* recvPacket) {
	// Update _routeTable (remove old entry)
	std::map<routeTableEntry,int>::iterator it;

	it = _routeTable.find(recvPacket->src);
	if (it != _routeTable.end())
		_routeTable.erase (it);

	_type.erase(recvFD);
	
	_isFDReady.erase(recvFD);
	_recvBuffer.erase(recvFD);
	_tempSendBuffer.erase(recvFD);
	if (LOG) {
		eraseStats(recvFD);
	}
	remove_select(recvFD, SELECT_READ);
	close(recvFD);
	
	if (PRINT) {
		click_chatter("Received JOIN_SECONDARY_NAK from node (%s, %d) \n", inet_ntoa(_proxy.publicIP), _proxy.port);
	}
	
	//Re Create a JOIN_SECONDARY message
	char version = (char)(VERSION);
	char cmd = (char)(ROUTE_PROTOCOL);
	string dst = _GDPRouterAddress;
	string src = _GDPRouterAddress;
	int packetDataSize =  _clientAdvertisments.size() * 32;
	WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
	
	char *joinSecondaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
	routePacket* joinSecondaryPacket = (routePacket *)(joinSecondaryOffset);
	if (recvPacket->type == JOIN_SECONDARY_NAK) {
		joinSecondaryPacket->type = JOIN_SECONDARY;
	} else if (recvPacket->type == UPDATE_SECONDARY_NAK) {
		joinSecondaryPacket->type = UPDATE_SECONDARY;
	}
	joinSecondaryPacket->src = _myInfo;
	joinSecondaryPacket->numClientAdvertisments = _clientAdvertisments.size();
	joinSecondaryPacket->numSecondaryAdvertisments = 0;
	joinSecondaryPacket->numSecondary = 0;
	joinSecondaryPacket->numPrimary = 0;
	joinSecondaryPacket->isTypeAssigned = false;
	
	int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
	if (joinSecondaryPacket->numClientAdvertisments > 0) {
		string concatAdvertisments;
		for(map<string, int >::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
				concatAdvertisments += (it->first).substr(0,32);
		}
		memcpy((void *)(sendPacket->data() 
				+ totalHeaderSize), 
			   (void *)concatAdvertisments.c_str(), concatAdvertisments.length());
	}
	
	// chose a new proxy
	findProxyAndConnect(sendPacket);
	sendPacket->kill();
	return 0;
}

int GDPRouterNat::handleNewSecondary(int recvFD, routePacket* recvPacket, string& message) {
	if (PRINT) {
		click_chatter("Received NEW_SECONDARY from node (%s, %d) \n", inet_ntoa((recvPacket->src).publicIP), (recvPacket->src).port);
	}
	if (_myType == 'P') {
		int numSecondaryAdvertisments = recvPacket->numSecondaryAdvertisments;
		char* newSecondaryOffset = (char *)(recvPacket) + sizeof(routePacket) + numSecondaryAdvertisments*32;
		routeTableEntry* newSecondary = (routeTableEntry *)(newSecondaryOffset);
		
		//Update routeTable
		_routeTable[*newSecondary] = recvFD;
		
		if (PRINT) {
			string pubIP(inet_ntoa(newSecondary->publicIP));
			string priIP(inet_ntoa(newSecondary->privateIP));
			click_chatter("I am a Primary node and the NEW SECONDARY node is (%s, %s, %d)\n",
							pubIP.c_str(), priIP.c_str(), newSecondary->port);
		}
		
		//Update _secondaryAdvertisments
		if (numSecondaryAdvertisments > 0) {
			char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
				
			// for each advertisement sent by bootstrap create an entry in _primaryAdvertisments
			for (int i = 0; i < numSecondaryAdvertisments; i++) {
				string key(seekPtr, 32);
				_secondaryAdvertisments[key] = *newSecondary;
				seekPtr += 32;
			}
		}
		
		// forward to all secondary nodes directly connected with same public IP as new node;
		map<unsigned long, vector<routeTableEntry> >::iterator it;
  		it = _publicToPrivate.find((*newSecondary).publicIP.s_addr);
  		if (it != _publicToPrivate.end()) {
  			int numSnodes = (it->second).size();
  			for (int i = 0; i < numSnodes; i++) {
  			
  				map<routeTableEntry, int>::iterator findFD = _routeTable.find((it->second)[i]);
  				
  				if (findFD != _routeTable.end()) {
  					int sendFD = findFD->second;
					int sentPacket = regulatedWrite(sendFD, message.c_str() , message.length());
				
					if (PRINT) {
						string pubIP(inet_ntoa((it->second)[i].publicIP));
						string priIP(inet_ntoa((it->second)[i].privateIP));
						click_chatter("Forwarding NEW SECONDARY to node (%s, %s, %d)\n",
										pubIP.c_str(), priIP.c_str(), (it->second)[i].port);
					}
	
					if (sentPacket < 0) {
						perror("Error writing packet to remote socket: \n");
					}
				} else {
					string pubIP(inet_ntoa((it->second)[i].publicIP));
					string priIP(inet_ntoa((it->second)[i].privateIP));
					click_chatter("I dont have the file descriptor for secondary node (%s, %s, %d)\n",
										pubIP.c_str(), priIP.c_str(), (it->second)[i].port);
				}
  			}
  		}

	} else if (_myType == 'S') {
		int numSecondaryAdvertisments = recvPacket->numSecondaryAdvertisments;
		char* newSecondaryOffset = (char *)(recvPacket) + sizeof(routePacket) + numSecondaryAdvertisments*32;
		routeTableEntry* newSecondary = (routeTableEntry *)(newSecondaryOffset);
		
		if (PRINT) {
			string pubIP(inet_ntoa(newSecondary->publicIP));
			string priIP(inet_ntoa(newSecondary->privateIP));
			click_chatter("I am a Secondary node and the NEW SECONDARY node is (%s, %s, %d)\n",
							pubIP.c_str(), priIP.c_str(), newSecondary->port);
		}
		
		//Update _secondaryAdvertisments
		if (numSecondaryAdvertisments > 0) {
			char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
				
			// for each advertisement sent by new node create an entry in _secondaryAdvertisments
			for (int i = 0; i < numSecondaryAdvertisments; i++) {
				string key(seekPtr, 32);
				_secondaryAdvertisments[key] = *newSecondary;
				seekPtr += 32;
			}
		}
		
		map<routeTableEntry,int>::iterator it;
  		it = _routeTable.find(*newSecondary);
  		
  		// Send ADD SECONDARY to the new only if it is not in the _routeTable
  		if (it ==  _routeTable.end()) {
  		
			// Create an ADD SECONDARY packet
			char version = (char)(VERSION);
			char cmd = (char)(ROUTE_PROTOCOL);
			string dst = _GDPRouterAddress;
			string src = _GDPRouterAddress;
			int packetDataSize = _clientAdvertisments.size() * 32;
			WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
			
			char *addSecondaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
			routePacket* addSecondaryPacket = (routePacket *)(addSecondaryOffset);
			addSecondaryPacket->type = ADD_SECONDARY;
			addSecondaryPacket->src = _myInfo;
			addSecondaryPacket->dst = *newSecondary;
			addSecondaryPacket->numClientAdvertisments = _clientAdvertisments.size();
			addSecondaryPacket->numSecondaryAdvertisments = 0;
			addSecondaryPacket->numSecondary = 0;
			addSecondaryPacket->numPrimary = 0;
			addSecondaryPacket->isTypeAssigned = false;
		
			int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
			if (addSecondaryPacket->numClientAdvertisments > 0) {
				string concatAdvertisments;
				for(map<string, int >::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
						concatAdvertisments += (it->first).substr(0,32);
				}
				memcpy((void *)(sendPacket->data() 
						+ totalHeaderSize), 
					   (void *)concatAdvertisments.c_str(), concatAdvertisments.length());
			}
		
			struct sockaddr_in remoteServer;
			int clientFD = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
			remoteServer.sin_family = AF_INET;
			remoteServer.sin_port = htons((*newSecondary).port);
			remoteServer.sin_addr = (*newSecondary).privateIP;
			int remoteLen = sizeof(remoteServer);

			socklen_t sockOptLen = sizeof(int);
			int sendBufSize;
			int err = getsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);
			if (err < 0) {
				perror("Error in obtaining recvBuffer size for socket: \n");
			}


			sendBufSize= sendBufSize * 5;
			err = setsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize,
									 sizeof(sendBufSize));

			if (connect(clientFD,(struct sockaddr *) &remoteServer, remoteLen) < 0) {
				perror("error connecting to remote socket: \n");
				exit(EXIT_FAILURE);
			}

			err = getsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);


			// nonblocking I/O and close-on-exec for the socket
			fcntl(clientFD, F_SETFL, O_NONBLOCK);
			fcntl(clientFD, F_SETFD, FD_CLOEXEC);	

			//sending ADD Secondary packet
			_isFDReady[clientFD] = true;
			int sentPacket = regulatedWrite(clientFD, sendPacket->data() , sendPacket->length());
			if (sentPacket < 0) {
				perror("Error writing packet to remote socket: \n");
				_isFDReady.erase(clientFD);
			} else {
				add_select(clientFD, SELECT_READ);
				_routeTable[*newSecondary] = clientFD;
				_type[clientFD] = 'S';
				
				if (PRINT) {
					string pubIP(inet_ntoa(newSecondary->publicIP));
					string priIP(inet_ntoa(newSecondary->privateIP));
					click_chatter("Sent ADD_SECONDARY to node (%s, %s, %d)\n",
									pubIP.c_str(), priIP.c_str(), newSecondary->port);
				}
			}
			sendPacket->kill();
		}
	}
	return 0;
}

int GDPRouterNat::handleWithdrawSecondary(routePacket* recvPacket) {
	if (PRINT) {
		click_chatter("I am a P node and I Received WITHDRAW_SECONDARY from node (%s, %d) \n", inet_ntoa((recvPacket->src).publicIP), (recvPacket->src).port);
	}
	
	if (_myType == 'P') {
		char* failedSecondaryOffset = (char *)(recvPacket) + sizeof(routePacket);
		routeTableEntry* failedSecondary = (routeTableEntry *)(failedSecondaryOffset);
		
		if (PRINT) {
			string pubIP = inet_ntoa(failedSecondary->publicIP);
			string priIP = inet_ntoa(failedSecondary->privateIP);
			click_chatter("The failed secondary node is (%s, %s, %d) \n", pubIP.c_str(), priIP.c_str(),
							failedSecondary->port);
		}
		
		// Gather all the 256 ID connected to the failed node;
		vector<string> advertismentsToRemove;
		for (map<string, routeTableEntry>::iterator it = _secondaryAdvertisments.begin(); it != _secondaryAdvertisments.end(); it++) {
			if (it->second == *failedSecondary) {
				advertismentsToRemove.push_back(it->first);
				if (PRINT) {
					click_chatter("Client directly connected to failed secondary node: %s\n", (it->first).c_str());
				}
			}
		}

		// Remove all the identified entries from _secondaryAdvertisments;
		int numAdv = advertismentsToRemove.size();
		for (int i = 0; i < numAdv; i++) {
			_secondaryAdvertisments.erase(advertismentsToRemove[i]);
		}
		
		// update _routeTable by  removing the failed node entry
		_routeTable.erase(*failedSecondary);
	}
	
	return 0;
}

int GDPRouterNat::handleAddSecondary(int recvFD, routePacket* recvPacket) {
		
	routeTableEntry newSecondary = recvPacket->src;
	
	if (PRINT) {
		string pubIP(inet_ntoa(newSecondary.publicIP));
		string priIP(inet_ntoa(newSecondary.privateIP));
		click_chatter("Received ADD_SECONDARY from node (%s, %s, %d)\n",
						pubIP.c_str(), priIP.c_str(), newSecondary.port);
	}
	
	// Update _secondaryAdvertisments
	int numClientAdvertisments = recvPacket->numClientAdvertisments;
	if (numClientAdvertisments > 0) {
		char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
			
		// for each advertisement sent by node (with same public IP as me) update _secondaryAdvertisments
		for (int i = 0; i < numClientAdvertisments; i++) {
			string key(seekPtr, 32);
			_secondaryAdvertisments[key] = newSecondary;
			seekPtr += 32;
		}
	}
	
	// Update type;
	_type[recvFD] = 'S';
	
	// Update RouteTable
	_routeTable[newSecondary] = recvFD;
	
	//initiate call back for new connection
	add_select(recvFD, SELECT_READ);
	
	// Create an ADD SECONDARY ACK packet
	char version = (char)(VERSION);
	char cmd = (char)(ROUTE_PROTOCOL);
	string dst = _GDPRouterAddress;
	string src = _GDPRouterAddress;
	int packetDataSize = _clientAdvertisments.size() * 32;
	WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
	
	char* addSecondaryAckOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
	routePacket* addSecondaryAckPacket = (routePacket *)(addSecondaryAckOffset);
	addSecondaryAckPacket->type = ADD_SECONDARY_ACK;
	addSecondaryAckPacket->src = _myInfo;
	addSecondaryAckPacket->dst = newSecondary;
	addSecondaryAckPacket->numClientAdvertisments = _clientAdvertisments.size();
	addSecondaryAckPacket->numSecondaryAdvertisments = 0;
	addSecondaryAckPacket->numSecondary = 0;
	addSecondaryAckPacket->numPrimary = 0;
	addSecondaryAckPacket->isTypeAssigned = false;
	
	int totalDataSize = GDP_HEADER_SIZE + sizeof(routePacket);
	if (addSecondaryAckPacket->numClientAdvertisments > 0) {
		string concatAdvertisments;
		for(map<string, int >::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
				concatAdvertisments += (it->first).substr(0,32);
		}
		memcpy((void *)(sendPacket->data() 
				+ totalDataSize), 
			   (void *)concatAdvertisments.c_str(), concatAdvertisments.length());
	}
	
	//Send ADD SECONDARY ACK BACK TO THE SOURCE
	_isFDReady[recvFD] = true;
	int sentPacket = regulatedWrite(recvFD, sendPacket->data() , sendPacket->length());
	
	if (PRINT) {
		string pubIP(inet_ntoa(newSecondary.publicIP));
		string priIP(inet_ntoa(newSecondary.privateIP));
		click_chatter("Sending ADD_SECONDARY_ACK to node (%s, %s, %d)\n", pubIP.c_str(),
						priIP.c_str(), newSecondary.port);
	}
	
	
	if (sentPacket < 0) {
		perror("Error writing packet to remote socket: \n");
	} 
	
	sendPacket->kill();
	return 0;
}

int GDPRouterNat::handleAddAckSecondary(routePacket* recvPacket) {
	
	routeTableEntry secondaryNode = recvPacket->src;
	int numSecondaryAdvertisments = recvPacket->numClientAdvertisments;
	
	if (PRINT) {
		string pubIP(inet_ntoa(secondaryNode.publicIP));
		string priIP(inet_ntoa(secondaryNode.privateIP));
		click_chatter("Received ADD_SECONDARY_ACK from node (%s, %s, %d)\n", pubIP.c_str(),
						priIP.c_str(), secondaryNode.port);
	}
	
	//Update _secondaryAdvertisments
	if (numSecondaryAdvertisments > 0) {
		char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
			
		// for each advertisement sent by the new node, update _secondaryAdvertisments
		for (int i = 0; i < numSecondaryAdvertisments; i++) {
			string key(seekPtr, 32);
			_secondaryAdvertisments[key] = secondaryNode;
			seekPtr += 32;
		}
	}
	
	return 0;
}

int GDPRouterNat::handleClientAdvertisment(int recvFD, string& message, int dataLen, int optLen, string& packetSrc, int packetCmd) {
	
	if (PRINT) {
		click_chatter("Received an Advertisment from a client: %s\n", packetSrc.c_str());
	}
	int numNewClients = 0;
	
	// Update _clientAdvertisments for packetSrc
	if (packetCmd == (char)(ADVERTISE_CMD)) {
		_clientAdvertisments[packetSrc] = recvFD;
	} else if (packetCmd == (char)(ADVERTISE_WITHDRAW)) {
		_clientAdvertisments.erase(packetSrc);
	}
	numNewClients++;
	
	// It is possible the message data contains more advertisements
	// Obtain the other advertisments from the PDU data portion
	// update _clientAdvertisments
	string packetData = message.substr(80 + optLen, dataLen);
	for (int i = 0; i < dataLen; i+=32) {
		string key = packetData.substr(i, 32);
		if (packetCmd == (char)(ADVERTISE_CMD)) {
			_clientAdvertisments[key] = recvFD;
		} else if (packetCmd == (char)(ADVERTISE_WITHDRAW)) {
			_clientAdvertisments.erase(key);
		}
		numNewClients++;
	}
	
	string newAdvertisments = packetSrc.substr(0, 32);
	newAdvertisments += packetData;
	
	if (PRINT) {
		click_chatter("NUM OF CLIENTS: %d\n", numNewClients);
		click_chatter("LENGTH: %d\n", newAdvertisments.length());
	}
	
	if (_myType == 'P') {
		
		//create NEW_CLIENT_PRIMARY packet
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = numNewClients * 32;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char* newClientPrimaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* newClientPrimaryPacket = (routePacket *)(newClientPrimaryOffset);
		if (packetCmd == (char)(ADVERTISE_CMD)) {
			newClientPrimaryPacket->type = NEW_CLIENT_PRIMARY;
		} else if (packetCmd == (char)(ADVERTISE_WITHDRAW)) {
			newClientPrimaryPacket->type = WITHDRAW_CLIENT_PRIMARY;
		}
		newClientPrimaryPacket->src = _myInfo;
		newClientPrimaryPacket->numClientAdvertisments = numNewClients;
		newClientPrimaryPacket->numSecondaryAdvertisments = 0;
		newClientPrimaryPacket->numSecondary = 0;
		newClientPrimaryPacket->numPrimary = 0;
		newClientPrimaryPacket->isTypeAssigned = false;
		
		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
		memcpy((void *)(sendPacket->data() + totalHeaderSize),
				(void *)(newAdvertisments.c_str()), newAdvertisments.length());
		
		// Send NEW_CLIENT_PRIMARY to each Primary node from _primaryNodes
		int numPNodes = _primaryNodes.size();
		for (int i = 0; i < numPNodes; i++) {
			routePacket* r = (routePacket *)(sendPacket->data());
			r->dst = _primaryNodes[i]; 
			
			map<routeTableEntry, int>::iterator findFD = _routeTable.find(_primaryNodes[i]);
			
			if (findFD != _routeTable.end()) {
				int sendFD = findFD->second;
				if (LOG) {
					_logSendAdvNumber[sendFD] = _logSendAdvNumber[sendFD] + 1;
					_logSendAdvBytes[sendFD] = _logSendAdvBytes[sendFD] + sendPacket->length();
				}
				int sentPacket = regulatedWrite(sendFD, sendPacket->data(), sendPacket->length());
			
				if (PRINT) {
					click_chatter("I am a P node sending NEW_CLIENT_PRIMARY to node (%s, %d)\n", inet_ntoa(_primaryNodes[i].publicIP), 
									_primaryNodes[i].port);
				}
				if (sentPacket < 0) {
					perror("Error forwarding NEW_CLIENT_PRIMARY: \n");
				}
			} else {
				click_chatter("I dont have file descriptor for primary node (%s, %d)\n", inet_ntoa(_primaryNodes[i].publicIP), 
									_primaryNodes[i].port);
			}
 		}
		
		sendPacket->kill();
	} else if (_myType == 'S') {
	
		//create NEW_CLIENT_SECONDARY packet
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = numNewClients * 32;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char *newClientSecondaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* newClientSecondaryPacket = (routePacket *)(newClientSecondaryOffset);
		if (packetCmd == (char)(ADVERTISE_CMD)) {
			newClientSecondaryPacket->type = NEW_CLIENT_SECONDARY;
		} else if (packetCmd == (char)(ADVERTISE_WITHDRAW)) {
			newClientSecondaryPacket->type = WITHDRAW_CLIENT_SECONDARY;
		}
		newClientSecondaryPacket->src = _myInfo;
		newClientSecondaryPacket->numClientAdvertisments = numNewClients;
		newClientSecondaryPacket->numSecondaryAdvertisments = 0;
		newClientSecondaryPacket->numSecondary = 0;
		newClientSecondaryPacket->numPrimary = 0;
		newClientSecondaryPacket->isTypeAssigned = false;
		
		int totalDataSize = GDP_HEADER_SIZE + sizeof(routePacket);
		memcpy((void *)(sendPacket->data() + totalDataSize), (void *)(newAdvertisments.c_str()), newAdvertisments.length());
				
		// Send NEW_CLIENT_SECONDARY to all S members in the routing table
		for (map<routeTableEntry, int>::iterator it = _routeTable.begin(); it != _routeTable.end(); it++) {
			routeTableEntry node = it->first;
			int sendFD = it->second;
			if (node.publicIP.s_addr != node.privateIP.s_addr) {
				// node is an S node
				routePacket* r = (routePacket *)(sendPacket->data());
				r->dst = node;
				if (LOG) {
					_logSendAdvNumber[sendFD] = _logSendAdvNumber[sendFD] + 1;
					_logSendAdvBytes[sendFD] = _logSendAdvBytes[sendFD] + sendPacket->length();
				}
				int sentPacket = regulatedWrite(sendFD, sendPacket->data(), sendPacket->length());
				//write(sendFD, sendPacket->data(), sendPacket->length());
				
				if (PRINT) {
					string pubIP(inet_ntoa(node.publicIP));
					string priIP(inet_ntoa(node.privateIP));
					click_chatter("I am a S node sending NEW_CLIENT_SECONDARY to node (%s, %s, %d)\n", pubIP.c_str(), priIP.c_str(), 
								node.port);
				}
				
				if (sentPacket < 0) {
					perror("Error forwarding NEW_CLIENT_SECONDARY: \n");
				}
			}
		}
		
		// Send NEW_CLIENT_SECONDARY to proxy as well
		if (_proxyFD != -1) {
			routePacket* r = (routePacket *)(sendPacket->data());
			r->dst = _proxy;
			if (LOG) {
				_logSendAdvNumber[_proxyFD] = _logSendAdvNumber[_proxyFD] + 1;
				_logSendAdvBytes[_proxyFD] = _logSendAdvBytes[_proxyFD] + sendPacket->length();
			}
			int sentPacket = regulatedWrite(_proxyFD, sendPacket->data(), sendPacket->length());
			//write(_proxyFD, sendPacket->data(), sendPacket->length());
			
			if (PRINT) {
				click_chatter("Sending NEW_CLIENT_SECONDARY to proxy (%s, %d)\n", inet_ntoa(_proxy.publicIP), _proxy.port);
			}
			if (sentPacket < 0) {
				perror("Error forwarding NEW_CLIENT_SECONDARY to proxy: \n");
			}
		}
		
		sendPacket->kill();
	}
	return 0;
}

int GDPRouterNat::handleClientPrimary(routePacket* recvPacket) {
	routeTableEntry advertismentSrc = recvPacket->src;
	
	if (PRINT) {
		click_chatter("Received NEW/WITHDRAW_CLIENT_PRIMARY from (%s, %d)\n", inet_ntoa(advertismentSrc.publicIP), advertismentSrc.port);
	}
	
	// Update _primaryAdvertisments
	int numClientAdvertisments = recvPacket->numClientAdvertisments;
	if (numClientAdvertisments > 0) {
		char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
			
		// for each advertisement sent by node update _primaryAdvertisments
		for (int i = 0; i < numClientAdvertisments; i++) {
			string key(seekPtr, 32);
			if (recvPacket->type == NEW_CLIENT_PRIMARY) {
				_primaryAdvertisments[key] = advertismentSrc;
			} else if (recvPacket->type == WITHDRAW_CLIENT_PRIMARY){
				_primaryAdvertisments.erase(key);
			}
			seekPtr += 32;
		}
	}
	
	return 0;
}

int GDPRouterNat::handleClientSecondary(int recvFD, routePacket* recvPacket, string& message) {
	routeTableEntry advertismentSrc = recvPacket->src;
	
	if (PRINT) {
		click_chatter("Received NEW/WITHDRAW_CLIENT_SECONDARY from (%s, %d)\n", inet_ntoa(advertismentSrc.publicIP), advertismentSrc.port);
	}
	
	if (_myType == 'S') {
		int numClientAdvertisments = recvPacket->numClientAdvertisments;
		if (numClientAdvertisments > 0) {
			char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
			
			// for each advertisement sent by node update _secondaryAdvertisments
			for (int i = 0; i < numClientAdvertisments; i++) {
				string key(seekPtr, 32);
				if (recvPacket->type == NEW_CLIENT_SECONDARY) {
					_secondaryAdvertisments[key] = advertismentSrc;
				} else if (recvPacket->type == WITHDRAW_CLIENT_SECONDARY) {
					_secondaryAdvertisments.erase(key);
				}
				seekPtr += 32;
			}
		}
	} else if (_myType == 'P' && _type[recvFD] == 'S') {
		// Since source of the Advertisment is secondary
		// I am the proxy for the source
		
		// Update _secondaryAdvertisments
		int numClientAdvertisments = recvPacket->numClientAdvertisments;
		if (numClientAdvertisments > 0) {
			char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
			
			// for each advertisement sent by node update _secondaryAdvertisments
			for (int i = 0; i < numClientAdvertisments; i++) {
				string key(seekPtr, 32);
				if (recvPacket->type == NEW_CLIENT_SECONDARY) {
					_secondaryAdvertisments[key] = advertismentSrc;
				} else if (recvPacket->type == WITHDRAW_CLIENT_SECONDARY) {
					_secondaryAdvertisments.erase(key);
				}
				seekPtr += 32;
			}
		}
		
		// Since I am proxy, My job is to forward the entire packet to other P nodes
		int numPNodes = _primaryNodes.size();
		for (int i = 0; i < numPNodes; i++) {
			routePacket* r = (routePacket *)(message.c_str());
			r->dst = _primaryNodes[i]; 
			
			map<routeTableEntry, int>::iterator findFD = _routeTable.find(_primaryNodes[i]);
			
			if (findFD != _routeTable.end()) {
				int sendFD = findFD->second;
				if (LOG) {
					_logSendAdvNumber[sendFD] = _logSendAdvNumber[sendFD] + 1;
					_logSendAdvBytes[sendFD] = _logSendAdvBytes[sendFD] + message.length();
				}
				int sentPacket = regulatedWrite(sendFD, message.c_str(), message.length());
			
				if (PRINT) {
					click_chatter("Forwarding NEW/WITHDRAW_CLIENT_SECONDARY to (%s, %d)\n", inet_ntoa(_primaryNodes[i].publicIP), _primaryNodes[i].port);
				}
	
				if (sentPacket < 0) {
					perror("Error forwarding NEW/WITHDRAW_CLIENT_SECONDARY TO OTHER P NODES: \n");
				}
			} else {
				click_chatter("I dont have file descriptor for primary node (%s, %d)\n", 
								inet_ntoa(_primaryNodes[i].publicIP), _primaryNodes[i].port);
			}
		}
	} else if (_myType == 'P' && _type[recvFD] == 'P') {
		// Update _secondaryAdvertisments
		int numClientAdvertisments = recvPacket->numClientAdvertisments;
		if (numClientAdvertisments > 0) {
			char* seekPtr = (char *)(recvPacket) + sizeof(routePacket);
			
			// for each advertisement sent by node update _secondaryAdvertisments
			for (int i = 0; i < numClientAdvertisments; i++) {
				string key(seekPtr, 32);
				if (recvPacket->type == NEW_CLIENT_SECONDARY) {
					_secondaryAdvertisments[key] = advertismentSrc;
				} else if (recvPacket->type == WITHDRAW_CLIENT_SECONDARY) {
					_secondaryAdvertisments.erase(key);
				}
				seekPtr += 32;
			}
		}
	}
	return 0;
}

int GDPRouterNat::handleForwardPacket(int recvFD, string& packetDst, string& packetSrc, string& message , int dataLen, int optLen, int sigLen) {
	if (PRINT) {
		click_chatter("Received a forwarding packet: src: %s, dst: %s\n", packetSrc.c_str(), packetDst.c_str());
	}
	
	if (_myType == 'P') {
		
		//see if the destination is in _clientAdvertisments;
		map<string, int>::iterator it1 = _clientAdvertisments.find(packetDst);
		if (it1 != _clientAdvertisments.end()) {
			// found the destination
			int sendFD = it1->second;
			if (LOG) {
				_logSendFwdNumber[sendFD] = _logSendFwdNumber[sendFD] + 1;
				_logSendFwdBytes[sendFD] =_logSendFwdBytes[sendFD] + optLen + dataLen + sigLen + 80;
			}
			int sentPacket = regulatedWrite(sendFD, message.c_str(), optLen + dataLen + sigLen + 80);
			
			if (PRINT) {
				click_chatter("Sent forward packet to: %d\n:", sendFD);
			}
			
			if (sentPacket < 0) {
				perror("Error forwarding message to a connected client: \n");
				return -1;
			}
			return 0;
		}
		
		// see if the destination is in _primaryAdvertisments
		map<string, routeTableEntry>::iterator it2 = _primaryAdvertisments.find(packetDst);
		if (it2 != _primaryAdvertisments.end()) {
			// found the destination
			
			map<routeTableEntry, int>::iterator it3 = _routeTable.find(it2->second);
			if (it3 != _routeTable.end()) {
				// found the file handle for the destination node
				int sendFD = it3->second;
				if (LOG) {
					_logSendFwdNumber[sendFD] = _logSendFwdNumber[sendFD] + 1;
					_logSendFwdBytes[sendFD] =_logSendFwdBytes[sendFD] + optLen + dataLen + sigLen + 80;
				}
				int sentPacket = regulatedWrite(sendFD, message.c_str(), optLen + dataLen + sigLen + 80);
				
				if (PRINT) {
					click_chatter("Sent forward packet to node (%s, %d)\n:", inet_ntoa((it2->second).publicIP), (it2->second).port);
				}
			
				if (sentPacket < 0) {
					perror("Error forwarding message to a connected client: \n");
					return -1;
				}
				return 0;
			} else {
				click_chatter("Error: I have the string, but not the FD in routeTable");
				return -1;
			}
		}
		
		// see if the destination is in _secondaryAdvertisments
		map<string, routeTableEntry>::iterator it4 = _secondaryAdvertisments.find(packetDst);
		if (it4 != _secondaryAdvertisments.end()) {
			// found the destination
			
			map<routeTableEntry, int>::iterator it5 = _routeTable.find(it4->second);
			if (it5 != _routeTable.end()) {
				// found the file handle for the destination node
				int sendFD = it5->second;
				if (LOG) {
					_logSendFwdNumber[sendFD] = _logSendFwdNumber[sendFD] + 1;
					_logSendFwdBytes[sendFD] =_logSendFwdBytes[sendFD] + optLen + dataLen + sigLen + 80;
				}
				int sentPacket = regulatedWrite(sendFD, message.c_str(), optLen + dataLen + sigLen + 80);
				
				if (PRINT) {
					click_chatter("Sent forward packet to node (%s, %s, %d)\n:", inet_ntoa((it4->second).publicIP), 
									inet_ntoa((it4->second).privateIP), (it4->second).port);
				}
				
				if (sentPacket < 0) {
					perror("Error forwarding message to a connected client: \n");
					return -1;
				}
				return 0;
			} else {
				click_chatter("Error: I have the string, but not the FD in routeTable");
				return -1;
			}
		}

		//sendNAK
		int status = handleLostPacket(recvFD, message, packetSrc, packetDst);
		return status;
		
	} else if (_myType == 'S') {
		//see if the destination is in _clientAdvertisments;
		map<string, int>::iterator it1 = _clientAdvertisments.find(packetDst);
		if (it1 != _clientAdvertisments.end()) {
			// found the destination
			int sendFD = it1->second;
			if (LOG) {
				_logSendFwdNumber[sendFD] = _logSendFwdNumber[sendFD] + 1;
				_logSendFwdBytes[sendFD] =_logSendFwdBytes[sendFD] + optLen + dataLen + sigLen + 80;
			}
			int sentPacket = regulatedWrite(sendFD, message.c_str(), optLen + dataLen + sigLen + 80);
			
			if (PRINT) {
				click_chatter("Sent forward packet to: %d\n:", sendFD);
			}
			
			if (sentPacket < 0) {
				perror("Error forwarding message to a connected client: \n");
				return -1;
			}
			return 0;
		}
		
		// see if the destination is in _secondaryAdvertisments
		map<string, routeTableEntry>::iterator it2 = _secondaryAdvertisments.find(packetDst);
		if (it2 != _secondaryAdvertisments.end()) {
			// found the destination
			
			map<routeTableEntry, int>::iterator it3 = _routeTable.find(it2->second);
			if (it3 != _routeTable.end()) {
				// found the file handle for the destination node
				int sendFD = it3->second;
				if (LOG) {
					_logSendFwdNumber[sendFD] = _logSendFwdNumber[sendFD] + 1;
					_logSendFwdBytes[sendFD] =_logSendFwdBytes[sendFD] + optLen + dataLen + sigLen + 80;
				}
				int sentPacket = regulatedWrite(sendFD, message.c_str(), optLen + dataLen + sigLen + 80);
				
				if (PRINT) {
					click_chatter("Sent forward packet to node (%s, %s, %d)\n:", inet_ntoa((it2->second).publicIP), 
									inet_ntoa((it2->second).privateIP), (it2->second).port);
				}
				
				if (sentPacket < 0) {
					perror("Error forwarding message to a connected client: \n");
					return -1;
				}
				return 0;
			} else {
				click_chatter("Error: I have the string, but not the FD in routeTable");
				return -1;
			}
		}
		
		// see if the packet came from proxy
		if (recvFD != _proxyFD && _proxyFD != -1) {
			// if the packet didnt come from proxy, send it to proxy
			if (LOG) {
				_logSendFwdNumber[_proxyFD] = _logSendFwdNumber[_proxyFD] + 1;
				_logSendFwdBytes[_proxyFD] =_logSendFwdBytes[_proxyFD] + optLen + dataLen + sigLen + 80;
			}
			int sentPacket = regulatedWrite(_proxyFD, message.c_str(), optLen + dataLen + sigLen + 80);
			
			if (PRINT) {
				click_chatter("Sent forward packet to proxy (%s, %d)\n:", inet_ntoa(_proxy.publicIP), _proxy.port);
			}
				
			if (sentPacket < 0) {
				perror("Error forwarding message to a connected client: \n");
				return -1;
			}
			return 0;
		} 
		
		
		//sendNAK
		int status = handleLostPacket(recvFD, message, packetSrc, packetDst);
		return status;
	} else {
	
		//sendNAK
		int status = handleLostPacket(recvFD, message, packetSrc, packetDst);
		return status;
	}
}

int GDPRouterNat::handleLostPacket(int recvFD, string& message, string& packetSrc, string& packetDst) {
	if (PRINT) {
		click_chatter("A Lost Packet\n");
	}
	if (recvFD == 0) {
		//drop the packet
		return 0;
	}

	char version = (char)(VERSION);
	char cmd = (char)(NAK);  //NAK
	
	string nakMessage;
	nakMessage += version;
	nakMessage += (char)(0x00);
	nakMessage += (char)(0x00);
	nakMessage += cmd;
	nakMessage += packetSrc.substr(0,32); //src of lost packet is dst
	nakMessage += packetDst.substr(0,32); //dst of nak is the src of the lost packet
	nakMessage += message.substr(68, 4);
	for (int i = 0; i < 8; i++) {
		nakMessage += (char)(0x00);
	}
	if (LOG) {
		_logSendFwdNumber[recvFD] = _logSendFwdNumber[recvFD] + 1;
		_logSendFwdBytes[recvFD] =_logSendFwdBytes[recvFD] + nakMessage.length();
	}
	int sentPacket = regulatedWrite(recvFD, nakMessage.c_str(), nakMessage.length());
	
	if (PRINT) {
		click_chatter("Sent lost packet back to src node\n");
	}
	
	if (sentPacket < 0) {
		perror("Error something went while sending NAK packet: \n");
		return -1;
	}
	
	return 0;
}

int GDPRouterNat::regulatedWrite(int fd, const void *data, int length) {
	if (_isFDReady[fd] == true) {
		int sentPacket = write(fd, data, length);
		if (sentPacket < 0) {
			if (errno == EAGAIN) {
				perror("Error11 something went while sending packet: ");
				string temp((char *)data, length);
				string buf = _tempSendBuffer[fd];
				buf += temp;
				_tempSendBuffer[fd] = buf;
				add_select(fd, SELECT_READ|SELECT_WRITE);
				_isFDReady[fd] = false;
				return 0;
			} else {
				perror("Error12: Something went wrong while sending packet");
				return errno;
			}
		} else if (sentPacket < length) {
			string dataString((char *)data, length);
			string temp = dataString.substr(sentPacket, length - sentPacket);
			string buf = _tempSendBuffer[fd];
			temp += buf;
			_tempSendBuffer[fd] = temp;
			add_select(fd, SELECT_READ|SELECT_WRITE);
			_isFDReady[fd] = false;
			if (LOG) {
				_logSendBytes[fd] = _logSendBytes[fd] + sentPacket;
				_curSendBytes[fd] = _curSendBytes[fd] + sentPacket;
			}
			return sentPacket;
		} else {
			if (LOG) {
				_logSendBytes[fd] = _logSendBytes[fd] + sentPacket;
				_curSendBytes[fd] = _curSendBytes[fd] + sentPacket;
			}
			return sentPacket;
		}
	} else {
		string temp((char *)data, length);
		string buf = _tempSendBuffer[fd];
		buf += temp;
		_tempSendBuffer[fd] = buf;
		add_select(fd, SELECT_READ|SELECT_WRITE);
		return 0;
	}
}

void GDPRouterNat::findProxyAndConnect(WritablePacket *sendPacket) {

	//calculating the time taken to ping each node
	vector<int> pingTimes = findPingTime();
	
	if (PRINT) {
		click_chatter("Got all the ping timings\n");
	}
	// removing all nodes which couldn't be pinged succefully
	vector<int> removeIndices;
	int numP = _primaryNodes.size();
	for (int i = 0; i < numP; i++) {
		if (pingTimes[i] == -1) {
			removeIndices.push_back(i);
		}
 	}
 	
 	int numRemove = removeIndices.size();
 	for (int i = 0; i < numRemove; i++) {
 		_primaryNodes.erase(_primaryNodes.begin() + removeIndices[i]);
 		pingTimes.erase(pingTimes.begin() + removeIndices[i]);
 	}
 	
 	while (_primaryNodes.size() > 0) {
 	
 		// find the node with minimum ping time
 		int minPingTime = 3000;
 		int minPingIndex = 0;
 		int numP = _primaryNodes.size();
 		for (int i = 0; i < numP; i++) {
 			if (minPingTime > pingTimes[i]) {
 				minPingTime = pingTimes[i];
 				minPingIndex = i;
 			}
 		}
 		
 		_proxyIndex = minPingIndex;
 		
 		// connecting to node with minimum ping time
 		struct sockaddr_in remoteServer;
		int clientFD = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
		remoteServer.sin_family = AF_INET;
		remoteServer.sin_port = htons(_primaryNodes[_proxyIndex].port);
		remoteServer.sin_addr = _primaryNodes[_proxyIndex].publicIP;
		int remoteLen = sizeof(remoteServer);

		socklen_t sockOptLen = sizeof(int);
		int sendBufSize;
		int err = getsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);
		if (err < 0) {
			perror("Error in obtaining recvBuffer size for socket: \n");
		}


		sendBufSize= sendBufSize * 5;
		err = setsockopt(clientFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize,
								 sizeof(sendBufSize));

		if (connect(clientFD,(struct sockaddr *) &remoteServer, remoteLen) < 0) {
			perror("error connecting to remote socket: \n");
			close(clientFD);
			if (LOG) {
				eraseStats(clientFD);
			}
			_primaryNodes.erase(_primaryNodes.begin() + minPingIndex);
			pingTimes.erase(pingTimes.begin() + minPingIndex);
			continue;
		}
		

		// nonblocking I/O and close-on-exec for the socket
		fcntl(clientFD, F_SETFL, O_NONBLOCK);
		fcntl(clientFD, F_SETFD, FD_CLOEXEC);
		
		routePacket* r = (routePacket *)(sendPacket->data());
		r->dst = _primaryNodes[_proxyIndex];
		
		_isFDReady[clientFD] = true;
		int sentPacket = regulatedWrite(clientFD, sendPacket->data() , sendPacket->length());
		if (sentPacket < 0) {
			perror("Error writing packet to remote socket: \n");
			_isFDReady.erase(clientFD);
			close(clientFD);
			if (LOG) {
				eraseStats(clientFD);
			}
			_primaryNodes.erase(_primaryNodes.begin() + minPingIndex);
			pingTimes.erase(pingTimes.begin() + minPingIndex);
			continue;
		} else {
			add_select(clientFD, SELECT_READ);
			
			int one = 1;
			setsockopt(clientFD, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one));
	
			_routeTable[_primaryNodes[_proxyIndex]] = clientFD;
			_type[clientFD] = 'P';
			
			//Update proxy;
			_proxy = _primaryNodes[_proxyIndex];
	
			//Update Proxy FD;
			_proxyFD = clientFD;
			
			if (PRINT) {
				click_chatter("Chose Proxy Index %d/%d\n", _proxyIndex, _primaryNodes.size());
				if (r->type == JOIN_SECONDARY) {
					click_chatter("Sent JOIN_SECONDARY TO PROXY (%s, %d)", inet_ntoa(_proxy.publicIP), _proxy.port);
				} else if (r->type == UPDATE_SECONDARY) {
					click_chatter("Sent UPDATE_SECONDARY TO PROXY (%s, %d)", inet_ntoa(_proxy.publicIP), _proxy.port);
				}
			}
		}
		
		return;
 	}
 	
 	click_chatter("Error, Cannot connect to any primary node, Exiting\n");
 	exit(EXIT_FAILURE);
}

vector<int> GDPRouterNat::findPingTime() {
	int proxyIndex = 0;
	int tmin = 3000; //in ms
	struct icmphdr icmp_hdr;
	struct icmphdr rcv_hdr;
    struct sockaddr_in addr;
    struct timeval sendTime;
    struct timeval recvTime;
    unsigned char sendData[2048];
    unsigned char recvData[2048];
    fd_set read_set;
    int sequence = 0;
    int sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_ICMP);
    /*if (sock < 0) {
        perror("ICMP socket Error: ");
        return 0;
    }*/
    
    memset(&icmp_hdr, 0, sizeof icmp_hdr);
    icmp_hdr.type = ICMP_ECHO;
    icmp_hdr.un.echo.id = 1234;      //arbitrary id
    memcpy(sendData, &icmp_hdr, sizeof(icmp_hdr));
	memcpy(sendData + sizeof(icmp_hdr), "hello", 5);  //icmp payload
	memset(&read_set, 0, sizeof(read_set));
    FD_SET(sock, &read_set);
	
	vector<int> pingTimes;
	int numP = _primaryNodes.size();
    for (int i = 0; i < numP; i++) {
    	memset(&addr, 0, sizeof addr);
    	addr.sin_family = AF_INET;
    	addr.sin_addr = _primaryNodes[i].publicIP;
    	
    	icmphdr* hdr = (icmphdr *)(sendData);
    	(hdr->un).echo.sequence = sequence++;
    
        int rc;
        struct timeval timeout = {3, 0};    //wait max 3 seconds for a reply
        socklen_t slen;

        gettimeofday( &sendTime, NULL);
        rc = sendto(sock, sendData, sizeof(icmp_hdr) + 5,
                        0, (struct sockaddr*)&addr, sizeof(addr));
        if (rc <= 0) {
            perror("ICMP sendTo Error: ");
            pingTimes.push_back(-1);
            continue;
        }

        //wait for a reply with a timeout
        rc = select(sock + 1, &read_set, NULL, NULL, &timeout);
        if (rc == 0) {
        	if (PRINT) {
        		click_chatter("ICMP Timeout, Moving to next node\n");
        	}
        	pingTimes.push_back(3000);
            continue;
        } else if (rc < 0) {
            perror("ICMP select Error: ");
            pingTimes.push_back(-1);
            continue;
        }

        slen = 0;
        rc = recvfrom(sock, recvData, sizeof(recvData), 0, NULL, &slen);
        if (rc <= 0) {
            perror("ICMP recvfrom Error: ");
            pingTimes.push_back(-1);
            continue;
        } else if (rc < sizeof(rcv_hdr)) {
        	pingTimes.push_back(3000);
            continue;
        }
        
        memcpy(&rcv_hdr, recvData, sizeof(rcv_hdr));
        if (rcv_hdr.type == ICMP_ECHOREPLY) {
            gettimeofday( &recvTime, NULL);
			if( (recvTime.tv_usec -= sendTime.tv_usec) < 0 )   {
				recvTime.tv_sec--;
				recvTime.tv_usec += 1000000;
			}
			recvTime.tv_sec -= sendTime.tv_sec;
			int triptime = recvTime.tv_sec*1000+(recvTime.tv_usec/1000);
			if (PRINT) {
				click_chatter("ICMP Reply, id=0x%x, sequence =  0x%x, TIME: %d ms\n",
								icmp_hdr.un.echo.id, icmp_hdr.un.echo.sequence, triptime);
            }
            if (tmin > triptime) {
            	tmin = triptime;
            	proxyIndex = i;
            }
            pingTimes.push_back(triptime);
        } else {
        	pingTimes.push_back(-1);
            continue;
        }
    }
    return pingTimes;
}

int GDPRouterNat::handleClientFailure(int clientFD) {
	
	// Update _clientAdvertisments
	if (PRINT) {
		click_chatter("Detected Client Failure\n");
	}
	
	// Gather all the 256 ID mapped to the client connection;
	vector<string> advertismentsToRemove;
	for (map<string, int>::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
		if (it->second == clientFD) {
			advertismentsToRemove.push_back(it->first);
			if (PRINT) {
				click_chatter("client with ID: %s, failed\n", (it->first).c_str());
			}
		}
	}
	
	// Remove all entries and also concatenate into a single string to send to other nodes;
	string concatAdvertisments;
	int numAdv = advertismentsToRemove.size();
	for (int i = 0; i < numAdv; i++) {
		concatAdvertisments += advertismentsToRemove[i];
		_clientAdvertisments.erase(advertismentsToRemove[i]);
	}
	
	if (_myType == 'P') {
		//create WITHDRAW_CLIENT_PRIMARY packet
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = advertismentsToRemove.size() * 32;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char *withdrawClientPrimaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* withdrawClientPrimaryPacket = (routePacket *)(withdrawClientPrimaryOffset);
		withdrawClientPrimaryPacket->type = WITHDRAW_CLIENT_PRIMARY;
		withdrawClientPrimaryPacket->src = _myInfo;
		withdrawClientPrimaryPacket->numClientAdvertisments = advertismentsToRemove.size();
		withdrawClientPrimaryPacket->numSecondaryAdvertisments = 0;
		withdrawClientPrimaryPacket->numSecondary = 0;
		withdrawClientPrimaryPacket->numPrimary = 0;
		withdrawClientPrimaryPacket->isTypeAssigned = false;
		
		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
		memcpy((void *)(sendPacket->data() + totalHeaderSize),
				(void *)(concatAdvertisments.c_str()), concatAdvertisments.length());
				
		// Send WITHDRAW_CLIENT_PRIMARY to each Primary node from _primaryNodes
		int numPNodes = _primaryNodes.size();
		for (int i = 0; i < numPNodes; i++) {
			routePacket* r = (routePacket *)(sendPacket->data());
			r->dst = _primaryNodes[i]; 
			
			map<routeTableEntry, int>::iterator findFD = _routeTable.find(_primaryNodes[i]);
			
			if (findFD != _routeTable.end()) {
				int sendFD = findFD->second;
				if (LOG) {
					_logSendAdvNumber[sendFD] = _logSendAdvNumber[sendFD] + 1;
					_logSendAdvBytes[sendFD] = _logSendAdvBytes[sendFD] + sendPacket->length();
				}
				int sentPacket = regulatedWrite(sendFD, sendPacket->data(), sendPacket->length());
			
				if (PRINT) {
					click_chatter("I am a P node sending WITHDRAW_CLIENT_PRIMARY to node (%s, %d)\n", inet_ntoa(_primaryNodes[i].publicIP), 
									_primaryNodes[i].port);
				}
				if (sentPacket < 0) {
					perror("Error forwarding WITHDRAW_CLIENT_PRIMARY: \n");
				}
			} else {
				click_chatter("I dont have file descriptor for primary node (%s, %d)\n", inet_ntoa(_primaryNodes[i].publicIP), 
									_primaryNodes[i].port);
			}
 		}
		
		sendPacket->kill();
	} else if (_myType == 'S') {
		// If I am a secondary node, I will send a WITHDRAW_CLIENT_SECONDARY command to all nodes
		// in my routeTable and also to the proxy
		//create WITHDRAW_CLIENT_SECONDARY packet
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = advertismentsToRemove.size() * 32;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char* withdrawClientSecondaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* withdrawClientSecondaryPacket = (routePacket *)(withdrawClientSecondaryOffset);
		withdrawClientSecondaryPacket->type = WITHDRAW_CLIENT_SECONDARY;
		withdrawClientSecondaryPacket->src = _myInfo;
		withdrawClientSecondaryPacket->numClientAdvertisments = advertismentsToRemove.size();
		withdrawClientSecondaryPacket->numSecondaryAdvertisments = 0;
		withdrawClientSecondaryPacket->numSecondary = 0;
		withdrawClientSecondaryPacket->numPrimary = 0;
		withdrawClientSecondaryPacket->isTypeAssigned = false;
		
		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
		memcpy((void *)(sendPacket->data() + totalHeaderSize), (void *)(concatAdvertisments.c_str()), concatAdvertisments.length());
				
		// Send WITHDRAW_CLIENT_SECONDARY to all S members in the routing table
		for (map<routeTableEntry, int>::iterator it = _routeTable.begin(); it != _routeTable.end(); it++) {
			routeTableEntry node = it->first;
			int sendFD = it->second;
			if (node.publicIP.s_addr != node.privateIP.s_addr) {
				// node is an S node
				routePacket* r = (routePacket *)(sendPacket->data());
				r->dst = node; 
				if (LOG) {
					_logSendAdvNumber[sendFD] = _logSendAdvNumber[sendFD] + 1;
					_logSendAdvBytes[sendFD] = _logSendAdvBytes[sendFD] + sendPacket->length();
				}
				int sentPacket = regulatedWrite(sendFD, sendPacket->data(), sendPacket->length());
				//write(sendFD, sendPacket->data(), sendPacket->length());
				
				if (PRINT) {
					string pubIP(inet_ntoa(node.publicIP));
					string priIP(inet_ntoa(node.privateIP));
					click_chatter("I am a S node sending WITHDRAW_CLIENT_SECONDARY to node (%s, %s, %d)\n", pubIP.c_str(), priIP.c_str(), 
								node.port);
				}
				
				if (sentPacket < 0) {
					perror("Error forwarding WITHDRAW_CLIENT_SECONDARY: \n");
				}
			}
		}
		
		// Send WITHDRAW_CLIENT_SECONDARY to proxy as well
		if (_proxyFD != -1) {
			routePacket* r = (routePacket *)(sendPacket->data());
			r->dst = _proxy;
			if (LOG) {
				_logSendAdvNumber[_proxyFD] = _logSendAdvNumber[_proxyFD] + 1;
				_logSendAdvBytes[_proxyFD] = _logSendAdvBytes[_proxyFD] + sendPacket->length();
			}
			int sentPacket = regulatedWrite(_proxyFD, sendPacket->data(), sendPacket->length());
			//write(_proxyFD, sendPacket->data(), sendPacket->length());
			
			if (PRINT) {
				click_chatter("Sending WITHDRAW_CLIENT_SECONDARY to proxy (%s, %d)\n", inet_ntoa(_proxy.publicIP), _proxy.port);
			}
			if (sentPacket < 0) {
				perror("Error forwarding WITHDRAW_CLIENT_SECONDARY to proxy: \n");
			}
		}
		sendPacket->kill();
	}
	
	// close the connection
	remove_select(clientFD, SELECT_READ);
	_type.erase(clientFD);
	_isFDReady.erase(clientFD);
	_recvBuffer.erase(clientFD);
	_tempSendBuffer.erase(clientFD);
	if (LOG) {
		eraseStats(clientFD);
	}
	close(clientFD);
	return 0;
}

int GDPRouterNat::handleSecondaryFailure(int secFD) {
	// identify the S node that failed given the connection handler
	if (PRINT) {
		click_chatter("Detected a Secondary Node failure\n");
	}
	bool foundFailedNode = false;
	routeTableEntry failedNode;
	for (map<routeTableEntry, int>::iterator it = _routeTable.begin(); it != _routeTable.end(); it++) {
		if (it->second == secFD) {
			foundFailedNode = true;
			failedNode = it->first;
		}
	} 
	
	if (foundFailedNode == true) {
		if (PRINT) {
				string pubIP(inet_ntoa(failedNode.publicIP));
				string priIP(inet_ntoa(failedNode.privateIP));
				click_chatter("I detected (%s, %s, %d) S node failed\n", pubIP.c_str(), priIP.c_str(), 
							failedNode.port);
		}
		
		// remove all the client advertisments directly connected to secondary node
		// from _secondaryAdvertisments
		
		// Gather all the 256 ID connected to the failed node;
		vector<string> advertismentsToRemove;
		for (map<string, routeTableEntry>::iterator it = _secondaryAdvertisments.begin(); it != _secondaryAdvertisments.end(); it++) {
			if (it->second == failedNode) {
				advertismentsToRemove.push_back(it->first);
				if (PRINT) {
					click_chatter("The client directly connected to the secondary node: %s\n", (it->first).c_str());
				}
			}
		}

		// Remove all the identified entries from _secondaryAdvertisments;
		int numAdv = advertismentsToRemove.size();
		for (int i = 0; i < numAdv; i++) {
			_secondaryAdvertisments.erase(advertismentsToRemove[i]);
		}
		
		// update _routeTable by  removing the failed node entry
		_routeTable.erase(failedNode);
		
		if (_myType == 'P') {
			// If am a P node and I detected an S node failure
			// Then I was the proxy for the failed S node.
			// I will do two additional tasks
			// 1. update _publicToPrivate by removing the failed S node
			// 2. I will send a WITHDRAW_SECONDARY command to the
			//    other P nodes, informing them of S node failure
			
			// find the failed S node Group in _publicToPrivate;
			map<unsigned long, vector<routeTableEntry> >::iterator findSGroup = _publicToPrivate.find(failedNode.publicIP.s_addr);
			
			if (findSGroup != _publicToPrivate.end()) {
				// I found the S node group to which the failed node belonged
				
				int findSIndex = -1;
				int numS = (findSGroup->second).size();
				for (int i = 0; i < numS; i++) {
					if (failedNode == (findSGroup->second)[i]) {
						findSIndex = i;
						break;
					}
				}
				
				if (findSIndex >= 0) {
					// found the S node in the S group inside _publicToPrivate
					
					// remove the S node inside the S group
					(findSGroup->second).erase((findSGroup->second).begin() + findSIndex);
					
					int newSize = (findSGroup->second).size();
					if (newSize == 0) {
						if (PRINT) {
							click_chatter("The failed S node was the only node I had in the S group\n");
						}
						_publicToPrivate.erase(findSGroup);
					}
				} else {
					click_chatter("Error: I found the S group but i didnt find the failed S node inside the S group\n");
				}
			} else {
				click_chatter("Error I couldnt find the S group to which the failed S node belonged\n");
			}
			
			// send WITHDRAW_SECONDARY command to other P nodes
			char version = (char)(VERSION);
			char cmd = (char)(ROUTE_PROTOCOL);
			string dst = _GDPRouterAddress;
			string src = _GDPRouterAddress;
			int packetDataSize = sizeof(routeTableEntry);
			WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
			
			char *withdrawSecondaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
			routePacket* withdrawSecondaryPacket = (routePacket *)(withdrawSecondaryOffset);
			withdrawSecondaryPacket->type = WITHDRAW_SECONDARY;
			withdrawSecondaryPacket->src = _myInfo;
			withdrawSecondaryPacket->numClientAdvertisments = 0;
			withdrawSecondaryPacket->numSecondaryAdvertisments = 0;
			withdrawSecondaryPacket->numSecondary = 1;
			withdrawSecondaryPacket->numPrimary = 0;
			withdrawSecondaryPacket->isTypeAssigned = 0;
		
			int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
			memcpy((void *)(sendPacket->data() + totalHeaderSize),
					(void *)(&failedNode), sizeof(routeTableEntry));
				
			// Send WITHDRAW SECONDARY PACKET to all primary nodes
			int numPnodes = _primaryNodes.size();
			for (int i = 0; i < numPnodes; i++) {
				routePacket* routePacketOffset = (routePacket *)(sendPacket->data());
				routePacketOffset->dst = _primaryNodes[i];
			
				map<routeTableEntry, int>::iterator findFD = _routeTable.find(_primaryNodes[i]);
			
				if (findFD != _routeTable.end()) {
					int sendFD = findFD->second;
					int sentPacket = regulatedWrite(sendFD, sendPacket->data() , sendPacket->length());
			
					if (PRINT) {
						click_chatter("Sending WITHDRAW_SECONDARY to primary node (%s, %d) \n", inet_ntoa(_primaryNodes[i].publicIP),
										_primaryNodes[i].port);
					}
				
					if (sentPacket < 0) {
						perror("Error writing packet to remote socket: \n");
					}
				} else {
					click_chatter("I dont have the file descriptor for primary node (%s, %d) \n", inet_ntoa(_primaryNodes[i].publicIP),
										_primaryNodes[i].port);
				}
			}
			sendPacket->kill();
		}
	} else {
		click_chatter("Error: Couldnt find the failed S node in the routeTable\n");
	}
			
	// close connection
	remove_select(secFD, SELECT_READ);
	_type.erase(secFD);
	_isFDReady.erase(secFD);
	_recvBuffer.erase(secFD);
	_tempSendBuffer.erase(secFD);
	if (LOG) {
		eraseStats(secFD);
	}
	close(secFD);
	return 0;
}

int GDPRouterNat::handlePrimaryFailure(int priFD) {
	if (PRINT) {
		click_chatter("Detected Primary Node Failure\n");
	}
	if (_myType == 'P') {
		// I am a P node and I detected failure of another P node
		// I have 2 tasks
		// 1. update my state
		// 2. send WITHDRAW_PRIMARY command to all S nodes directly connected to me
		
		// Update _routeTable, Remove all entries for which fd = priFD
		// These include the P node that failed
		// All S nodes connected to failed P node
		// find the failed primary node as well
		
		vector<routeTableEntry> removeEntries;
		routeTableEntry failedNode;
		bool foundFailedNode;
		for (map<routeTableEntry, int>::iterator it = _routeTable.begin(); it != _routeTable.end(); it++) {
			if (it->second == priFD) {
				removeEntries.push_back(it->first);
				if ((it->first).publicIP.s_addr == (it->first).privateIP.s_addr) {
					// found the failed P node
					foundFailedNode = true;
					failedNode = it->first;
				}
			}
		}
		
		int removeEntriesNum = removeEntries.size();
		for (int i = 0; i < removeEntriesNum; i++) {
			_routeTable.erase(removeEntries[i]);
		}
		
		if (foundFailedNode == true) {
			// Update _primaryNodes, remove the failed P node;
			// find the index of the failed P nodes inside _primaryNodes
			if (PRINT) {
				click_chatter("The failed P node is (%s, %d)\n", inet_ntoa(failedNode.publicIP), failedNode.port);
			}
			
			// remove the P node from _primaryNodes
			int findIndex = -1;
			int numP = _primaryNodes.size();
			for (int i = 0; i < numP; i++) {
				if (_primaryNodes[i] == failedNode) {
					findIndex = i;
					break;
				}
			}
			
			if (findIndex >= 0) {
				_primaryNodes.erase(_primaryNodes.begin() + findIndex);
			} else {
				click_chatter("Error, Unable to locate the failed P node inside _primaryNodes");
			}
			
			// Update _primaryAdvertisments, remove all entries for the failed node
			// Gather all the 256 ID connected to the failed node;
			vector<string> advertismentsToRemove;
			for (map<string, routeTableEntry>::iterator it = _primaryAdvertisments.begin(); it != _primaryAdvertisments.end(); it++) {
				if (it->second == failedNode) {
					advertismentsToRemove.push_back(it->first);
					if (PRINT) {
						click_chatter("Client directly connected to failed P node: %s\n", (it->first).c_str());
					}
				}
			}

			// Remove all the identified entries from _primaryAdvertisments;
			int numAdv = advertismentsToRemove.size();
			for (int i = 0; i < numAdv; i++) {
				_primaryAdvertisments.erase(advertismentsToRemove[i]);
			}
			
			if (failedNode.canBeProxy == true) {
				// if the failed node could have served as a proxy
				// all directly S nodes need to be informed that the node doesnt exist anymore
				
				// Send a WITHDRAW_PRIMARY command to all the S nodes directly connected to me
				// creating WITHDRAW_PRIMARY for directly connected secondary nodes
				char version = (char)(VERSION);
				char cmd = (char)(ROUTE_PROTOCOL);
				string dst = _GDPRouterAddress;
				string src = _GDPRouterAddress;
				int packetDataSize = sizeof(routeTableEntry);
				WritablePacket* sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
			
				char* withdrawPrimaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
				routePacket* withdrawPrimaryPacket = (routePacket *)(withdrawPrimaryOffset);
				withdrawPrimaryPacket->type = WITHDRAW_PRIMARY;
				withdrawPrimaryPacket->src = _myInfo;
				withdrawPrimaryPacket->numClientAdvertisments = 0;
				withdrawPrimaryPacket->numSecondaryAdvertisments = 0;
				withdrawPrimaryPacket->numSecondary = 0;
				withdrawPrimaryPacket->numPrimary = 1;
				withdrawPrimaryPacket->isTypeAssigned = false;
		
				int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
				memcpy((void *)(sendPacket->data() + totalHeaderSize), &(failedNode), sizeof(routeTableEntry));
	
				//Sending WITHDRAW_PRIMARY to all directly connected secondary nodes
				for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
					int size = (it->second).size();
					for (int i = 0; i < size; i++) {
						routeTableEntry s = (it->second)[i];
			
						routePacket* r = (routePacket *)(sendPacket->data());
						r->dst = s;
			
						map<routeTableEntry, int>::iterator findFD = _routeTable.find(s);
						if (findFD != _routeTable.end()) {
							int sendFD = findFD->second;
							int sentPacket = regulatedWrite(sendFD, sendPacket->data() , sendPacket->length());
							if (PRINT) {
								string pubIP(inet_ntoa(s.publicIP));
								string priIP(inet_ntoa(s.privateIP));
								click_chatter("Sending WITHDRAW_PRIMARY to node (%s, %s, %d), %d\n", pubIP.c_str(), priIP.c_str(), s.port, _routeTable[s]);
							}
				
							if (sentPacket < 0) {
								perror("Error writing Withdraw Primary packet to remote socket: \n");
							}
						} else {
							string pubIP(inet_ntoa(s.publicIP));
							string priIP(inet_ntoa(s.privateIP));
							click_chatter("I dont have the file descriptor for secondary node (%s, %s, %d), %d\n", pubIP.c_str(), priIP.c_str(), s.port);
						}
					}
				}
				sendPacket->kill();
			}
		} else {
			click_chatter("Error, Couldnt find the failed P node given the fd\n");
		}
	} else if (_myType == 'S' && priFD == _proxyFD) {
		// I am an S node and I detected a P node failure
		// the failed P node was my proxy
		// My tasks are
		// 1. Update my states
		// 2. find a new proxy
		// 3. send UPDATE_SECONDARY command to new proxy
		
		if (PRINT) {
			click_chatter("My Proxy (%s, %d) has failed\n", inet_ntoa(_proxy.publicIP), _proxy.port);
		}
		
		map<routeTableEntry,int>::iterator findFD = _routeTable.find(_proxy);
		if (findFD != _routeTable.end()) {
			_routeTable.erase(findFD);
		}
		
		// Remove the node from the _primaryNodes list
		int findIndex = -1;
		int numP = _primaryNodes.size();
		for (int i = 0; i < numP; i++) {
			if (_proxy == _primaryNodes[i]) {
				findIndex = i;
				break;
			}
		}
		
		if (findIndex >= 0) {
			_primaryNodes.erase(_primaryNodes.begin() + findIndex);
		} else {
			click_chatter("Error My proxy is not in my _primaryNodes list\n");
		}
		
		// Prepare UPDATE_SECONDARY command
		// 1. contains my location
		// 2. IDs of all my directly connected clients (_clientAdvertisments)
		char version = (char)(VERSION);
		char cmd = (char)(ROUTE_PROTOCOL);
		string dst = _GDPRouterAddress;
		string src = _GDPRouterAddress;
		int packetDataSize = _clientAdvertisments.size() * 32;
		WritablePacket *sendPacket = createGDPPacket(version, cmd, dst, src, packetDataSize);
		
		char* updateSecondaryOffset = (char *)(sendPacket->data()) + GDP_HEADER_SIZE;
		routePacket* updateSecondaryPacket = (routePacket *)(updateSecondaryOffset);
		updateSecondaryPacket->type = UPDATE_SECONDARY;
		updateSecondaryPacket->src = _myInfo;
		updateSecondaryPacket->numClientAdvertisments = _clientAdvertisments.size();
		updateSecondaryPacket->numSecondaryAdvertisments = 0;
		updateSecondaryPacket->numSecondary = 0;
		updateSecondaryPacket->numPrimary = 0;
		updateSecondaryPacket->isTypeAssigned = false;
		
		int totalHeaderSize = GDP_HEADER_SIZE + sizeof(routePacket);
		if (updateSecondaryPacket->numClientAdvertisments > 0) {
			string concatAdvertisments;
			for(map<string, int >::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
					concatAdvertisments += (it->first).substr(0,32);
			}
			memcpy((void *)(sendPacket->data() + totalHeaderSize), 
				   (void *)concatAdvertisments.c_str(), concatAdvertisments.length());
		}
		
		// chose a proxy 
		findProxyAndConnect(sendPacket);
		
		if (PRINT) {
			click_chatter(" New Chosen Proxy is (%s, %d)\n", inet_ntoa(_primaryNodes[_proxyIndex].publicIP), _primaryNodes[_proxyIndex].port);
		}
		
		sendPacket->kill();
	}
	
	// close connection
	remove_select(priFD, SELECT_READ);
	_type.erase(priFD);
	_isFDReady.erase(priFD);
	_recvBuffer.erase(priFD);
	_tempSendBuffer.erase(priFD);
	if (LOG) {
		eraseStats(priFD);
	}
	close(priFD);
	return 0;
}

int GDPRouterNat::handleConnectionFailure(int recvFD) {
	if (_type[recvFD] == 'C') {
		return handleClientFailure(recvFD);
	} else if (_type[recvFD] == 'S') {
		return handleSecondaryFailure(recvFD);
	} else if (_type[recvFD] == 'P') {
		return handlePrimaryFailure(recvFD);
	} else {
		remove_select(recvFD, SELECT_READ);
		close(recvFD);
		if (LOG) {
			eraseStats(recvFD);
		}
		return 0;
	}
}

void GDPRouterNat::displayLogBytes() {
	if (_myType == 'P') {
		click_chatter("-----------------BEGIN LOG------------------\n");
		click_chatter("--------------Primary Nodes------------------\n");
		int numP = _primaryNodes.size();
		for (int i = 0; i < numP; i++) {
			map<routeTableEntry, int>::iterator findFD = _routeTable.find(_primaryNodes[i]);
			if (findFD != _routeTable.end()) {
				string pubIP = inet_ntoa(_primaryNodes[i].publicIP);
				string priIP = inet_ntoa(_primaryNodes[i].privateIP);
				click_chatter("(%s, %s, %d): \n", pubIP.c_str(), priIP.c_str(), _primaryNodes[i].port);
				
				map<int, unsigned long>::iterator findRecvBytes = _logRecvBytes.find(findFD->second);
				if (findRecvBytes != _logRecvBytes.end()) {
					click_chatter("Bytes Received: %lu\n", findRecvBytes->second);
				}
				
				map<int, unsigned long>::iterator findSendBytes = _logSendBytes.find(findFD->second);
				if (findSendBytes != _logSendBytes.end()) {
					click_chatter("Bytes Sent: %lu\n", findSendBytes->second);
				}
				
				click_chatter("\n");
			}
		}
		
		click_chatter("\n\n");
		click_chatter("-------------Secondary Nodes-------------\n");
		for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
			int numS = (it->second).size();
			for (int i = 0; i < numS; i++) {
				map<routeTableEntry, int>::iterator findFD = _routeTable.find((it->second)[i]);
				if (findFD != _routeTable.end()) {
					string pubIP = inet_ntoa((it->second)[i].publicIP);
					string priIP = inet_ntoa((it->second)[i].privateIP);
					click_chatter("(%s, %s, %d): \n", pubIP.c_str(), priIP.c_str(), (it->second)[i].port);
				
					map<int, unsigned long>::iterator findRecvBytes = _logRecvBytes.find(findFD->second);
					if (findRecvBytes != _logRecvBytes.end()) {
						click_chatter("Bytes Received: %lu\n", findRecvBytes->second);
					}
				
					map<int, unsigned long>::iterator findSendBytes = _logSendBytes.find(findFD->second);
					if (findSendBytes != _logSendBytes.end()) {
						click_chatter("Bytes Sent: %lu\n", findSendBytes->second);
					}
					
					click_chatter("\n");
				}
			}
		}
		click_chatter("-----------------END LOG------------------\n");
	} else if (_myType == 'S') {
		click_chatter("-----------------BEGIN LOG------------------\n");
		click_chatter("-------------Secondary Nodes-------------\n");
		for (map<routeTableEntry, int>::iterator it = _routeTable.begin(); it != _routeTable.end(); it++) {
			if ((it->first).publicIP.s_addr != (it->first).privateIP.s_addr) {
				string pubIP = inet_ntoa((it->first).publicIP);
				string priIP = inet_ntoa((it->first).privateIP);
				click_chatter("(%s, %s, %d): \n", pubIP.c_str(), priIP.c_str(),(it->first).port);
			
				map<int, unsigned long>::iterator findRecvBytes = _logRecvBytes.find(it->second);
				if (findRecvBytes != _logRecvBytes.end()) {
					click_chatter("Bytes Received: %lu\n", findRecvBytes->second);
				}
			
				map<int, unsigned long>::iterator findSendBytes = _logSendBytes.find(it->second);
				if (findSendBytes != _logSendBytes.end()) {
					click_chatter("Bytes Sent: %lu\n", findSendBytes->second);
				}
			
				click_chatter("\n");
			}
		}
		
		click_chatter("\n\n");
		click_chatter("-------------Proxy-------------\n");
		string pubIP = inet_ntoa(_proxy.publicIP);
		string priIP = inet_ntoa(_proxy.privateIP);
		click_chatter("(%s, %s, %d): \n", pubIP.c_str(), priIP.c_str(), _proxy.port);
		map<int, unsigned long>::iterator findRecvBytes = _logRecvBytes.find(_proxyFD);
		if (findRecvBytes != _logRecvBytes.end()) {
			click_chatter("Bytes Received: %lu\n", findRecvBytes->second);
		}
	
		map<int, unsigned long>::iterator findSendBytes = _logSendBytes.find(_proxyFD);
		if (findSendBytes != _logSendBytes.end()) {
			click_chatter("Bytes Sent: %lu\n", findSendBytes->second);
		}
		click_chatter("-----------------END LOG------------------\n");
	}
}

int GDPRouterNat::processPacket(int fd, string& message, int dataLen, int optLen, int sigLen, struct in_addr& newConnPublicIP) {
	int status = 0;
	string packetSrc = message.substr(36, 32);
	string packetDst = message.substr(4, 32);
	unsigned char packetCmd = message[3];
	
	if (packetSrc == _GDPRouterAddress && packetCmd == ROUTE_PROTOCOL) {
		// The received packet from a routing node
		// meant for routing layer
		
		string packetData = message.substr(80 + optLen, dataLen);
		const char* routePacketOffset = packetData.c_str();
		routePacket *recvPacket = (routePacket *)routePacketOffset;
		
		if (recvPacket->type == JOIN) {
			status = handleJoinPacket(fd, recvPacket, newConnPublicIP);
		} else if (recvPacket->type == ADD_PRIMARY) {
			status = handleAddPrimary(fd, recvPacket);
		} else if (recvPacket->type == ADD_SECONDARY) {
			status = handleAddSecondary(fd, recvPacket);
		} else if (recvPacket->type == JOIN_SECONDARY) {
			status = handleJoinSecondary(fd, recvPacket);
		} else if (recvPacket->type == UPDATE_SECONDARY) {
			status = handleUpdateSecondary(fd, recvPacket);
		} else if (recvPacket->type == JOIN_ACK) {
			status = handleJoinAckPacket(fd, recvPacket);
		} else if (recvPacket->type == ADD_PRIMARY_ACK) {
			status = handleAddPrimaryAck(fd, recvPacket);
		} else if (recvPacket->type == ADD_SECONDARY_ACK) {
			status = handleAddAckSecondary(recvPacket);
		} else if (recvPacket->type == NEW_PRIMARY) {
			status = handleNewPrimary(recvPacket);
		} else if (recvPacket->type == WITHDRAW_PRIMARY) {
			status = handleWithdrawPrimary(recvPacket);
		} else if (recvPacket->type == JOIN_SECONDARY_ACK || recvPacket->type == UPDATE_SECONDARY_ACK) {
			status = handleJoinSecondaryAck(fd, recvPacket);
		} else if (recvPacket->type == JOIN_SECONDARY_NAK || recvPacket->type == UPDATE_SECONDARY_NAK) {
			status = handleJoinSecondaryNak(fd, recvPacket);
		}  else if (recvPacket->type == NEW_SECONDARY) {
			status = handleNewSecondary(fd, recvPacket, message);
		} else if (recvPacket->type == WITHDRAW_SECONDARY) {
			status = handleWithdrawSecondary(recvPacket);
		} else if (recvPacket->type == NEW_CLIENT_PRIMARY || recvPacket->type == WITHDRAW_CLIENT_PRIMARY) {
			if (LOG) {
				_logRecvAdvNumber[fd] = _logRecvAdvNumber[fd] + 1;
				_logRecvAdvBytes[fd]  =  _logRecvAdvBytes[fd] + message.length();
			}
			status = handleClientPrimary(recvPacket);
		} else if (recvPacket->type == NEW_CLIENT_SECONDARY || recvPacket->type == WITHDRAW_CLIENT_SECONDARY) {
			if (LOG) {
				_logRecvAdvNumber[fd] = _logRecvAdvNumber[fd] + 1;
				_logRecvAdvBytes[fd]  =  _logRecvAdvBytes[fd] + message.length();
			}
			status = handleClientSecondary(fd, recvPacket, message);
		} else if (recvPacket->type == PING) {
			if (PRINT) {
				click_chatter("Recived a ping packet\n");
			}
			if (LOG) {
				_logRecvPingNumber[fd] = _logRecvPingNumber[fd] + 1;
				_logRecvPingBytes[fd]  =  _logRecvPingBytes[fd] + message.length();
			}
			/*if (LOG) {
				_logDisplayCounter++;
				if (_logDisplayCounter == LOG_DISPLAY_FREQUENCY) {
					_logDisplayCounter = 0;
					displayLogBytes();
				}
			}*/
		} else if (recvPacket->type == COOL) {
			if (PRINT) {
				click_chatter("Recived a cool packet\n");
			}
		} else {
			click_chatter("Illegal Route CMD\n");
			return -1;
		}
	} else if (packetDst == _GDPRouterAddress && (packetCmd == ADVERTISE_CMD || packetCmd == ADVERTISE_WITHDRAW)) {
		// The new received packet is from an incoming gdp entity
		// and hence it is an advertisement
		_isFDReady[fd] = true;
		_type[fd] = 'C';
		status = handleClientAdvertisment(fd, message, dataLen, optLen, packetSrc, packetCmd);
	} else if (packetDst == _GDPRouterAddress && packetCmd == 0) {
		// the message is for routing layer because destination is _GDPRouteraddress
		// the message is simply a keep Alive
		// ignore for now
	} else if (packetDst == _GDPRouterAddress && packetCmd != ADVERTISE_CMD && packetCmd != ADVERTISE_WITHDRAW && packetCmd != 0) {
		// the message is for routing layer because destination is _GDPRouteraddress
		// However, the message contains a command other than [0, 1, 2]
		// terminate connection
		handleConnectionFailure(fd);
	 } else {
		//This packet is not meant for the routing layer Simply forward it
		if (LOG) {
			_logRecvFwdNumber[fd] = _logRecvFwdNumber[fd] + 1;
			_logRecvFwdBytes[fd] = _logRecvFwdBytes[fd] + message.length();
		}
		status = handleForwardPacket(fd, packetDst, packetSrc, message , dataLen, optLen, sigLen);
	}
	return status;
}

// web interface functions
void GDPRouterNat::initialize_webServer() {
	// create socket
	_webFD = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	_webServer.sin_family = AF_INET;
	_webServer.sin_port = htons(_webPort);
	_webServer.sin_addr.s_addr = INADDR_ANY;
	int webLen = sizeof(_webServer);

	socklen_t sockOptLen = sizeof(int);
	int sendBufSize;
	int err = getsockopt(_webFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);
	if (err < 0) {
		perror("Error in obtaining recv buffer size: \n");
	}

	sendBufSize= sendBufSize * 5;
	err = setsockopt(_webFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize,
							 sizeof(sendBufSize));


	if (bind(_webFD, (struct sockaddr *) &_webServer, webLen) < 0) {
		perror("error binding socket: \n");
		exit(EXIT_FAILURE);
	}
	
	listen(_webFD,5);

	err = getsockopt(_webFD, SOL_SOCKET, SO_RCVBUF, (char *)&sendBufSize, &sockOptLen);

	// nonblocking I/O and close-on-exec for the socket
	fcntl(_webFD, F_SETFL, O_NONBLOCK);
	fcntl(_webFD, F_SETFD, FD_CLOEXEC);

	add_select(_webFD, SELECT_READ);
}

string GDPRouterNat::stringToHex(string& input)
{
    static const char* const lut = "0123456789ABCDEF";
    size_t len = input.length();

    string output;
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        char p = lut[c >> 4];
        output += p;
        p = lut[c & 15];
        output += p;
    }
    return output;
}

void GDPRouterNat::sendLogBytes(int fd) {
	if (_myType == 'P') {
		json_t *primaryObject;
		primaryObject = json_array();
		int numP = _primaryNodes.size();
		for (int i = 0; i < numP; i++) {
			map<routeTableEntry, int>::iterator findFD = _routeTable.find(_primaryNodes[i]);
			if (findFD != _routeTable.end()) {
				json_t* info = json_object();
				string pubIP = inet_ntoa(_primaryNodes[i].publicIP);
				string key = pubIP;
				key += ":";
				char port[33];
				snprintf(port, sizeof(port), "%d", (int)(_primaryNodes[i].port));
				key += port;
				json_object_set_new(info, "NodeID (IP:port)", json_string(key.c_str()));
				
				map<int, unsigned long>::iterator findRecvBytes = _logRecvBytes.find(findFD->second);
				if (findRecvBytes != _logRecvBytes.end()) {
					json_object_set_new(info, "BytesReceived", json_integer(findRecvBytes->second));
				} else {
					json_object_set_new(info, "BytesReceived", json_integer(0));
				}
				
				map<int, unsigned long>::iterator findSendBytes = _logSendBytes.find(findFD->second);
				if (findSendBytes != _logSendBytes.end()) {
					json_object_set_new(info, "BytesSent", json_integer(findSendBytes->second));
				} else {
					json_object_set_new(info, "BytesSent", json_integer(0));
				}
				
				map<int, double>::iterator findRecvBw = _recvThroughput.find(findFD->second);
				if (findRecvBw != _recvThroughput.end()) {
					json_object_set_new(info, "Inbound Throughput (bps) ", json_real(findRecvBw->second));
				} else {
					json_object_set_new(info, "Inbound Throughput (bps) ", json_real(0));
				}
				
				map<int, double>::iterator findSendBw = _sendThroughput.find(findFD->second);
				if (findSendBw != _sendThroughput.end()) {
					json_object_set_new(info, "Outbound Throughput (bps) ", json_real(findSendBw->second));
				} else {
					json_object_set_new(info, "Outbound Throughput (bps) ", json_real(0));
				}
				
				 json_array_append_new(primaryObject, info);
			}
		}
		
		json_t *secondaryObject;
		secondaryObject = json_array();
		for (map<unsigned long, vector<routeTableEntry> >::iterator it = _publicToPrivate.begin(); it != _publicToPrivate.end(); it++) {
			int numS = (it->second).size();
			json_t* sec;
			if (numS > 0) {
				sec = json_array();
			}
			for (int i = 0; i < numS; i++) {
				map<routeTableEntry, int>::iterator findFD = _routeTable.find((it->second)[i]);
				if (findFD != _routeTable.end()) {
					json_t* info = json_object();
					string priIP = inet_ntoa((it->second)[i].privateIP);
					string key = priIP;
					key += ":";
					char port[33];
					snprintf(port, sizeof(port), "%d", (int)(it->second)[i].port);
					key += port;
					json_object_set_new(info, "NodeID (IP:port)", json_string(key.c_str()));
				
					map<int, unsigned long>::iterator findRecvBytes = _logRecvBytes.find(findFD->second);
					if (findRecvBytes != _logRecvBytes.end()) {
						json_object_set_new(info, "BytesReceived", json_integer(findRecvBytes->second));
					} else {
						json_object_set_new(info, "BytesReceived", json_integer(0));
					}
				
					map<int, unsigned long>::iterator findSendBytes = _logSendBytes.find(findFD->second);
					if (findSendBytes != _logSendBytes.end()) {
						json_object_set_new(info, "BytesSent", json_integer(findSendBytes->second));
					} else {
						json_object_set_new(info, "BytesSent", json_integer(0));
					}
					
					map<int, double>::iterator findRecvBw = _recvThroughput.find(findFD->second);
					if (findRecvBw != _recvThroughput.end()) {
						json_object_set_new(info, "Inbound Throughput (bps) ", json_real(findRecvBw->second));
					} else {
						json_object_set_new(info, "Inbound Throughput (bps) ", json_real(0));
					}
					
					map<int, double>::iterator findSendBw = _sendThroughput.find(findFD->second);
					if (findSendBw != _sendThroughput.end()) {
						json_object_set_new(info, "Outbound Throughput (bps) ", json_real(findSendBw->second));
					} else {
						json_object_set_new(info, "Outbound Throughput (bps) ", json_real(0));
					}
					
					json_array_append_new(sec, info);
					
				}
			}
			
			if (numS > 0) {
				json_t* NATgrp = json_object();
				json_object_set_new(NATgrp, "NATIP", json_string(inet_ntoa((it->second)[0].publicIP)));
				json_object_set_new(NATgrp, "Nodes", sec);
				json_array_append_new(secondaryObject, NATgrp);
			}
		}
		
		json_t *clientObject;
		clientObject = json_array();
		for (map<string, int>::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
			string key = it->first;
			string keyInHex = stringToHex(key);
			json_array_append_new(clientObject, json_string(keyInHex.c_str()));
		}
		
		json_t* completeObject = json_object();
		json_object_set_new(completeObject, "My Type", json_string("Primary"));
		json_object_set_new(completeObject, "My Public IP", json_string(inet_ntoa(_myInfo.publicIP)));
		json_object_set_new(completeObject, "My Private IP", json_string(inet_ntoa(_myInfo.privateIP)));
		json_object_set_new(completeObject, "My GDP Port", json_integer(_myInfo.port));
		json_object_set_new(completeObject, "Primary Nodes", primaryObject);
		json_object_set_new(completeObject, "Secondary Nodes", secondaryObject);
		json_object_set_new(completeObject, "Clients", clientObject);
		char responseHeader[1024];
		char *responseData;
   		int responseLen;
   		
   		responseData = json_dumps(completeObject, JSON_INDENT(3));
   		responseLen = strlen(responseData);
   		snprintf(responseHeader, 1024, "%d", (int)responseLen);
   		json_decref(completeObject);
   		
   		string header = "Content-length: ";
	   	header += responseHeader;
	   	header += "\n";

	   	string finalPacket = "HTTP/1.1 200 OK\n";
		finalPacket += header;
	   	finalPacket +=  "Content-Type: application/json\n\n";
	   	string data(responseData, responseLen);
	   	finalPacket += data;
	   	
	   	int sentPacket = write(fd, finalPacket.c_str(), finalPacket.length());
	   	if (sentPacket < 0) {
	   		perror("Error sending HTTP JSON Packet: ");
	   	}
		
	} else if (_myType == 'S') {
		json_t *primaryObject;
		primaryObject = json_array();
		string pubIP = inet_ntoa(_proxy.publicIP);
		string key = pubIP;
		key += ":";
		char port[33];
		snprintf(port, sizeof(port), "%d", (int)(_proxy.port));
		key += port;
		
		json_t* info = json_object();
		json_object_set_new(info, "NodeID (IP:port)", json_string(key.c_str()));
		map<int, unsigned long>::iterator findRecvBytes = _logRecvBytes.find(_proxyFD);
		if (findRecvBytes != _logRecvBytes.end()) {
			json_object_set_new(info, "BytesReceived", json_integer(findRecvBytes->second));
		} else {
			json_object_set_new(info, "BytesReceived", json_integer(0));
		}
	
		map<int, unsigned long>::iterator findSendBytes = _logSendBytes.find(_proxyFD);
		if (findSendBytes != _logSendBytes.end()) {
			json_object_set_new(info, "BytesSent", json_integer(findSendBytes->second));
		} else {
			json_object_set_new(info, "BytesSent", json_integer(0));
		}
		
		map<int, double>::iterator findRecvBw = _recvThroughput.find(_proxyFD);
		if (findRecvBw != _recvThroughput.end()) {
			json_object_set_new(info, "Inbound Throughput (bps) ", json_real(findRecvBw->second));
		} else {
			json_object_set_new(info, "Inbound Throughput (bps) ", json_real(0));
		}
		
		map<int, double>::iterator findSendBw = _sendThroughput.find(_proxyFD);
		if (findSendBw != _sendThroughput.end()) {
			json_object_set_new(info, "Outbound Throughput (bps) ", json_real(findSendBw->second));
		} else {
			json_object_set_new(info, "Outbound Throughput (bps) ", json_real(0));
		}
		json_array_append_new(primaryObject, info);
		
		json_t *secondaryObject;
		secondaryObject = json_array();
		json_t *sec = json_array();
		for (map<routeTableEntry, int>::iterator it = _routeTable.begin(); it != _routeTable.end(); it++) {
			if ((it->first).publicIP.s_addr != (it->first).privateIP.s_addr) {
				json_t* info = json_object();
				string priIP = inet_ntoa((it->first).privateIP);
				string key = priIP;
				key += ":";
				char port[33];
				snprintf(port, sizeof(port), "%d", (int)(it->first).port);
				key += port;
				
				json_object_set_new(info, "NodeID (IP:port)", json_string(key.c_str()));
				
				map<int, unsigned long>::iterator findRecvBytes = _logRecvBytes.find(it->second);
				if (findRecvBytes != _logRecvBytes.end()) {
					json_object_set_new(info, "BytesReceived", json_integer(findRecvBytes->second));
				} else {
					json_object_set_new(info, "BytesReceived", json_integer(0));
				}
			
				map<int, unsigned long>::iterator findSendBytes = _logSendBytes.find(it->second);
				if (findSendBytes != _logSendBytes.end()) {
					json_object_set_new(info, "BytesSent", json_integer(findSendBytes->second));
				} else {
					json_object_set_new(info, "BytesSent", json_integer(0));
				}
				
				map<int, double>::iterator findRecvBw = _recvThroughput.find(it->second);
				if (findRecvBw != _recvThroughput.end()) {
					json_object_set_new(info, "Inbound Throughput (bps) ", json_real(findRecvBw->second));
				} else {
					json_object_set_new(info, "Inbound Throughput (bps) ", json_real(0));
				}
				
				map<int, double>::iterator findSendBw = _sendThroughput.find(it->second);
				if (findSendBw != _sendThroughput.end()) {
					json_object_set_new(info, "Outbound Throughput (bps) ", json_real(findSendBw->second));
				} else {
					json_object_set_new(info, "Outbound Throughput (bps) ", json_real(0));
				}
			
				json_array_append_new(sec, info);
			}
		}
		json_t* NATgrp = json_object();
		json_object_set_new(NATgrp, "NATIP", json_string(inet_ntoa(_myInfo.publicIP)));
		json_object_set_new(NATgrp, "Nodes", sec);
		json_array_append_new(secondaryObject, NATgrp);
		
		json_t *clientObject;
		clientObject = json_array();
		for (map<string, int>::iterator it = _clientAdvertisments.begin(); it != _clientAdvertisments.end(); it++) {
			string key = it->first;
			string keyInHex = stringToHex(key);
			json_array_append_new(clientObject, json_string(keyInHex.c_str()));
		}
		
		json_t* completeObject = json_object();
		json_object_set_new(completeObject, "My Type", json_string("Secondary"));
		json_object_set_new(completeObject, "My Public IP", json_string(inet_ntoa(_myInfo.publicIP)));
		json_object_set_new(completeObject, "My Private IP", json_string(inet_ntoa(_myInfo.privateIP)));
		json_object_set_new(completeObject, "My GDP Port", json_integer(_myInfo.port));
		json_object_set_new(completeObject, "Primary Nodes", primaryObject);
		json_object_set_new(completeObject, "Secondary Nodes", secondaryObject);
		json_object_set_new(completeObject, "Clients", clientObject);
		char responseHeader[1024];
		char *responseData;
   		int responseLen;
   		
   		responseData = json_dumps(completeObject, JSON_INDENT(3));
   		responseLen = strlen(responseData);
   		snprintf(responseHeader, 1024, "%d", (int)responseLen);
   		json_decref(completeObject);
   		
   		string header = "Content-length: ";
	   	header += responseHeader;
	   	header += "\n";

	   	string finalPacket = "HTTP/1.1 200 OK\n";
		finalPacket += header;
	   	finalPacket +=  "Content-Type: application/json\n\n";
	   	string data(responseData, responseLen);
	   	finalPacket += data;
	   	
	   	int sentPacket = write(fd, finalPacket.c_str(), finalPacket.length());
	   	if (sentPacket < 0) {
	   		perror("Error sending HTTP JSON Packet: ");
	   	}
	}
}

void GDPRouterNat::eraseStats(int fd) {
	_logSendBytes.erase(fd);
	_logRecvBytes.erase(fd);
	_logSendPingBytes.erase(fd);
	_logRecvPingBytes.erase(fd);
	_logSendPingNumber.erase(fd);
	_logRecvPingNumber.erase(fd);
	_logSendAdvBytes.erase(fd);
	_logRecvAdvBytes.erase(fd);
	_logSendAdvNumber.erase(fd);
	_logRecvAdvNumber.erase(fd);
	_logSendFwdBytes.erase(fd);
	_logRecvFwdBytes.erase(fd);
	_logSendFwdNumber.erase(fd);
	_logRecvFwdNumber.erase(fd);
	
	_curRecvBytes.erase(fd);
	_curSendBytes.erase(fd);
	_recvThroughput.erase(fd);
	_sendThroughput.erase(fd);
}


CLICK_ENDDECLS
EXPORT_ELEMENT(GDPRouterNat)
ELEMENT_REQUIRES(userlevel)