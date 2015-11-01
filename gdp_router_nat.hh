#ifndef CLICK_GDPROUTERNAT_HH
#define CLICK_GDPROUTERNAT_HH
#include <click/element.hh>
#include <click/task.hh>
#include <click/notifier.hh>
#include <click/string.hh>
#include <click/hashmap.hh>
#include <vector>
#include <map>
#include <string>
#include <tr1/unordered_map>
CLICK_DECLS

using namespace std;

#define VERSION 0x02
#define FORWARD_CMD 0x00
#define ADVERTISE_CMD 0x01
#define ADVERTISE_WITHDRAW 0x02
#define ROUTE_PROTOCOL 0x03
#define NAK 0xf0

#define READ_BUF_SIZE 16348

#define PING_INTERVAL 120
#define JOIN_TIMEOUT  60

#define GDP_HEADER_SIZE 80

#define LOG 1
#define LOG_DISPLAY_FREQUENCY 10
#define LOG_SAMPLE_RATE 60

enum routePacketType {JOIN = 8, 
					JOIN_ACK, 
					ADD_PRIMARY, 
					ADD_PRIMARY_ACK,
					NEW_PRIMARY,
					WITHDRAW_PRIMARY,
					JOIN_SECONDARY,
					JOIN_SECONDARY_ACK,
					JOIN_SECONDARY_NAK,
					NEW_SECONDARY,
					WITHDRAW_SECONDARY,
					ADD_SECONDARY,
					ADD_SECONDARY_ACK,
					NEW_CLIENT_PRIMARY,
					NEW_CLIENT_SECONDARY,
					WITHDRAW_CLIENT_PRIMARY,
					WITHDRAW_CLIENT_SECONDARY,
					UPDATE_SECONDARY,
					UPDATE_SECONDARY_ACK,
					UPDATE_SECONDARY_NAK,
					COOL,
					PING};

typedef struct routeTableEntry routeTableEntry;
struct routeTableEntry {
	struct in_addr publicIP;
	struct in_addr privateIP;
	uint16_t port;
	bool canBeProxy; // parameter to indicate if the router can serve as proxy to S nodes
	
	routeTableEntry() {
		publicIP.s_addr = 0;
		privateIP.s_addr = 0;
		port = 0;
	}
	
	bool operator<(const routeTableEntry &o)  const {
		if (publicIP.s_addr < o.publicIP.s_addr) {
			return true;
		} else if (publicIP.s_addr > o.publicIP.s_addr) {
			return false;
		} else {
			if (privateIP.s_addr < o.privateIP.s_addr) {
				return true;
			} else if (privateIP.s_addr > o.privateIP.s_addr) {
				return false;
			} else {
				return (port < o.port);
			}
		}
	}
	
	bool operator==(const routeTableEntry &o) const {
        return ((publicIP.s_addr == o.publicIP.s_addr) && (privateIP.s_addr == o.privateIP.s_addr) && (port == o.port));
    }
};

typedef struct routePacket routePacket;
struct routePacket {
	routePacketType type;
	routeTableEntry src;
	routeTableEntry dst;

	int numClientAdvertisments;
	int numSecondaryAdvertisments;
	int numSecondary;
	int numPrimary;
	
	bool isTypeAssigned;
	char typeAssigned;
};

typedef struct advertismentEntry advertismentEntry;
struct advertismentEntry {
	char ID[33];
	routeTableEntry node;
};

class GDPRouterNat : public Element { 
	public:
		GDPRouterNat();
		~GDPRouterNat();
		
		const char *class_name() const	{ return "GDPRouterNat"; }
		const char *port_count() const	{ return "0/0"; }
		const char *processing() const	{ return PUSH; }
		int configure(Vector<String>&, ErrorHandler*);
		
		bool run_task(Task *);
		int initialize(ErrorHandler *errh);
		void selected(int fd, int mask);
		WritablePacket* createGDPPacket(char version, 
										char cmd,
										string dst,
							    		string src,
										int packetDataSize);
		int processPacket(int fd, string& message, int dataLen, int optLen, int sigLen, struct in_addr& newConnPublicIP);
		
		int handleJoinPacket(int recvFD, routePacket* recvPacket, struct in_addr& srcPublicIP);
		
		int handleJoinAckPacket(int recvFD, routePacket* recvPacket);
		
		int handleAddPrimary(int recvFD, routePacket* recvPacket);
		
		int handleAddPrimaryAck(int recvFD, routePacket* recvPacket);
		
		int handleNewPrimary(routePacket* recvPacket);
		
		int handleWithdrawPrimary(routePacket* recvPacket);
		
		int handleJoinSecondary(int recvFD, routePacket* recvPacket);
		
		int handleUpdateSecondary(int recvFD, routePacket* recvPacket);
		
		int handleJoinSecondaryAck(int recvFD, routePacket* recvPacket);
		
		int handleJoinSecondaryNak(int recvFD, routePacket* recvPacket);
		
		int handleNewSecondary(int recvFD, routePacket* recvPacket, string& message);
		
		int handleWithdrawSecondary(routePacket* recvPacket);
		
		int handleAddSecondary(int recvFD, routePacket* recvPacket);
		
		int handleAddAckSecondary(routePacket* recvPacket);
		
		int handleClientAdvertisment(int recvFD, string& message, int dataLen, int optLen, string& packetSrc, int packetCmd);
		
		int handleClientPrimary(routePacket* recvPacket);
		
		int handleClientSecondary(int recvFD, routePacket* recvPacket, string& message);
		
		int handleForwardPacket(int recvfd, string& packetDst, string& packetSrc, string& message , int dataLen, int optLen, int sigLen);
		
		int handleLostPacket(int recvFD, string& message, string& packetSrc, string& packetDst);
		
		int regulatedWrite(int fd, const void *data, int length);
		
		 void run_timer(Timer *timer);
		 
		 void findProxyAndConnect(WritablePacket *sendPacket);
		 
		 vector<int> findPingTime();
		 
		 
		 int handleConnectionFailure(int recvFD);
		 
		 int handleClientFailure(int clientFD);
		 
		 int handleSecondaryFailure(int secFD);
		 
		 int handlePrimaryFailure(int priFD); 
		 
		 void displayLogBytes();
		 
		 void calculateThroughput(int fd, double _curTimeInstant);
		 
		 void eraseStats(int fd);
		 
		 // web interface
		 string stringToHex(string& input);
		 void initialize_webServer();
		 void sendLogBytes(int fd);
		 
	private:
		unsigned char _get_byte(int pos, unsigned int seekPtr, const string& bufferData, const string& readData);
		Timer _pingTimer;
		Timer _connectTimer;
		Timer _joinTimer;
		Timer _logTimer;
		bool nodeJoined;
		Task _task;
		
		// Address and port and type of this gdp router
		routeTableEntry _myInfo;
		char _myType;
		bool _isFirstNode;
		
		// The local conection, I am listening on
		struct sockaddr_in _localServer;
		int _localFD;
		
		// Address and port of Primary gdp router connecting to
		routeTableEntry _bootStrap;
		int _bootStrapFD;
		
		// Information of the proxy if I am an 'S' node
		routeTableEntry _proxy;
		int _proxyFD;
		int _proxyIndex;
		
		//client ID mapping directly connected to me
		map<string, int> _clientAdvertisments;
		
		// secondary node advertisments
		map<string, routeTableEntry> _secondaryAdvertisments;
		
		// primary node advertisments
		map<string, routeTableEntry> _primaryAdvertisments;
		
		// table mapping node info to connection
		map<routeTableEntry, int> _routeTable;
		
		// List of Primary nodes in the network
		// If I am a 'P' node, I will use it to keep track of all my peer 'P' nodes
		// If I am a 'S' node, I will use it as a list for backup proxies i can use
		vector<routeTableEntry> _primaryNodes;
		
		// map of public address to all nodes with the public address connected
		// I am a 'P' node, I will use it to record all 'S' nodes directly connected
		// to me
		map<unsigned long, vector<routeTableEntry> > _publicToPrivate;
		
		// table maintaing a map of connection to type of node
		// 'C' - for client
		// 'P' - Primary
		// 'S' - Secondary
		map<int, char> _type;

		// tables for each connection
		map<int, string> _recvBuffer;
		map<int, string> _tempSendBuffer;
		map<int, bool> _isFDReady;
		
		//log tables maintaining number of bytes received and sent per connection
		map<int, unsigned long> _logSendBytes;
		map<int, unsigned long> _logRecvBytes;
		map<int, unsigned long> _logSendPingBytes;
		map<int, unsigned long> _logRecvPingBytes;
		map<int, unsigned long> _logSendPingNumber;
		map<int, unsigned long> _logRecvPingNumber;
		map<int, unsigned long> _logSendAdvBytes;
		map<int, unsigned long> _logRecvAdvBytes;
		map<int, unsigned long> _logSendAdvNumber;
		map<int, unsigned long> _logRecvAdvNumber;
		map<int, unsigned long> _logSendFwdBytes;
		map<int, unsigned long> _logRecvFwdBytes;
		map<int, unsigned long> _logSendFwdNumber;
		map<int, unsigned long> _logRecvFwdNumber;
		
		map<int, unsigned long> _curRecvBytes;
		map<int, unsigned long> _curSendBytes;
		double _prevTimeInstant;
		map<int, double> _recvThroughput;
		map<int, double> _sendThroughput;
		int _logDisplayCounter;
		
		// receive buffer
		char _readBuffer[READ_BUF_SIZE];
		
		// A string to represent GDPRouter
		string _GDPRouterAddress;
		
		
		//http Web server interface
		uint16_t _webPort; 
		struct sockaddr_in _webServer;
		int _webFD;
		
		//option to print debug output
		int _debug;
};

CLICK_ENDDECLS
#endif