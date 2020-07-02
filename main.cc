/*
 *
 *
 *
 *
 *
 */

#include <stdint.h>
#include <stdlib.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include <atomic>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

inline std::string ToString(const double bytes) {
	char unit[] = {' ', 'K', 'M', 'G', 'T'};
	int idx = 0;
	double b = bytes;
	while (1 < (b / 1024.0f)) {
		idx++;
		b = b / 1024.0f;
	}

	std::stringstream ss;
	ss << std::fixed << std::setprecision(2) << b << unit[idx];
	return ss.str();
}

static bool krunning = true;
static const size_t kMaxMtuSize = 1500;
struct PktStat {
	PktStat()
		: pkt_count(0),
		pkt_bytes(0) { }
	
	std::atomic<uint32_t> pkt_count;
	std::atomic<uint64_t> pkt_bytes;
};

void Recv(const int fd, PktStat* stat) {
	uint8_t buffer[kMaxMtuSize];
	
	while (krunning) {
		struct sockaddr_in from;
		socklen_t sock_len = sizeof(from);
		int len = ::recvfrom(fd, buffer, kMaxMtuSize, 0, (struct sockaddr*)&from, &sock_len);
		if (0 >= len)
			return;

		stat->pkt_count++;
		stat->pkt_bytes += len;	
	}
}

void RecvMmsg(const int fd, PktStat* stat) {
	const size_t MAX_MSG = 128;
	struct mmsghdr mmsg[MAX_MSG];
	struct iovec iovecs[MAX_MSG];

	std::unique_ptr<uint8_t[]> buffer(new uint8_t[MAX_MSG * kMaxMtuSize]);
	for (size_t i = 0; i < MAX_MSG; i++) {
		iovecs[i].iov_base = buffer.get() + kMaxMtuSize * i;
		iovecs[i].iov_len  = kMaxMtuSize;
		mmsg[i].msg_hdr.msg_iov	= &iovecs[i];
		mmsg[i].msg_hdr.msg_iovlen = 1;
	}
	
	while (krunning) {
		int r = ::recvmmsg(fd, mmsg, MAX_MSG, MSG_WAITFORONE, nullptr);
		if (0 >= r)
			return;
		
		int bytes = 0;
		for (int i = 0; i < r; i++) {
			bytes += mmsg[i].msg_len;
			mmsg[i].msg_hdr.msg_flags = 0;
			mmsg[i].msg_len = 0;
		}
		stat->pkt_count += r;
		stat->pkt_bytes += bytes;
	}
}

void Stat(PktStat* stat) {
	uint32_t last_count = 0;
	uint64_t last_bytes = 0;
	while (krunning) {
		std::this_thread::sleep_for(std::chrono::milliseconds(1000));
		uint32_t pkt_count = stat->pkt_count;
		uint64_t pkt_bytes = stat->pkt_bytes;
		double delta_bytes = pkt_bytes - last_bytes;
		std::cerr << "statitics count [" << pkt_count << "] bytes [" << ToString(pkt_bytes)
  				  << "B] pps is [" << ToString(pkt_count - last_count) << "pps"
				  << "] rate is [" << ToString(delta_bytes * 8) << "bps]" << std::endl;

		last_count = pkt_count;
		last_bytes = pkt_bytes;
	}	
}

int Listen(const uint16_t port) {
	int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
	if (0 > fd) {
		std::cerr << "socket init failed" << std::endl;
		return -1;
	}

	int rcv_buff = 0;
	socklen_t opt_len = sizeof(rcv_buff);
	::getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv_buff, &opt_len);
	std::cerr << "socket [" << fd << "] receive buffer is [" << ToString(rcv_buff) << "]iB" << std::endl;
	
	struct sockaddr_in local;
	local.sin_family = AF_INET;
	local.sin_addr.s_addr = inet_addr("0.0.0.0");
	local.sin_port = htons(port);	
	if (::bind(fd, (struct sockaddr*)&local, sizeof(local))) {
		std::cerr << "socket bind failed" << std::endl;
		close(fd);
		return -1;
	}

	return fd;
}

bool initsignal() {
    struct sigaction sig;

    sig.sa_handler = [](int signal) {
		krunning = false;
	};
	
    sigemptyset(&sig.sa_mask);
    sig.sa_flags = 0;
    sigaction(SIGINT, &sig, NULL);
    sigaction(SIGQUIT, &sig, NULL);
    sigaction(SIGABRT, &sig, NULL);
    sigaction(SIGTERM, &sig, NULL);
	sigaction(SIGHUP, &sig, NULL);	
    return true;
}

int main(int argc, char* argv[]) {
	int ch = -1;
	uint16_t port = 0;
	bool recvmmsg = false;
	while ((ch = getopt(argc, argv, "p:r")) != -1) {
		if (ch == 'p')
			port = std::atoi(optarg);
		if (ch == 'r')
			recvmmsg = true;
	}

	initsignal();
	
	int fd = Listen(port);
	if (0 > fd) {
		std::cerr << "listen in port [" << port << "] failed" << std::endl;
	}
	
	std::cerr << "server listen in port [" << port << "]" << std::endl;

	std::unique_ptr<struct PktStat> stat(new PktStat());
	std::thread worker(Stat, stat.get());
	worker.detach();

	recvmmsg ? RecvMmsg(fd, stat.get()) : Recv(fd, stat.get());
	close(fd);
	return 0;
}
