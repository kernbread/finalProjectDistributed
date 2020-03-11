bin_PROGRAMS = tcpserver tcpclient my_adduser

tcpserver_SOURCES = server_main.cpp PasswdMgr.cpp FileDesc.cpp Server.cpp TCPServer.cpp TCPConn.cpp strfuncts.cpp Logger.cpp
tcpserver_LDFLAGS = -largon2 -pthread

tcpclient_SOURCES = client_main.cpp Client.cpp FileDesc.cpp TCPClient.cpp strfuncts.cpp Logger.cpp
tcpclient_LDFLAGS = -pthread

my_adduser_SOURCES = adduser_main.cpp PasswdMgr.cpp FileDesc.cpp strfuncts.cpp Logger.cpp
my_adduser_LDFLAGS = -largon2
