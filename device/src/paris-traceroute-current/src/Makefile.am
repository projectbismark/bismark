@SET_MAKE@

bin_PROGRAMS=paris-traceroute

paris_traceroute_SOURCES = common.cc Util.cc Time.cc Options.cc Output.cc \
	IP4Header.cc UDPHeader.cc TCPHeader.cc ICMPHeader.cc MPLSHeader.cc \
	Datagram.cc Probe.cc UDPProbe.cc TCPProbe.cc ICMPProbe.cc \
	Reply.cc ICMPReply.cc TCPReply.cc Server.cc \
	TimedProbe.cc NULLTracert.cc HopByHopTracert.cc PackByPackTracert.cc \
	ScoutTracert.cc ConcurrentTracert.cc paris-traceroute.cc TracertImpl.cc \
	MtTracert.cc ExhaustiveTracert.cc ExhaustiveOldTracert.cc Bandwidth.cc

#tupleroute_LDADD=$(top_builddir)/libnetlink/libnetlink.a

#tupleroute_DEPENDENCIES=$(top_builddir)/libnetlink/libnetlink.la

#Test_SOURCES = common.cc Util.cc Datagram.cc Server.cc Options.cc \
#	Reply.cc ICMPReply.cc TCPReply.cc \
#	IP4Header.cc UDPHeader.cc TCPHeader.cc ICMPHeader.cc \
#	NULLTracert.cc Test.cc

