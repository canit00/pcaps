# pcaps

### [1] connection list

$ tshark -r a.pcap -q -z conv,tcp


#### [2] TTLs
$ tshark -r a.pcap -T fields -e ip.src -e ip.ttl | sort -u

#### [3] Look for something that could be an issue

$ tshark -r a.pcap -Y "tcp.analysis.retransmission" | wc -l
0
$ tshark -r a.pcap -Y "tcp.analysis.zero_window" | wc -l
0
$ tshark -r a.pcap -Y "tcp.flags.reset == 1" | wc -l
0
$ tshark -r a.pcap -Y "tcp.time_delta > 50" | wc -l

#### [4] large delta times

$ tshark -r a.pcap -Y "tcp.time_delta > 50"  -z proto,colinfo,tcp.time_delta,tcp.time_delta | tr "." " " | awk '{print $(NF-1)}' | sort | uniq -c

#### [5] delta times > 250

$ tshark -r a.pcap -Y "tcp.time_delta > 250"  -z proto,colinfo,tcp.time_delta,tcp.time_delta

#### [6] delta times < 250 and greater than 50

$ tshark -r edclosad160.bcbsfl.com-2019-08-23-09-39-24.pcap00 -Y "tcp.time_delta > 50 && tcp.time_delta < 250"  -z proto,colinfo,tcp.time_delta,tcp.time_delta | tail -20
