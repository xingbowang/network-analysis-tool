#!/usr/bin/python3

#step for generating input file from a pcap file
#tshark -r packets_dump.pcap > /tmp/x1
#grep PSH /tmp/x1 > /tmp/psh
#cat /tmp/psh | sed "s/  / /g" | sed "s/  / /g"| sed "s/  / /g"| sed "s/  / /g"| sed "s/  / /g"| sed "s/  / /g"| sed "s/  / /g"| sed "s/  / /g"| sed "s/  / /g"| sed "s/  / /g" | sed "s/^ //g" > /tmp/psh_white
#cat /tmp/psh_white | cut -f2,3,5,8,10 -d' ' > ./input

# TODO move this into command line argument
server_ip = "100.82.92.46"
server_port = "6379"
input_file = "input"

client_request_sent_timestamp = {}
server_side_latency_stats = []

# read file line by line
# Example:
# timestamp source-ip dest-ip src-port dest-port
# 2.490903 100.85.131.232 100.82.92.46 56986 6379
# 2.490950 100.85.131.232 100.82.92.46 19754 6379

# track the packets belongs to request/response pair.
paired_lines_set = set()

with open(input_file) as f:
    for line in f:
        line = line.strip()

        timestamp, src_ip, dest_ip, src_port, dest_port = line.split(" ")
        timestamp = float(timestamp)
        if src_port == server_port:
            # response
            # track response sent time
            client = dest_ip + dest_port
            if client in client_request_sent_timestamp:
                # Found response for the request, track it
                request_line = client_request_sent_timestamp[client][1]
                paired_lines_set.add(request_line)
                paired_lines_set.add(line)
                # Update latency result
                request_timestamp = client_request_sent_timestamp[client][0]
                server_side_latency = timestamp - request_timestamp
                server_side_latency_stats.append(server_side_latency)
                del client_request_sent_timestamp[client]
        else:
            # request
            client = src_ip + src_port
            # track request received time
            client_request_sent_timestamp[client] = [timestamp, line]

data_points_count = len(server_side_latency_stats)
print("stats data point count {}".format(data_points_count))
server_side_latency_stats.sort()
print("P50 {:10.4f} ms, P90 {:10.4f} ms, P99 {:10.4f} ms, P99.9 {:10.4f} ms, P100 {:10.4f} ms".format(
    server_side_latency_stats[int(data_points_count * 50 / 100)] * 1000,
    server_side_latency_stats[int(data_points_count * 90 / 100)] * 1000,
    server_side_latency_stats[int(data_points_count * 99 / 100)] * 1000,
    server_side_latency_stats[int(data_points_count * 999/1000)] * 1000,
    server_side_latency_stats[-1] * 1000))

# Go through the file again and filter out the packet that does not belong to any request/response pair
paired_lines = []
with open(input_file) as f:
    for line in f:
        line = line.strip()
        if line in paired_lines_set:
            paired_lines.append(line)


# Calculate metric for in-flight request count per milliseconds
from collections import OrderedDict

inflightRequests = OrderedDict()
aggregatedDuration = [0.0] * 2000
openRequestCountPerMilliseconds = [0] * 2500
currentTimestampMilliseconds = 0
lastTimestamp = None

for line in paired_lines:
    timestamp, src_ip, dest_ip, src_port, dest_port = line.split(" ")
    timestamp = float(timestamp)

    while currentTimestampMilliseconds < timestamp * 1000:
        openRequestCountPerMilliseconds[currentTimestampMilliseconds] = len(inflightRequests)
        currentTimestampMilliseconds = currentTimestampMilliseconds + 1

    if src_port == server_port:
        # response
        client = dest_ip + dest_port
        inflightRequestCount = len(inflightRequests)
        if inflightRequestCount > 0:
            aggregatedDuration[inflightRequestCount - 1] += timestamp - lastTimestamp
        del inflightRequests[client]

    else:
        # request
        client = src_ip + src_port
        # aggregate number of requests in flight duration
        inflightRequestCount = len(inflightRequests)
        if inflightRequestCount > 0:
            aggregatedDuration[inflightRequestCount - 1] += timestamp - lastTimestamp
            if inflightRequestCount == 1005:
               print(timestamp)
        # track request received time
        inflightRequests[client] = timestamp
    lastTimestamp = timestamp

for i in range(len(aggregatedDuration)):
    # filter out the ones that is <= 10ms
    if aggregatedDuration[i] > 0.01:
        print("{:4} : {:6.3f} ms".format(i + 1, aggregatedDuration[i] * 1000))

# Calculate metric for received and completed request every 10ms seconds.
receivedRequestCountPerTenMilliseconds = [0] * 250
completedRequestCountPerTenMilliseconds = [0] * 250
receivedRequestCount = 0
completedRequestCount = 0
currentTimestampTenMilliseconds = 0

for line in paired_lines:
    timestamp, src_ip, dest_ip, src_port, dest_port = line.split(" ")
    timestamp = float(timestamp)
    currentTimestampTenMilliseconds = int(timestamp * 100)

    if src_port == server_port:
        # response
        completedRequestCountPerTenMilliseconds[currentTimestampTenMilliseconds] = \
            completedRequestCountPerTenMilliseconds[currentTimestampTenMilliseconds] + 1
    else:
        # request
        receivedRequestCountPerTenMilliseconds[currentTimestampTenMilliseconds] = \
            receivedRequestCountPerTenMilliseconds[currentTimestampTenMilliseconds] + 1

# plot the result
import matplotlib.pyplot as plt

milliseconds = []
for i in range(2500):
    milliseconds.append(i)
tenMilliseconds = []
for i in range(250):
    tenMilliseconds.append(i * 10)


plt.plot(milliseconds, openRequestCountPerMilliseconds, 'r',
         tenMilliseconds, receivedRequestCountPerTenMilliseconds, 'b',
         tenMilliseconds, completedRequestCountPerTenMilliseconds, 'g')
plt.ylabel('open requests count per milliseconds')
plt.show()
