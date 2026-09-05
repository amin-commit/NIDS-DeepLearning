from nfstream import NFStreamer
import requests

flask_url = '' #ENTER YOUR FLASK URL HERE
print(f'capture sending to {flask_url}')

streamer = NFStreamer(
    source='', #CHANGE SOURCE MEDIUM HERE
    statistical_analysis=True, #needed to get all features out.
    idle_timeout=2, #CAN BE CHANGED
    active_timeout=10 #CAN BE CHANGED
)

for flow in streamer: #iterates over streamers' flows
     #print(flow) testing flow to remove extra features
     #break
    dst = str(getattr(flow, 'dst_ip', ''))
    if dst.startswith('192.') or dst.startswith('224.') or dst.startswith('ff') or dst.startswith('192.') or dst.endswith('.255'): # BLOCK LIST IPS REMOVED - ADD YOUR OWN RULE TO BLOCK IPS HERE.
            continue
    dur_ms = getattr(flow, 'bidirectional_duration_ms', 0) #attributes
    dur_ms = dur_ms if dur_ms > 0 else 1
    dur_us = float(dur_ms) * 1000.0 #convert to microseconds
    dur_s = float(dur_ms) / 1000.0 #into seconds
    packets = getattr(flow, 'bidirectional_packets', 0) 
    packets = packets if packets > 0 else 1
    src_packets = getattr(flow, 'src2dst_packets', 0) or 1
    dst_packets = getattr(flow, 'dst2src_packets', 0) or 1
    flow_bytes = getattr(flow, 'bidirectional_bytes', 0)
    src_bytes = getattr(flow, 'src2dst_bytes', 0)
    dst_bytes = getattr(flow, 'dst2src_bytes', 0)
    flow_bytes_per_s   = float(flow_bytes) / dur_s
    flow_packets_per_s = float(getattr(flow, 'bidirectional_packets', 0)) / dur_s
    fwd_packets_per_s  = float(getattr(flow, 'src2dst_packets', 0)) / dur_s
    bwd_packets_per_s  = float(getattr(flow, 'dst2src_packets', 0)) / dur_s
features = {
        'Flow Duration': dur_us,
        'Fwd Packet Length Max': float(getattr(flow, 'src2dst_max_ps', 0)),
        'Fwd Packet Length Mean': float(getattr(flow, 'src2dst_mean_ps', 0)),
        'Fwd Packet Length Std': float(getattr(flow, 'src2dst_stddev_ps', 0)),
        'Bwd Packet Length Max': float(getattr(flow, 'dst2src_max_ps', 0)),
        'Bwd Packet Length Mean': float(getattr(flow, 'dst2src_mean_ps', 0)),
        'Bwd Packet Length Std': float(getattr(flow, 'dst2src_stddev_ps', 0)),
        'Flow IAT Mean':float(getattr(flow, 'bidirectional_mean_piat_ms', 0)) * 1000, 
        'Flow IAT Std': float(getattr(flow, 'bidirectional_stddev_piat_ms', 0)) * 1000,
        'Flow IAT Max': float(getattr(flow, 'bidirectional_max_piat_ms', 0)) * 1000,
        'Flow IAT Min': float(getattr(flow, 'bidirectional_min_piat_ms', 0)) * 1000,
        'Fwd IAT Mean': float(getattr(flow, 'src2dst_mean_piat_ms', 0)) * 1000,
        'Fwd IAT Std': float(getattr(flow, 'src2dst_stddev_piat_ms', 0)) * 1000,
        'Fwd IAT Max': float(getattr(flow, 'src2dst_max_piat_ms', 0)) * 1000,
        'Fwd IAT Min': float(getattr(flow, 'src2dst_min_piat_ms', 0)) * 1000,
        'Bwd IAT Mean': float(getattr(flow, 'dst2src_mean_piat_ms', 0)) * 1000,
        'Bwd IAT Std': float(getattr(flow, 'dst2src_stddev_piat_ms', 0)) * 1000,
        'Bwd IAT Max': float(getattr(flow, 'dst2src_max_piat_ms', 0)) * 1000,
        'Bwd IAT Min': float(getattr(flow, 'dst2src_min_piat_ms', 0)) * 1000,
        'Fwd PSH Flags': float(getattr(flow, 'src2dst_psh_packets', 0)),
'SYN Flag Count':float(getattr(flow, 'bidirectional_syn_packets', 0)),
        'URG Flag Count':float(getattr(flow, 'bidirectional_urg_packets', 0)),
        'Packet Length Max': float(getattr(flow, 'bidirectional_max_ps', 0)),
        'Packet Length Mean':float(getattr(flow, 'bidirectional_mean_ps', 0)),
        'Packet Length Std':float(getattr(flow, 'bidirectional_stddev_ps', 0)),
        'Flow Bytes/s': flow_bytes_per_s,
        'Flow Packets/s': flow_packets_per_s,
        'Fwd Packets/s': fwd_packets_per_s,
        'Bwd Packets/s': bwd_packets_per_s,
        'Packet Length Variance': float(getattr(flow, 'bidirectional_stddev_ps', 0)) ** 2,
        'Avg Packet Size': float(flow_bytes) / float(packets),
        'Avg Fwd Segment Size': float(src_bytes) / float(src_packets),
        'Avg Bwd Segment Size': float(dst_bytes) / float(dst_packets),
        'src_ip': getattr(flow, 'src_ip', 'N/A'),
        'dst_ip': getattr(flow, 'dst_ip', 'N/A'),
    }
#checking for errors
print(f"features sent - {features}")
try:
        resp = requests.post(flask_url, json=features, timeout=3) #attempts to post with 3s request timeout
        print(f'sent - {features["src_ip"]} -> {features["dst_ip"]} | status: {resp.status_code}') #shows src and destination ip and status code on success
except Exception as e:
        print(f'error - {e}')