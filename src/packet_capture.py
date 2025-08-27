import queue
import threading
import datetime
import time
from scapy.all import sniff, IP, TCP, UDP

class PacketCapture:
	def __init__(self, max_queue_size = 1000):
		self.packet_queue = queue.Queue(maxsize=max_queue_size)
		self.is_capturing = False
		self.capture_thread = None


	##################################
	def start_capture(self):
		if self.is_capturing:
			print("Already caputing1")
			return
			
		self.is_capturing = True
		self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
		self.capture_thread.start()
		print("packet capture started!")


	##################################
	def stop_capturing(self):
		self.is_capturing = False
		
		if self.capture_thread:
			self.capture_thread.join(timeout=2)
		

	##################################
	def get_packet(self, timeout = 1):
		try:
			return self.packet_queue.get(timeout=timeout)
		except queue.Empty:
			return None
	
	##########################
	def get_all_packets(self):
		packets = []
		
		while not self.packet_queue.empty():
			try:
				packets.append(self.packet_queue.get_nowait())
			except queue.Empty:
				break
		
		return packets

	##################################
	def _capture_loop(self):
		def packet_callback(packet):
			if not self.is_capturing:
				return
			
			packet_info = self._process_packet(packet)

			if packet_info:
				try:
					self.packet_queue.put_nowait(packet_info)
				except queue.Full:
					try:
						self.packet_queue.get_nowait()
						self.packet_queue.put_nowait(packet_info)
					except queue.Empty:
						pass
		
		try:
			sniff(prn = packet_callback, store = False, stop_filter = lambda x: not self.is_capturing)
		except Exception as e:
			print(f"Captured Error : {e}")
			self.is_capturing = False
		
	def _process_packet(self, packet):
		if not IP in packet:
			return None
		
		packet_info = {
			'timestamp' : datetime.datetime.now(),
			'src_ip' : packet[IP].src,
			"dst_ip" : packet[IP].dst,
			'protocol' : self._get_protocol_name(packet[IP].proto),
			'size' : len(packet),
			'src_port' : None,
			'dst_port' : None,
			"traffic_type" : 'other'
		}
		
		if TCP in packet:
			packet_info['src_port'] = packet[TCP].sport
			packet_info['dst_port'] = packet[TCP].dport
			packet_info['traffic_type'] = self._classify_traffic(packet[TCP].dport)
		elif UDP in packet:
			packet_info['src_port'] = packet[UDP].sport
			packet_info['dst_port'] = packet[UDP].dport
			packet_info['traffic_type'] = self._classify_traffic(packet[UDP].dport)
		
		return packet_info
	
	def _get_protocol_name(self, proto_num):
		protocols = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
		return protocols.get(proto_num, f'Protocol-{proto_num}')

	def _classify_traffic(self, port):
		if port in [80, 8080]:
			return 'HTTP'
		elif port in [443, 8443]:
			return 'HTTPS' 
		elif port == 53:
			return 'DNS'
		elif port in [25, 587, 465]:
			return 'Email'
		elif port in [21, 22]:
			return 'File Transfer'
		else:
			return 'Other'
		
	def get_queue_size(self):
		return self.packet_queue.qsize()
	
	def is_running(self):
		return self.is_capturing
	

if __name__ == "__main__":
	print("Testing PacketCapture class...") 
	
	capture = PacketCapture()
	capture.stop_capturing()

	print("capturing packet for 10 seconds .... ")
	time.sleep(10)
	
	packets = capture.get_all_packets()
	print(f"Captured {len(packets)} packets")
	
	for packet in packets:
		print(f"{packet['src_ip']} --> {packet['dst_ip']}  [{packet['protocol']}]  {packet['traffic_type']}")

	
	capture.start_capture()
	print("test Completed!")
    
		
	

		
		
	
	