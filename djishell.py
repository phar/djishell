import usb.core
import usb.backend.libusb1
import struct
import cmd
import json
import threading, queue
from threading import Event
import os
import readline



PKT_CLASS_DJI = 0x55
PKT_CLASS_TRANSFER = 0x21



class DJIHelper():
	def __init__(self):
		self.vid = 0x2ca3
		self.pid = 0x0022
		self.events = {}
		self.dissector = {}
		self.pkt_filter = []
		self.pkt_types = {}
		self.send_endpoint = 0x04
		self.recv_endpoint = 0x85
		self.reload_filter_data()
#		self.responsequeue = queue.Queue()

		self.register_dissector(75, self.dissect_accel_data)


	def register_dissector(self,pkttype, dissectorfunc):
		self.dissector[pkttype] = dissectorfunc

	def dissect_accel_data(self, pkt):
		labels= ["GIMBLE_X","GIMBLE_Y","GIMBLE_Z","GIMBLEUNK","UNK02","UNK03","UNK04","UNK05","UNK06","UNK07","UNK08","UNK09","UNK10","UNK11","UNK12","UNK13",]
		vals = struct.unpack(">3h3i11h",pkt[9:-9])
		return json.dumps(dict(zip(labels,vals)), indent=4, sort_keys=True)

	def register_dji_response(self, pkt):
		extra = {}
		ret = False

		if pkt[0] == PKT_CLASS_DJI:
			(d,crcvalid) = self.validate_packet(pkt)
			if crcvalid:
				pkt = pkt[2:-2]
				if int(pkt[1]) in self.pkt_filter: #silently drop anything filtere
					return (True,pkt,extra)

				if int(pkt[1]) in self.dissector:	#signal to any expected events
					extra = self.dissector[pkt[1]](pkt)
					ret = True
				
				if int(pkt[1]) in self.events:	#signal to any expected events
					self.event[pkt[1]][1] = extra
					self.event[pkt[1]][0].set()
					ret = True

				return (ret,pkt,extra)
		elif pkt[0] == PKT_CLASS_TRANSFER:
			print("File Transfer Class (%d)" %  pkt[0], ' '.join(format(x, '02x') for x in pkt))

			ret = True
		else:
			print("non-handled packet class (%d)" %  pkt[0], ' '.join(format(x, '02x') for x in pkt))
			ret = True
		return (ret,pkt,extra)

#	def subscribe_event(self,event_name):

	def wait_event(self, pkttype, timeout=5):
		if pkttype not in self.events:
			self.events[pkttype] = (Event(),{})
		self.events[pkttype][0].clear()
		return (self.events[pkttype][0].wait(timeout), self.events[pkttype][1])

	def reload_filter_data(self):
		self.load_types()
		self.load_filter()

	def load_filter(self):
#		try:
			f = open('pkt_filter.json')
			try:
				self.pkt_filter = json.load(f)
			except json.decoder.JSONDecodeError:
				print("bad pkt_filter.json file")
				self.pkt_filter = []
			f.close()
#		except:
#			self.pkt_filter = {}
				
	def load_types(self):
#		try:
			f = open('pkt_types.json')
			try:
				self.pkt_types = json.load(f)
			except json.decoder.JSONDecodeError:
				print("bad pkt_types.json file")
				self.pkt_types =  {}
			f.close()
#		except:
#			self.pkt_types = {}

	def validate_packet(self,pkt):
		v = struct.unpack("<H",pkt[-2:])[0]
		crc = self.get_pkt_crc(pkt[:-2])
		return (pkt[2:-2],v == crc)


	def prepare_to_send(self,pkt):
		buff = []
		buff.append(PKT_CLASS_DJI)
		buff.append(len(pkt) + 4)
		for i in range(len(pkt)):
			buff.append(pkt[i])

		crc = struct.pack("<H", self.get_pkt_crc(buff))
		buff.append(crc[0])
		buff.append(crc[1])
		return bytes(buff)
		

	def get_pkt_crc(self, pkt):
		seed = 0x3692
		crc_table = [
			0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
			0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
			0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
			0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
			0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
			0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
			0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
			0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
			0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
			0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
			0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
			0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
			0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
			0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
			0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
			0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
			0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
			0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
			0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
			0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
			0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
			0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
			0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
			0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
			0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
			0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
			0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
			0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
			0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
			0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
			0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
			0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78,
	]
		j = seed;
		for i in range(0,len(pkt)):
			j = (j >> 8) ^ crc_table[(j ^ pkt[i]) & 0xFF];

		return j



histfile = os.path.expanduser('dji_cmd_history')
histfile_size = 1000

class DJIShell(cmd.Cmd):
	intro = 'dji shell test.\n'
	prompt = '(dji) '
	file = None
	dji = DJIHelper()
	connected = False
	testval = 1
	dumptype = 0

	def do_dumptype(self,arg):
		self.dumptype = int(arg)
	
	def precmd(self, line):
		line = line.lower()
		if self.file and 'playback' not in line:
			print(line, file=self.file)
		return line
		
	def close(self):
		if self.file:
			self.file.close()
			self.file = None
			
	def do_reload(self,arg):
		"""reload filter files"""
		self.dji.reload_filter_data()

	def do_connect_uart(self,arg):
		"""connect to uart device"""
		#this is a note for a fixme because the controller does expose this protocol on a CDC UART interface
		#and this tool might help in probing that protocol as well

	def do_connect_usb(self,arg):
		"""connect to raw usb device"""
		if self.connected == False:
			self.usbdev = usb.core.find(idVendor=self.dji.vid, idProduct=self.dji.pid)
			if self.usbdev is None:
				print("unable to connect to device")
				return
			usb.util.claim_interface(self.usbdev, 1)
			self.cfg = self.usbdev.get_active_configuration()
			self.connected = True
			
			self.listenthread = threading.Thread(target=self.client_thread, args=(1,))
			self.listenthread.start()
		print("connected.")
		
	def do_send(self,arg):
		if not self.connected:
			print("not connected to device")
			return
		try:
			buf = self.dji.prepare_to_send(bytes.fromhex(arg))
			print("sent:",buf)
			self.usbdev.write(self.dji.send_endpoint,buf)
		except ValueError:
			print("bad input packet")

	def do_send_file(self,arg):
		if not self.connected:
			print("not connected to device")
			return
		argval =  eval("\"" + arg + "\"")
		pkt = b"\x04\xB0\x2A\x4F\x10\x0D\x40\x00\x2A\x01\xC0\xB1\x6E\x0B"
		pkt += bytes([len(argval.strip())])
		pkt += bytes(str(argval), encoding='utf8') #wm260_1502_v10.21.40.13_20220321.pro.fw.sig
		pkt += b"\x00\x00\x01\x01"
		self.device_write(pkt)

		pkt = b"\x0D\x04\x33\x2A\x03\x11\x0D\x40\x00\x0E"


	def do_request_file2(self, arg):
		if not self.connected:
			print("not connected to device")
			return
		arg =  eval("\"" + arg + "\"")
		pkt = b"\x04\x63\x0A\x1D\x64\x75\x40\x00\x2A\x08"
		pkt += bytes([len(arg.strip())])
		pkt += bytes(str(arg), encoding='utf8') #[or(x) for x in list(arg.strip())]
		pkt += b"\x09\x01\x04"
		self.device_write(pkt)
		
		pkt = b"\x04\x6D\x0A\x1D\xEB\x1A\x80\x00\x2A\x00\xD0\x03\xD0\x07\x01\x01"
		self.device_write(pkt)

		
	def do_get_device_serial(self,arg):
		pkt = b"\x04\x33\x2A\x03\xEF\x69\x40\x00\x01"
		self.device_write(pkt)

	def do_get_device_version(self,arg):
		pkt = b"\x04\x33\x2A\x1f\xEF\x69\x40\x00\x01"
		self.device_write(pkt)

	def do_get_device_data(self,arg):
		for i in range(0xff):
			pkt = b"\x04\x33\x2A"
			pkt += bytes([i])
			pkt += b"\xEF\x69\x40\x00\x01"
			self.device_write(pkt)


#		04 33 2A 1F EE 69 40 00 01
#		04 33 2A 03 EF 69 40 00 01


	def device_write(self,buffer):
		buf = self.dji.prepare_to_send(buffer)
		print("sent:",buf)
		self.usbdev.write(self.dji.send_endpoint,buf)

	def device_write_raw(self,buffer):
		print("sent:",buffer)
		self.usbdev.write(self.dji.send_endpoint,buffer)

	def do_request_file(self, arg):
		if not self.connected:
			print("not connected to device")
			return
		arg =  eval("\"" + arg + "\"")
		pkt = b"\x04\x9C\x0A\x1D\xF2\x72\x40\x00\x2A\x08"
		pkt += bytes([len(arg.strip())])
		pkt += bytes(str(arg), encoding='utf8') #[or(x) for x in list(arg.strip())]
		pkt += b"\x09\x01\x00"
#		print(pkt)
#		try:
		buf = self.dji.prepare_to_send(pkt)
		print("sent:",buf)
		self.usbdev.write(self.dji.send_endpoint,buf)
#		except ValueError:
#			print("bad input packet")

	
			
	def client_thread(self,arg):
		while(1):
			try:
				pkt = bytes(self.usbdev.read(self.dji.recv_endpoint,1024))
				(handled, trimmedresponse,extra) = self.dji.register_dji_response(pkt)
				
				if not handled:
					if self.dumptype == 0:
						dd = ' '.join(format(x, '02x') for x in trimmedresponse)
					elif  self.dumptype == 1:
						dd = trimmedresponse

					if(str(int(trimmedresponse[1])) in  self.dji.pkt_types):
						print(self.dji.pkt_types[str(int(trimmedresponse[1]))],int(trimmedresponse[1]), "\t",dd)
					else:
						print("UNKNOWN_TYPE",int(trimmedresponse[1]), "\t",dd)


			except usb.core.USBError:
				print("USB IO Error")
				time.sleep(1)
				self.connected = False
				

	def preloop(self):
		if readline and os.path.exists(histfile):
			readline.read_history_file(histfile)

	def postloop(self):
		if readline:
			readline.set_history_length(histfile_size)
			readline.write_history_file(histfile)



def parse(arg):
	a = list(arg)
	l = []
	t = ""
	inquote = 0
	for i in a:
		if i in ["\"","'"]:
			inquote ^= 1
			if len(t):
				l.append(t.strip())
				t = ""
			
		else:
			if i == " " and inquote == 0:
				if len(t):
					l.append(t.strip())
					t = ""
				
			else:
				t += i
				
				
	if len(t):
		l.append(t.strip())
	return l
			
if __name__ == '__main__':
    DJIShell().cmdloop()
