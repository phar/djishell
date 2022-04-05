import usb.core
import usb.backend.libusb1
import struct
import cmd
import json
import threading, queue
from threading import Event
import os
import readline
import time
import logging
import serial


PKT_CLASS_DJI = 0x55
PKT_CLASS_TRANSFER = 0x21



class DJIHelper():
	def __init__(self, logfile="dji_log.log"):
		self.vid = 0x2ca3
		self.pid = 0x0022
		self.events = {}
		self.dissector = {}
		self.pkt_filter = []
		self.pkt_types = {}
		self.send_endpoint = 0x04
		self.recv_endpoint = 0x85

		self.logger = logging.getLogger('djishell')
		
		self.logger.setLevel(logging.DEBUG)

		self.ser = None
		self.serpath = None
		self.serrbaud = None
		self.logfile = logfile

		self.c_handler = logging.StreamHandler()
		self.f_handler = logging.FileHandler(self.logfile)
		self.c_handler.setLevel(logging.INFO)
		self.f_handler.setLevel(logging.DEBUG)

		# Create formatters and add it to handlers
		c_format = logging.Formatter('%(levelname)s - %(message)s')
		f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		self.c_handler.setFormatter(c_format)
		self.f_handler.setFormatter(f_format)

		# Add handlers to the logger
		self.logger.addHandler(self.c_handler)
		self.logger.addHandler(self.f_handler)

		self.connected = False
		self.device_read = None
		self.device_write = None
		self.reload_filter_data()
		self.dumptype = 0
		

		

	def set_debug_level(self, level):
		self.c_handler.setLevel(level)
	
	
	def connect_uart(self, uart_path="/dev/tty.usbmodem3QDSJ2T0040QRL5", baudrate=115200):
		try:
			self.serpath = uart_path
			self.serrbaud = 115200 #this doesnt matter for dji devices but feels weird without a baud
			self.ser = serial.Serial(port=self.serpath,baudrate=self.serrbaud)
			self.connected = True
			self.device_read = self.uart_read_packet
			self.device_write = self.uart_write_packet
			self.listenthread = threading.Thread(target=self.listener_thread, args=(1,))
			self.listenthread.start()
			self.logger.info("connected")
		except serial.serialutil.SerialException:
			self.logger.info("unable to connect to device")


	def uart_write_packet(self, pkt):
		if self.connected:
			buf = self.prepare_to_send(pkt)
			self.ser.write(buf)
		
	def uart_read_packet(self):
		buffer = []
		crcok = False
		pa = ord(self.ser.read())
		while pa != 0x55:
			pa = ser.read()
		buffer.append(pa)

		blen = ord(self.ser.read()) #fixme, this is probably not right for 0x21 packets.. but im not sure they exist on uart streams?
		buffer.append(blen)
		for i in range(blen - 2): #minus the bytes already read
			buffer.append(ord(self.ser.read()))
		buffer = bytes(buffer)
		return (buffer)

	
	def connect_usb(self, vid=0x2ca3,pid=0x0022):
		if self.connected == False:
			self.vid = vid
			self.pid = pid
			self.usbdev = usb.core.find(idVendor=self.vid, idProduct=self.pid)
			if self.usbdev is None:
				self.logger.info("unable to connect to device")
				return
			usb.util.claim_interface(self.usbdev, 1)
			self.cfg = self.usbdev.get_active_configuration()
			self.connected = True
			self.device_read = self.usb_read_packet
			self.device_write = self.usb_write_packet
			self.listenthread = threading.Thread(target=self.listener_thread, args=(1,))
			self.listenthread.start()
			self.logger.info("connected.")
		else:
			self.logger.info("already connected, disconnect first")


	def listener_thread(self,arg):
		while(self.connected):
				pkt = self.device_read()
				if pkt != None:
					(handled, trimmedresponse,extra) = self.register_dji_response(pkt)
					
					if not handled:
						if self.dumptype == 0:
							dd = ' '.join(format(x, '02x') for x in trimmedresponse)
						elif  self.dumptype == 1:
							dd = str(trimmedresponse)

						if(str(int(trimmedresponse[1])) in  self.pkt_types):
							self.logger.debug(self.pkt_types[str(int(trimmedresponse[1]))],int(trimmedresponse[1])+ "\t"+dd)
						else:
							self.logger.debug("UNKNOWN_TYPE "+str(trimmedresponse[1])+ "\t"+dd)
				else:
					self.logger.error("failed to read from device")
				
				
	def usb_write_packet(self,buffer):
		if self.connected:
			buf = self.prepare_to_send(buffer)
			try:
				self.usbdev.write(self.send_endpoint,buf)
				self.logger.debug("sent: " + str(buf))
				return True
			except usb.core.USBError:
				self.logger.error("device disconnected:")
				self.device_read = None
				self.device_write = None
				self.connected = False
		else:
			self.logger.error("not connected: ")
		return False


	def usb_read_packet(self):
		if self.connected:
			try:
				pkt = bytes(self.usbdev.read(self.recv_endpoint,4096))
				self.logger.debug("read: " + str(pkt))
				return pkt
			except usb.core.USBError:
				self.logger.error("device disconnected:")
				self.device_read = None
				self.device_write = None
				self.connected = False
				return None
		else:
			self.logger.error("not connected: ")
		return None

	def dump(self,dumpdata):
		self.logger.info(self.dump_formatd(dumpdata))

	def dump_format(self, dumpdata):
		if self.dumptype == 0:
			return ' '.join(format(x, '02x') for x in dumpdata)
		elif  self.dumptype == 1:
			return dumpdata

	def register_dissector(self,pkttype, dissectorfunc):
		self.dissector[pkttype] = dissectorfunc

	def dissect_accel_data(self, pkt):
		labels= ["GIMBLE_X","GIMBLE_Y","GIMBLE_Z","GIMBLEUNK","UNK02","UNK03","UNK04","UNK05","UNK06","UNK07","UNK08","UNK09","UNK10","UNK11","UNK12","UNK13",]
		vals = struct.unpack(">3h3i11h",pkt[9:-9])
		ret = dict(zip(labels,vals))
		self.logger.info("(75) " + json.dumps(ret, indent=4, sort_keys=True))
		return ret


	def dissect_perf_data(self, pkt):
		perfdata = {"GPS_SATS":pkt[45]}
		self.logger.info("perf (152): " + self.dump_format(pkt))
		self.logger.info(json.dumps(perfdata, indent=4, sort_keys=True))
		return perfdata

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
			self.logger.info("File Transfer Class (%d)" %  pkt[0], ' '.join(format(x, '02x') for x in pkt))
			ret = True
		else:
			self.logger.info("non-handled packet class (%d)" %  pkt[0], ' '.join(format(x, '02x') for x in pkt))
			ret = True
		return (ret,pkt,extra)

	def wait_event(self, pkttype, timeout=5):
		if pkttype not in self.events:
			self.events[pkttype] = (Event(),{})
		self.events[pkttype][0].clear()
		return (self.events[pkttype][0].wait(timeout), self.events[pkttype][1])

	def reload_filter_data(self):
		self.load_types()
		self.load_filter()

	def load_filter(self):
		try:
			f = open('pkt_filter.json')
			try:
				self.pkt_filter = json.load(f)
			except json.decoder.JSONDecodeError:
				self.logger.warning("bad pkt_filter.json file")
				self.pkt_filter = []
			f.close()
		except:
			self.logger.warning("cant open pkt_filter.json file")
				
	def load_types(self):
		try:
			f = open('pkt_types.json')
			try:
				self.pkt_types = json.load(f)
			except json.decoder.JSONDecodeError:
				self.logger.warning("bad pkt_types.json file")
				self.pkt_types =  {}
			f.close()
		except:
			self.logger.warning("cant open pkt_types.json file")

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

	dji.register_dissector(75, dji.dissect_accel_data)
	dji.register_dissector(152, dji.dissect_perf_data)


	def do_dumptype(self,arg):
		self.dumptype = int(arg)
#
#	def precmd(self, line):
##		line = line.lower()
#		if self.file and 'playback' not in line:
#			print(line, file=self.file)
#		return line
		
	def close(self):
		if self.file:
			self.file.close()
			self.file = None
			
	def do_reload(self,arg):
		"""reload filter files"""
		self.dji.reload_filter_data()

	def do_connect_uart(self,arg):
		"""connect to uart device"""
		print(arg)
		self.dji.connect_uart(arg)

	def do_connect_usb(self,arg):
		"""connect to raw usb device"""
		self.dji.connect_usb()
#		if self.connected == False:
#			self.usbdev = usb.core.find(idVendor=self.dji.vid, idProduct=self.dji.pid)
#			if self.usbdev is None:
#				print("unable to connect to device")
#				return
#			usb.util.claim_interface(self.usbdev, 1)
#			self.cfg = self.usbdev.get_active_configuration()
#			self.connected = True
#
#			self.listenthread = threading.Thread(target=self.client_thread, args=(1,))
#			self.listenthread.start()
#		print("connected.")
		
	def do_send(self,arg):
		if not self.connected:
			print("not connected to device")
			return
		try:
			self.dji.device_write(bytes.fromhex(arg))
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
		self.dji.device_write(pkt)
	
		time.sleep(.5)
		pkt = b"\x0D\x04\x33\x2A\x03\x11\x0D\x40\x00\x0E"
		self.dji.device_write(pkt)


	def do_request_file_enc(self, arg):
		if not self.connected:
			print("not connected to device")
			return
		arg =  eval("\"" + arg + "\"")
		pkt = b"\x04\x63\x0A\x1D\x64\x75\x40\x00\x2A\x08"
		pkt += bytes([len(arg.strip())])
		pkt += bytes(str(arg), encoding='utf8') #[or(x) for x in list(arg.strip())]
		pkt += b"\x09\x01\x04"
		self.dji.device_write(pkt)
		
		pkt = b"\x04\x6D\x0A\x1D\xEB\x1A\x80\x00\x2A\x00\xD0\x03\xD0\x07\x01\x01"
		self.dji.device_write(pkt)

		
	def do_get_device_serial(self,arg):
		pkt = b"\x04\x33\x2A\x03\xEF\x69\x40\x00\x01"
		self.dji.device_write(pkt)

	def do_get_device_version(self,arg):
		pkt = b"\x04\x33\x2A\x1f\xEF\x69\x40\x00\x01"
		self.dji.device_write(pkt)

	def do_get_device_data(self,arg):
		for i in range(0xff):
			pkt = b"\x04\x33\x2A"
			pkt += bytes([i])
			pkt += b"\xEF\x69\x40\x00\x01"
			self.dji.device_write(pkt)


	def do_add_filter(self, arg):
		try:
			self.dji.pkt_filter.append(int(arg))
			print("added filter for type", int(arg))
		except:
			pass
			
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
		self.dji.device_write(pkt)
#		except ValueError:
#			print("bad input packet")

	
			

if __name__ == '__main__':
    DJIShell().cmdloop()
