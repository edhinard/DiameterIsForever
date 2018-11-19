#! /usr/bin/env python3
# coding: utf-8

import ctypes
import struct
import ipaddress
import enum

class Application(enum.Enum):
    Base=0
    Cx_Dx=16777216
    Sh=16777217
    Rx=16777236
    S6a_S6d=16777251
    S13=16777252
    SLg=16777255
    S6t=16777345

Diameterclasses = {}
class DiameterMeta(type(ctypes.BigEndianStructure)):
    def __init__(cls, name, bases, dikt):
        command = dikt.get('_command')
        R = dikt.get('_R')
        if command is not None and R is not None:
            Diameterclasses[(command, R)] = cls
        super(DiameterMeta, cls).__init__(name, bases, dikt)

class Diameter(ctypes.BigEndianStructure, metaclass=DiameterMeta):
    _fields_ = (
        ('version', ctypes.c_uint8),
        ('_length', ctypes.c_uint8 * 3),
        ('R', ctypes.c_uint8, 1),
        ('P', ctypes.c_uint8, 1),
        ('E', ctypes.c_uint8, 1),
        ('T', ctypes.c_uint8, 1),
        ('unused', ctypes.c_uint8, 4),
        ('_command_', ctypes.c_uint8 * 3),
        ('_application', ctypes.c_uint32),
        ('hop', ctypes.c_uint32),
        ('end', ctypes.c_uint32),
    )
    @staticmethod
    def from_bytes(buf, offset=0):
        diam = Diameter.from_buffer_copy(buf, offset)
        if len(buf) < offset+diam.length:
            raise ValueError("Buffer size too small ({} instead of at least {} bytes)".format(len(buf)-offset, diam.length))       
        avps = AVP.decodeAVPs(buf[offset+ctypes.sizeof(diam):offset+diam.length])
        diamclass = Diameterclasses.get((diam.command, diam.R), Diameter)
        return diamclass(*avps, version=diam.version, length=diam.length, R=diam.R, P=diam.P, E=diam.E, T=diam.T, unused=diam.unused, command=diam.command, application=diam.application, hop=diam.hop, end=diam.end)
    def __init__(self, *avps, version=1, **kwargs):
        super().__init__(version=version, **kwargs)
        if 'command' not in kwargs:
            try:
                self.command = self._command
            except AttributeError:
                raise Exception("missing command parameter") from None
        if 'R' not in kwargs:
            try:
                self.R = self._R
            except AttributeError:
                raise Exception("missing R parameter") from None
        self.avps = avps
    def __str__(self):
        avps = "\n  ".join(map(str, self.avps))
        if (self.command,self.R) in Diameterclasses:
            return "{}(\n  {}\n  application={}\n)".format(self.__class__.__name__, avps, self.application)
        else:
            return "Diameter(\n  {}\n  command={}, R={}, application={}\n)".format(avps, self.command, self.R, self.application)
    __repr__ = __str__
    def getlength(self):
        return int.from_bytes(self._length, byteorder='big')
    def setlength(self, value):
        self._length = (ctypes.c_uint8 * 3)(*value.to_bytes(3, 'big'))
    length = property(getlength, setlength)
    def getcommand(self):
        return int.from_bytes(self._command_, byteorder='big')
    def setcommand(self, value):
        self._command_ = (ctypes.c_uint8 * 3)(*value.to_bytes(3, 'big'))
    command = property(getcommand, setcommand)
    def getapplication(self):
        try:
            return Application(self._application)
        except:
            return self._application
    def setapplication(self, value):
        if isinstance(value, enum.Enum):
            value = value.value
        self._application = value
    application = property(getapplication, setapplication)
    def __bytes__(self):
        avps = b''.join([bytes(avp) for avp in self.avps])
        self.length = ctypes.sizeof(Diameter) + len(avps)
        return b'' + self + avps

class CER(Diameter):
    _command = 257; _R=1
class CEA(Diameter):
    _command = 257; _R=0


AVPclasses = {}
class AVPMeta(type(ctypes.BigEndianStructure)):
    def __init__(cls, name, bases, dikt):
        if '_code' in dikt:
            AVPclasses[dikt['_code']] = cls
        super(AVPMeta, cls).__init__(name, bases, dikt)

class AVP(ctypes.BigEndianStructure, metaclass=AVPMeta):
    _fields_ = (
        ('code', ctypes.c_uint32),
        ('V', ctypes.c_byte, 1),
        ('M', ctypes.c_byte, 1),
        ('P', ctypes.c_byte, 1),
        ('unused', ctypes.c_byte, 5),
        ('_length', ctypes.c_byte * 3),
    )
    @staticmethod
    def from_bytes(buf, offset):
        avp = AVP.from_buffer_copy(buf, offset)
        if len(buf) < avp.length:
            raise ValueError("Buffer size too small ({} instead of at least {} bytes)".format(len(buf)-offset, avp.length))
        data = buf[offset+ctypes.sizeof(avp):offset+avp.length]
        avpclass = AVPclasses.get(avp.code, AVP)
        return avpclass(data=data, code=avp.code, V=avp.V, M=avp.M, P=avp.P, _length=avp._length)
    @staticmethod
    def decodeAVPs(buf, offset=0):
        avps = []
        offset = offset
        while offset < len(buf):
            avp = AVP.from_bytes(buf, offset)
            avps.append(avp)
            offset += 4 * (1+(avp.length-1)//4)
        return avps
    def __init__(self, data=b'', **kwargs):
        super().__init__(**kwargs)
        if 'code' not in kwargs:
            try:
                self.code = self._code
            except AttributeError:
                raise Exception("missing code parameter") from None
        self.data = data
    def __bytes__(self):
        self.length = ctypes.sizeof(self) + len(self._data)
        padlen = (4 - self.length % 4) % 4
        return b'' + self + self._data + b'\x00' * padlen
    def __str__(self):
        if self.code in AVPclasses:
            return "{}({!r})".format(self.__class__.__name__, self.data)
        else:
            return "AVP({!r}, code={})".format(self.data, self.code)
    __repr__ = __str__
    def getlength(self):
        return int.from_bytes(self._length, byteorder='big')
    def setlength(self, value):
        self._length = (ctypes.c_byte * 3)(*value.to_bytes(3, 'big'))
    length = property(getlength, setlength)
class OctetString(AVP):
    def getdata(self):
        return self._data
    def setdata(self, data):
        self._data = data
    data = property(getdata, setdata)
class Integer32(AVP):
    def getdata(self):
        return int.from_bytes(self._data, byteorder='big', signed=True)
    def setdata(self, data):
        if isinstance(data, int):
            data = data.to_bytes(4, 'big', signed=True)
        self._data = data
    data = property(getdata, setdata)
class Integer64(AVP):
    def getdata(self):
        return int.from_bytes(self._data, byteorder='big', signed=True)
    def setdata(self, data):
        if isinstance(data, int):
            data = data.to_bytes(8, 'big', signed=True)
        self._data = data
    data = property(getdata, setdata)
class Unsigned32(AVP):
    def getdata(self):
        return int.from_bytes(self._data, byteorder='big', signed=False)
    def setdata(self, data):
        if isinstance(data, int):
            data = data.to_bytes(4, 'big', signed=False)
        self._data = data
    data = property(getdata, setdata)
class Unsigned64(AVP):
    def getdata(self):
        return int.from_bytes(self._data, byteorder='big', signed=False)
    def setdata(self, data):
        if isinstance(data, int):
            data = data.to_bytes(8, 'big', signed=False)
        self._data = data
    data = property(getdata, setdata)
class Float32(AVP):
    def getdata(self):
        return struct.unpack('>f', self._data)[0]
    def setdata(self, data):
        if isinstance(data, float):
            data = struct.pack('>f', data)
        self._data = data
    data = property(getdata, setdata)
class Float64(AVP):
    def getdata(self):
        return struct.unpack('>d', self._data)[0]
    def setdata(self, data):
        if isinstance(data, float):
            data = struct.pack('>d', data)
        self._data = data
    data = property(getdata, setdata)
class Address(AVP):
    def getdata(self):
        try:
            t = int.from_bytes(self._data[:2], byteorder='big', signed=False)
            a = ipaddress.ip_address(self._data[2:])
            return a
        except:
            return self._data
    def setdata(self, data):
        try:
            data = ipaddress.ip_address(data)
            if isinstance(data, ipaddress.IPv4Address):
                self._data = b'\x00\x01' + data.packed
            elif isinstance(data, ipaddress.IPv6Address):
                self._data = b'\x00\x02' + data.packed
        except:
            self._data = data
    data = property(getdata, setdata)
class UTF8String(AVP):
    def getdata(self):
        return self._data.decode('utf-8')
    def setdata(self, data):
        if isinstance(data, str):
            self._data = data.encode('utf-8')
        else:
            self._data = data
    data = property(getdata, setdata)
class DiamIdent(AVP):
    def getdata(self):
        return self._data.decode('ascii')
    def setdata(self, data):
        if isinstance(data, str):
            self._data = data.encode('ascii')
        else:
            self._data = data
    data = property(getdata, setdata)
class Grouped(AVP):
    def getdata(self):
        return AVP.decodeAVPs(self._data)
    def setdata(self, data):
        if isinstance(data, (list, tuple)):
            self._data = b''.join((bytes(avp) for avp in data))
        else:
            self._data = data
    data = property(getdata, setdata)

class Auth_Application_Id(Unsigned32):
    _code = 258
class Origin_Host(DiamIdent):
    _code = 264
class Origin_Realm(DiamIdent):
    _code = 296
class Host_IP_Address(Address):
    _code = 257
class Product_Name(UTF8String):
    _code = 269
class Vendor_Id(Unsigned32):
    _code = 266
class Failed_AVP(Grouped):
    _code = 279
class Result_Code(Unsigned32):
    _code = 268
class Error_Message(UTF8String):
    _code = 281

