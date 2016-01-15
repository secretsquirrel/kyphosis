#!/usr/bin/env python

import macholib.MachO
import sys
import os
import struct


class kyphosis():

    def __init__(self, someFile, writeFile=False):

        self.someFile = someFile
        self.extra_data_found = False
        self.supportedfiles = ["\xca\xfe\xba\xbe",  # FAT
                               "\xcf\xfa\xed\xfe",  # x86
                               "\xce\xfa\xed\xfe"   # x86_64
                               ]
        #check if macho
        self.dataoff = 0
        self.datasize = 0
        self.beginOffset = 0
        self.endOffset = 0
        self.fat_hdrs = {}
        self.extra_data = {}
        self.writeFile = writeFile

        self.run()

    def run(self):
        if self.check_binary() is not True:
            print "Submitted file is not a MachO file"
            return None

        self.aFile = macholib.MachO.MachO(self.someFile)

        if self.aFile.fat is None:
            self.find_load_cmds()
            self.check_macho_size()
        else:
            # Fat file
            self.make_soap()

        if self.extra_data_found is True:
            return True
        else:
            return False

    def make_soap(self):
        # process Fat file
        with open(self.someFile, 'r') as self.bin:
            self.bin.read(4)
            ArchNo = struct.unpack(">I", self.bin.read(4))[0]
            for arch in range(ArchNo):
                self.fat_hdrs[arch] = self.fat_header()
            self.end_fat_hdr = self.bin.tell()
            beginning = True
            self.count = 0
            for hdr, value in self.fat_hdrs.iteritems():
                if beginning is True:
                    self.beginOffset = self.end_fat_hdr
                    self.endOffset = value['Offset']
                    self.check_space()
                    self.beginOffset = value['Size'] + value['Offset']
                    beginning = False
                    self.count += 1
                    continue
                self.endOffset = value['Offset']
                self.check_space()
                self.beginOffset = value['Size'] + value['Offset']
                self.count += 1
        # Check end of file
        self.last_entry = self.beginOffset
        self.check_macho_size()

    def check_space(self):
        self.bin.seek(self.beginOffset, 0)
        self.empty_space = self.bin.read(self.endOffset - self.beginOffset)
        if self.empty_space != len(self.empty_space) * "\x00":
            print "Found extra data in the Fat file slack space for " + self.someFile
            self.extra_data_found = True
            self.extra_data[self.count] = self.extra_data_found
            if self.writeFile is True:
                print "Writing to " + os.path.basename(self.someFile) + '.extra_data_section' + str(self.count)
                with open(os.path.basename(self.someFile) + '.extra_data_section' + str(self.count), 'w') as h:
                    h.write(self.empty_space)

    def fat_header(self):
        header = {}
        header["CPU Type"] = struct.unpack(">I", self.bin.read(4))[0]
        header["CPU SubType"] = struct.unpack(">I", self.bin.read(4))[0]
        header["Offset"] = struct.unpack(">I", self.bin.read(4))[0]
        header["Size"] = struct.unpack(">I", self.bin.read(4))[0]
        header["Align"] = struct.unpack(">I", self.bin.read(4))[0]
        return header

    def check_binary(self):
        with open(self.someFile, 'r') as f:
            self.magicheader = f.read(4)
            if self.magicheader in self.supportedfiles:
                return True

    def find_load_cmds(self):
        for header in self.aFile.headers:
            for command in header.commands:
                if 'dataoff' in vars(command[1])['_objects_']:
                    self._dataoff = vars(command[1])['_objects_']['dataoff']
                    #check against api change after macholib 1.5.1
                    if 'datassize' in vars(command[1])['_objects_']:
                        self._datasize = vars(command[1])['_objects_']['datassize']
                    else:
                        self._datasize = vars(command[1])['_objects_']['datasize']
                    if self._dataoff > self.dataoff:
                        self.dataoff = self._dataoff
                        self.datasize = self._datasize
                if 'stroff' in vars(command[1])['_objects_']:
                    self._dataoff = vars(command[1])['_objects_']['stroff']
                    self._datasize = vars(command[1])['_objects_']['strsize']
                    if self._dataoff > self.dataoff:
                        self.dataoff = self._dataoff
                        self.datasize = self._datasize
                if 'fileoff' in vars(command[1])['_objects_']:
                    self._dataoff = vars(command[1])['_objects_']['fileoff']
                    self._datasize = vars(command[1])['_objects_']['filesize']
                    if self._dataoff > self.dataoff:
                        self.dataoff = self._dataoff
                        self.datasize = self._datasize

        self.last_entry = int(self.datasize + self.dataoff)

    def check_macho_size(self):
        with open(self.someFile, 'r') as f:
            if os.stat(self.someFile).st_size > self.last_entry:
                print "Found extra data at the end of file.. " + self.someFile
                f.seek(self.last_entry, 0)
                extra_data_end = f.read()
                self.extra_data_found = True
                self.extra_data['extra_data_end'] = extra_data_end
                if self.writeFile is True:
                    print "Writing to " + os.path.basename(self.someFile) + ".extra_data_end"
                    with open(os.path.basename(self.someFile) + '.extra_data_end', 'w') as g:
                        g.write(extra_data_end)


if __name__ == "__main__":
    if len(sys.argv) != 2: 
        print "Usage: " + sys.argv[0] + " macho_binary"
        sys.exit(-1)

    myfile = kyphosis(sys.argv[1], True)

    if myfile.extra_data_found is False:
		print "Nothing found"

