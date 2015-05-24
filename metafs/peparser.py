#!/usr/bin/env python

# Copyright (c) 2015, Yahoo Inc.
# Copyrights licensed under the BSD
# See the accompanying LICENSE.txt file for terms.

"""Parser for PE Headers for MetaFS
"""

import pefile
import string
import re

# TODO Add Certs
# TODO Add Resource magic types
# TODO Callbacks

class PEHeader(object):
    """Represent a PE file header"""

    def __init__(self, fullpath, file_magic=None):
        self.file_magic = file_magic
        pe = pefile.PE(fullpath, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_TLS'],
            pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])

        self.subsystem = pe.OPTIONAL_HEADER.Subsystem
        self.compile_time = pe.FILE_HEADER.TimeDateStamp
        # self.ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        # if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
        #     self.tls = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        self.type = self._get_type(pe)
        self.exports = self._get_exports(pe)
        self.imports = self._get_imports(pe)
        self.version_info = self._get_version_info(pe)
        # self.resources = self._get_resources(pe)
        self.sections = self._get_sections(pe)
        self.anomalies = self._get_anomalies(pe)

        pe.close()

    def parse(self):
        header = {
            "subsystem": self.subsystem,
            "compile_time": self.compile_time,
            # "ep": self.ep,
            "petype": self.type,
            "exports": self.exports,
            "imports": self.imports,
            "version_info": self.version_info,
            # "resources": self.resources,
            "sections": self.sections,
            "anomalies": self.anomalies
        }

        return header

    @staticmethod
    def _get_type(pe):
        # PE Type
        if pe.is_exe():
            pe_type = "exe"
        elif pe.is_dll():
            pe_type = "dll"
        elif pe.is_driver():
            pe_type = "drv"
        else:
            pe_type = "unk"
        return pe_type

    @staticmethod
    def _get_exports(pe):
        # PE Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = {
                "functions": []
            }

            if pe.DIRECTORY_ENTRY_EXPORT.struct.Name:
                exports["dll_name"] = pe.get_string_at_rva(pe.DIRECTORY_ENTRY_EXPORT.struct.Name)

            for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.address is not None:
                    export_function = {
                        "ordinal": export.ordinal,
                        "name": export.name,
                        "forwarder": str(export.forwarder)
                    }
                    exports["functions"].append(export_function)
            return exports
        else:
            return None

    @staticmethod
    def _get_imports(pe):
        # PE Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = {}
            for library in pe.DIRECTORY_ENTRY_IMPORT:
                functions = []
                for function in library.imports:
                    import_function = {
                        "ordinal": function.ordinal,
                        "name": function.name
                    }
                    functions.append(import_function)
                imports[library.dll] = functions
            return imports
        else:
            return None

    @staticmethod
    def _get_version_info(pe):
        # PE Version Info
        if hasattr(pe, 'FileInfo'):
            version_info = {}
            for entry in pe.FileInfo:
                if hasattr(entry, 'StringTable'):
                    for st_entry in entry.StringTable:
                        for str_entry in st_entry.entries.items():
                            version_info[str_entry[0]] = str_entry[1]
            return version_info
        else:
            return None

    def _get_resources(self, pe):
        # PE Resources
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            resources = []
            for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                resource_type = entry.name
                if resource_type is None:
                    resource_type = pefile.RESOURCE_TYPE.get(entry.struct.Id)
                if resource_type is None:
                    resource_type = entry.struct.Id
                if hasattr(entry, 'directory'):
                    for directory in entry.directory.entries:
                        if hasattr(directory, 'directory'):
                            for resource in directory.directory.entries:
                                resource_entry = {
                                    "name": str(resource_type),
                                    "size": resource.data.struct.Size,
                                    "type": ""
                                }
                                resource_data = None  # FIXME
                                if self.file_magic is not None:
                                    resource_entry["type"] = self.file_magic.from_buffer(resource_data)
                                resources.append(resource_entry)
            return resources
        else:
            return None

    @staticmethod
    def _get_sections(pe):
        # PE Sections
        sections = []
        for section in pe.sections:
            section_entry = {
                "name": ''.join([c for c in section.Name if c in string.printable]),
                "v_addr": section.VirtualAddress,
                "v_size": section.Misc_VirtualSize,
                "size": section.SizeOfRawData,
                "entropy": section.get_entropy()
            }
            sections.append(section_entry)
        return sections

    @staticmethod
    def _get_anomalies(pe):
        # Detected Anomalies
        anomalies = []

        if pe.OPTIONAL_HEADER.CheckSum == 0:
            anomalies.append("CHECKSUM_IS_ZERO")

        # This may be useful, but it causes significant performance degredation
        # if not pe.verify_checksum():
        #     anomalies.append("CHECKSUM_MISMATCH")

        if pe.get_overlay_data_start_offset():
            anomalies.append("CONTAINS_EOF_DATA")

        for i in range(0, len(pe.sections) - 1):
            section_end = pe.sections[i].SizeOfRawData + pe.sections[i].PointerToRawData
            start_next_section = pe.sections[i+1].PointerToRawData
            if section_end != start_next_section:
                anomalies.append("BAD_SECTION_SIZE")
                break

        for section in pe.sections:
            if not re.match("^[.A-Za-z][a-zA-Z]+", section.Name):
                anomalies.append("BAD_SECTION_NAME")
                break
        if anomalies:
            return anomalies
        else:
            return None
