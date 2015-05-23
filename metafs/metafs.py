#!/usr/bin/env python

# Copyright (c) 2015, Yahoo Inc.
# Copyrights licensed under the BSD
# See the accompanying LICENSE.txt file for terms.

"""Filer for storing file metadata for fast and complex searching
"""

import magic
import peparser
from pefile import PEFormatError
import hashlib
import sqlite3
import os
import sys

# TODO Check structure of db and reset if necessary
# TODO ELF/Mach-O Headers
# TODO verify proper behavior of section names character sets
# TODO Allow for lack of magic


class MetaFSError(Exception):
    pass


class Filer(object):
    def __init__(self, max_parse_size=100000000, magic_file=None):
        if magic_file:
            self.file_magic = magic.Magic(magic_file=magic_file)
        else:
            self.file_magic = magic.Magic()
        self.max_parse_size = max_parse_size

    def initialize(self, storage):
        # Method for initializing filer storage
        pass

    def update(self, root):
        if not os.path.isabs(root):
            raise MetaFSError("Must use absolute path for update")

        # Use lowercase paths for OSs that default to case insensitive file systems.  This could cause problems for
        # cases where a case sensitive file system has been mounted.
        if sys.platform in ["win32", "darwin"]:
            root = root.lower()
        self._add_dir_entry(root.decode('utf-8'))
        for (dirpath, dirnames, filenames) in os.walk(root):
            if sys.platform in ["win32", "darwin"]:
                dirpath = dirpath.lower()
            self._add_dir_entry(dirpath.decode('utf-8'))
            for filename in filenames:
                if sys.platform in ["win32", "darwin"]:
                    filename = filename.lower()
                self._add_file_entry(dirpath.decode('utf-8'), filename.decode('utf-8'))

    def _add_dir_entry(self, path):
        # Directories are stored by the hash of their path rather than contents
        path_hash = self._get_data_hash(path.encode('utf-8'))
        stat = os.stat(path)
        self._update_dir_entry(path_hash, path, stat.st_mtime, stat.st_atime, stat.st_ctime)

    def _add_file_entry(self, path, filename):
        file_type = None
        fullpath = os.path.join(path, filename)
        if os.path.isfile(fullpath):
            # Get hash of path
            path_hash = self._get_data_hash(path.encode('utf-8'))

            # Get stat info
            stat = os.stat(fullpath)

            # Get file hash
            if stat.st_size < self.max_parse_size:
                try:
                    file_hash = self._get_file_hash(fullpath)
                except IOError:
                    return

                # If the file has not been seen before get the metadata
                if not self._check_meta_entry(file_hash):
                    # Default to no headers
                    headers = {}

                    # Attempt to get get the magic
                    try:
                        file_type = self.file_magic.from_file(fullpath)
                    except magic.MagicException:
                        file_type = "Unknown"

                    # If type is PE parse the headers
                    if file_type.startswith("PE32"):
                            try:
                                headers["peheaders"] = peparser.PEHeader(fullpath).parse()
                            except PEFormatError:
                                pass

                    # insert new file entry
                    self._insert_meta_entry(file_hash, headers)

                # This file exists in the filer and only needs updating in the fs map
                self._update_file_entry(file_hash, path_hash, filename, file_type, stat.st_size, stat.st_mtime, stat.st_atime, stat.st_ctime)

    def _insert_meta_entry(self, file_hash, headers):
        # Insert file entry into the filer store
        pass

    def _update_dir_entry(self, path_hash, path, mtime, atime, ctime):
        # Insert/Update directory entry in the filer store
        pass

    def _update_file_entry(self, file_hash, path_hash, filename, file_type, size, mtime, atime, ctime):
        # Insert/Update file entry in the filer store
        pass

    def _check_meta_entry(self, file_hash):
        # Check to see if a file entry already exists in the filer store
        return False

    @staticmethod
    def _get_file_hash(fullpath):
        hasher = hashlib.md5()
        with open(fullpath, "rb") as fd:
            for chunk in iter(lambda: fd.read(2**20), b''):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def _get_data_hash(data):
        hasher = hashlib.md5()
        hasher.update(data)
        return hasher.hexdigest()


class SQLiteFiler(Filer):
    def __init__(self, filer_path, max_parse_size=100000000, magic_file=None):
        super(SQLiteFiler, self).__init__(max_parse_size=max_parse_size, magic_file=magic_file)

        if os.path.isfile(filer_path):
            self.conn = sqlite3.connect(filer_path)
        else:
            self.conn = self.initialize(filer_path)

    def initialize(self, storage):
        conn = sqlite3.connect(storage)
        cursor = conn.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS directories
(path_hash TEXT PRIMARY KEY NOT NULL, path TEXT NOT NULL, mtime REAL NOT NULL, ctime REAL NOT NULL,
 atime REAL NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS files
(file_hash TEXT NOT NULL, path_hash TEXT NOT NULL, filename TEXT NOT NULL, magic_hash TEXT NOT NULL,
size INT NOT NULL, mtime REAL NOT NULL, ctime REAL NOT NULL, atime REAL NOT NULL,
PRIMARY KEY (file_hash, path_hash))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS magic (magic_hash TEXT PRIMARY KEY NOT NULL,
magic TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS peheaders
(file_hash TEXT PRIMARY KEY NOT NULL, export_dll_hash TEXT NOT NULL, compile_time INT NOT NULL,
petype TEXT NOT NULL, subsystem INT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS export_dlls
(export_dll_hash TEXT PRIMARY KEY NOT NULL, export_dll TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS export_functions
(export_function_hash TEXT PRIMARY KEY NOT NULL, export_function TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS file_exports
(file_hash TEXT NOT NULL, export_function_hash TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS import_dlls
(import_dll_hash TEXT PRIMARY KEY NOT NULL, import_dll TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS file_import_dlls
(file_hash TEXT NOT NULL, import_dll_hash TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS import_functions
(import_function_hash TEXT PRIMARY KEY NOT NULL, import_function TEXT NOT NULL, import_dll_hash TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS file_import_functions
(file_hash TEXT NOT NULL, import_function_hash TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS sections
(file_hash TEXT NOT NULL, name TEXT NOT NULL, size INT NOT NULL, v_size INT NOT NULL, entropy REAL NOT NULL)''')

# Leaving this here for the future, but this makes the database unnecessarily large with little value
#         cursor.execute('''CREATE TABLE IF NOT EXISTS resources
# (file_hash TEXT NOT NULL, name TEXT NOT NULL, size INT NOT NULL, magic_hash TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS version_info_fields
(version_info_field_hash TEXT PRIMARY KEY NOT NULL, version_info_field TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS version_info_values
(version_info_value_hash TEXT PRIMARY KEY NOT NULL, version_info_value TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS file_version_info
(file_hash TEXT NOT NULL, version_info_field_hash TEXT NOT NULL, version_info_value_hash TEXT NOT NULL)''')


#         cursor.execute('''CREATE TABLE IF NOT EXISTS version_infos
# (version_info_hash TEXT PRIMARY KEY NOT NULL, version_info TEXT NOT NULL, value TEXT NOT NULL)''')
#
#         cursor.execute('''CREATE TABLE IF NOT EXISTS file_version_infos
# (file_hash TEXT NOT NULL, version_info_hash TEXT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS anomalies
(file_hash TEXT NOT NULL, anomaly TEXT NOT NULL)''')

        conn.commit()
        cursor.close()
        return conn

    def close(self):
        self.conn.commit()
        self.conn.close()

    def query(self, query):
        cursor = self.conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        cursor.close()
        return results

    def _insert_meta_entry(self, file_hash, headers):
        # Insert file entry into the filer store
        cursor = self.conn.cursor()
        if headers.get("peheaders"):
            if headers["peheaders"].get("exports"):
                export_dll_name = headers["peheaders"]["exports"].get("dll_name") or ""
                export_dll_hash = self._get_data_hash(export_dll_name)
                exports = headers["peheaders"]["exports"].get("functions")

                export_dlls = (export_dll_hash, export_dll_name)
                cursor.execute("INSERT OR IGNORE INTO export_dlls VALUES (?, ?)", export_dlls)

                export_functions = []
                file_exports = []
                for function in exports:
                    export_function_name = function.get("name") or "0x%0.4x" % function.get("ordinal")
                    export_function_hash = self._get_data_hash(export_function_name)
                    export_functions.append((export_function_hash, export_function_name))
                    file_exports.append((file_hash, export_function_hash))
                cursor.executemany("INSERT OR IGNORE INTO export_functions VALUES (?, ?)", export_functions)
                cursor.executemany("INSERT OR IGNORE INTO file_exports VALUES (?, ?)", file_exports)
            else:
                export_dll_hash = self._get_data_hash("")

            peheaders = (file_hash,
                         export_dll_hash,
                         headers["peheaders"].get("compile_time"),
                         headers["peheaders"].get("petype"),
                         headers["peheaders"].get("subsystem"))
            cursor.execute("INSERT OR IGNORE INTO peheaders VALUES (?, ?, ?, ?, ?)", peheaders)


            if headers["peheaders"].get("imports"):
                import_dlls = []
                import_functions = []
                file_import_dlls = []
                file_import_functions = []
                for import_dll_name in headers["peheaders"]["imports"]:
                    import_dll_hash = self._get_data_hash(import_dll_name.lower())
                    import_dlls.append((import_dll_hash, import_dll_name.lower()))
                    file_import_dlls.append((file_hash, import_dll_hash))
                    for function in headers["peheaders"]["imports"][import_dll_name]:
                        import_function_name = function.get("name") or "0x%0.4x" % function.get("ordinal")
                        import_function_hash = self._get_data_hash(import_function_name)
                        import_functions.append((import_function_hash, import_function_name, import_dll_hash))
                        file_import_functions.append((file_hash, import_function_hash))
                cursor.executemany("INSERT OR IGNORE INTO import_dlls VALUES (?, ?)", import_dlls)
                cursor.executemany("INSERT OR IGNORE INTO import_functions VALUES (?, ?, ?)", import_functions)
                cursor.executemany("INSERT OR IGNORE INTO file_import_dlls VALUES (?, ?)", file_import_dlls)
                cursor.executemany("INSERT OR IGNORE INTO file_import_functions VALUES (?, ?)", file_import_functions)

            # if headers["peheaders"].get("version_info"):
            #     version_infos = []
            #     file_version_infos = []
            #     for version_info in headers["peheaders"]["version_info"]:
            #         value = headers["peheaders"]["version_info"][version_info] or ""
            #         version_info_hash = self._get_data_hash(version_info.encode('utf-8') + value.encode('utf-8'))
            #         version_infos.append((version_info_hash, version_info, value))
            #         file_version_infos.append((file_hash, version_info_hash))
            #     cursor.executemany("INSERT OR IGNORE INTO version_infos VALUES (?, ?, ?)", version_infos)
            #     cursor.executemany("INSERT OR IGNORE INTO file_version_infos VALUES (?, ?)", file_version_infos)

            if headers["peheaders"].get("version_info"):
                file_version_info = []
                version_info_fields = []
                version_info_values = []
                for version_info_field in headers["peheaders"]["version_info"]:
                    version_info_field_hash = self._get_data_hash(version_info_field.encode('utf-8'))
                    version_info_value = headers["peheaders"]["version_info"][version_info_field] or ""
                    version_info_value_hash = self._get_data_hash(version_info_value.encode('utf-8'))
                    version_info_fields.append((version_info_field_hash, version_info_field))
                    version_info_values.append((version_info_value_hash, version_info_value))
                    file_version_info.append((file_hash, version_info_field_hash, version_info_value_hash))
                cursor.executemany("INSERT OR IGNORE INTO version_info_fields VALUES (?, ?)", version_info_fields)
                cursor.executemany("INSERT OR IGNORE INTO version_info_values VALUES (?, ?)", version_info_values)
                cursor.executemany("INSERT OR IGNORE INTO file_version_info VALUES (?, ?, ?)", file_version_info)


            # Leaving this here for the future, but this makes the database unnecessarily large with little value
            # if headers["peheaders"].get("resources"):
            #     resources = []
            #     for resource in headers["peheaders"]["resources"]:
            #         resource_magic = self._get_data_hash(resource["type"])
            #         resources.append((file_hash, resource["name"], resource["size"], resource_magic))
            #     cursor.executemany("INSERT OR IGNORE INTO resources VALUES (?, ?, ?, ?)", resources)

            if headers["peheaders"].get("sections"):
                sections = []
                for section in headers["peheaders"]["sections"]:
                    sections.append((file_hash, section["name"], section["size"], section["v_size"], section["entropy"]))
                cursor.executemany("INSERT OR IGNORE INTO sections VALUES (?, ?, ?, ?, ?)", sections)

            if headers["peheaders"].get("anomalies"):
                anomalies = []
                for anomaly in headers["peheaders"]["anomalies"]:
                    anomalies.append((file_hash, anomaly))
                cursor.executemany("INSERT OR IGNORE INTO anomalies VALUES (?, ?)", anomalies)

        cursor.close()
        self.conn.commit()

    def _update_dir_entry(self, path_hash, path, mtime, atime, ctime):
        # Insert/Update directory entry in the filer store
        cursor = self.conn.cursor()
        cursor.execute("REPLACE INTO directories VALUES (?, ?, ?, ?, ?)", (path_hash, path, mtime, atime, ctime))
        cursor.close()
        self.conn.commit()

    def _update_file_entry(self, file_hash, path_hash, filename, file_type, size, mtime, atime, ctime):
        # Insert/Update fs entry in the filer store
        cursor = self.conn.cursor()
        if file_type is not None:
            magic_hash = self._get_data_hash(file_type)
            cursor.execute("INSERT OR IGNORE INTO magic VALUES (?, ?)", (magic_hash, file_type))
            cursor.execute("REPLACE INTO files VALUES (?, ?, ?, ?, ?, ?, ? , ?)",
                           (file_hash, path_hash, filename, magic_hash, size, mtime, atime, ctime))
        else:
            cursor.execute("UPDATE files SET mtime=?, atime=?, ctime=? WHERE file_hash=? AND path_hash=?",
                           (mtime, atime, ctime, file_hash, path_hash))
        cursor.close()
        self.conn.commit()

    def _check_meta_entry(self, file_hash):
        # Check to see if a file entry already exists in the filer store
        cursor = self.conn.cursor()
        cursor.execute("SELECT file_hash FROM files WHERE file_hash = ?", (file_hash,))
        results = cursor.fetchall()
        cursor.close()
        return len(results)