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
# TODO Store PE Headers
# TODO ELF/Mach-O Headers
# TODO anomaly, type, and subsystem id handling
# TODO filemagic for Windows
# TODO verify proper behavior of section names character sets


class MetaFSError(Exception):
    pass


class Filer(object):
    def __init__(self, max_parse_size=100000000):
        self.file_magic = magic.Magic()
        self.max_parse_size = max_parse_size

    def initialize(self, storage):
        # Method for initializing filer storage
        pass

    def update(self, root):
        if not root.startswith("/"):
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
        path_hash = hashlib.md5(path.encode('utf-8')).hexdigest()
        stat = os.stat(path)
        self._update_dir_entry(path_hash, path, stat.st_mtime, stat.st_atime, stat.st_ctime)

    def _add_file_entry(self, path, filename):
        fullpath = os.path.join(path, filename)
        if os.path.isfile(fullpath):
            # Get hash of path
            path_hash = hashlib.md5(path.encode('utf-8')).hexdigest()

            # Get stat info
            stat = os.stat(fullpath)

            # Get file hash
            if stat.st_size < self.max_parse_size:
                try:
                    file_hash = self._get_file_hash(fullpath)
                except IOError:
                    return

                if not self._check_meta_entry(file_hash):
                    # Default to no headers
                    headers = {}

                    # If the file hasn't been seen before get the magic
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
                    self._insert_meta_entry(file_hash, file_type, stat.st_size, headers)

                # This file exists in the filer and only needs updating in the fs map
                self._update_fs_entry(file_hash, path_hash, filename, stat.st_mtime, stat.st_atime, stat.st_ctime)

    def _insert_meta_entry(self, file_hash, file_type, size, headers):
        # Insert file entry into the filer store
        pass

    def _update_dir_entry(self, path_hash, path, mtime, atime, ctime):
        # Insert/Update directory entry in the filer store
        pass

    def _update_fs_entry(self, file_hash, path_hash, filename, mtime, atime, ctime):
        # Insert/Update fs entry in the filer store
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


class SQLiteFiler(Filer):
    def __init__(self, filer_path, max_parse_size=100000000):
        super(SQLiteFiler, self).__init__(max_parse_size=max_parse_size)

        if os.path.isfile(filer_path):
            self.conn = sqlite3.connect(filer_path)
        else:
            self.conn = self.initialize(filer_path)

    def initialize(self, storage):
        conn = sqlite3.connect(storage)
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS files
(file_hash TEXT PRIMARY KEY NOT NULL, magic_hash TEXT NOT NULL, size INT NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS directories
(path_hash TEXT PRIMARY KEY NOT NULL, path TEXT NOT NULL, mtime INT NOT NULL, ctime INT NOT NULL,
 atime INT NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS fs
(file_hash TEXT NOT NULL, path_hash TEXT NOT NULL, filename TEXT KEY NOT NULL, mtime INT NOT NULL,
ctime INT NOT NULL, atime INT NOT NULL, PRIMARY KEY (file_hash, path_hash))''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS magic (magic_hash TEXT PRIMARY KEY NOT NULL,
magic TEXT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS peheaders
(file_hash TEXT PRIMARY KEY NOT NULL, export_dll_hash TEXT KEY NOT NULL, compile_time INT KEY NOT NULL,
petype TEXT KEY NOT NULL, subsystem INT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS export_dlls
(export_dll_hash TEXT PRIMARY KEY NOT NULL, export_dll TEXT NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS export_functions
(export_function_hash TEXT PRIMARY KEY NOT NULL, export_function TEXT NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS file_exports
(file_hash TEXT KEY NOT NULL, export_function_hash TEXT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS import_dll_functions
(import_dll_hash TEXT KEY NOT NULL, import_function_hash TEXT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS import_functions
(import_function_hash TEXT PRIMARY KEY NOT NULL, import_function TEXT NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS import_dlls
(import_dll_hash TEXT PRIMARY KEY NOT NULL, import_dll TEXT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS file_import_dlls
(file_hash TEXT KEY NOT NULL, import_dll_hash TEXT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS file_import_functions
(file_hash TEXT KEY NOT NULL, import_function_hash TEXT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS sections
(file_hash TEXT KEY NOT NULL, name TEXT KEY NOT NULL, size INT KEY NOT NULL, v_addr TEXT KEY NOT NULL,
v_size INT KEY NOT NULL, entropy REAL KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS resources
(file_hash TEXT KEY NOT NULL, name TEXT KEY NOT NULL, size INT KEY NOT NULL, magic_hash TEXT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS version_infos
(version_info_hash TEXT PRIMARY KEY NOT NULL, version_info TEXT KEY NOT NULL, value TEXT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS file_version_infos
(file_hash TEXT KEY NOT NULL, version_info_hash TEXT KEY NOT NULL)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS anomalies
(file_hash TEXT KEY NOT NULL, anomaly TEXT KEY NOT NULL)''')
        conn.commit()
        cursor.close()
        return conn

    def close(self):
        self.conn.commit()
        self.conn.close()

    def _insert_meta_entry(self, file_hash, file_type, size, headers):
        # Insert file entry into the filer store
        cursor = self.conn.cursor()
        magic_hash = hashlib.md5(file_type).hexdigest()
        cursor.execute("INSERT OR IGNORE INTO files VALUES (?, ?, ?)", (file_hash, magic_hash, size))
        cursor.execute("INSERT OR IGNORE INTO magic VALUES (?, ?)", (magic_hash, file_type))
        if headers.get("peheaders"):
            if headers["peheaders"].get("exports"):
                export_dll_name = headers["peheaders"]["exports"].get("dll_name") or ""
                export_dll_hash = hashlib.md5(export_dll_name).hexdigest()
                exports = headers["peheaders"]["exports"].get("functions")

                export_dlls = (export_dll_hash, export_dll_name)
                cursor.execute("INSERT OR IGNORE INTO export_dlls VALUES (?, ?)", export_dlls)

                export_functions = []
                file_exports = []
                for function in exports:
                    export_function_name = function.get("name") or "0x%0.4x" % function.get("ordinal")
                    export_function_hash = hashlib.md5(export_function_name).hexdigest()
                    export_functions.append((export_function_hash, export_function_name))
                    file_exports.append((file_hash, export_function_hash))
                cursor.executemany("INSERT OR IGNORE INTO export_functions VALUES (?, ?)", export_functions)
                cursor.executemany("INSERT OR IGNORE INTO file_exports VALUES (?, ?)", file_exports)
            else:
                export_dll_hash = hashlib.md5().hexdigest()

            peheaders = (file_hash,
                         export_dll_hash,
                         headers["peheaders"].get("compile_time"),
                         headers["peheaders"].get("petype"),
                         headers["peheaders"].get("subsystem"))
            cursor.execute("INSERT OR IGNORE INTO peheaders VALUES (?, ?, ?, ?, ?)", peheaders)


            if headers["peheaders"].get("imports"):
                import_dlls = []
                import_functions = []
                import_dll_functions = []
                file_import_dlls = []
                file_import_functions = []
                for import_dll_name in headers["peheaders"]["imports"]:
                    import_dll_hash = hashlib.md5(import_dll_name).hexdigest()
                    import_dlls.append((import_dll_hash, import_dll_name))
                    file_import_dlls.append((file_hash, import_dll_hash))
                    for function in headers["peheaders"]["imports"][import_dll_name]:
                        import_function_name = function.get("name") or "0x%0.4x" % function.get("ordinal")
                        import_function_hash = hashlib.md5(import_function_name).hexdigest()
                        import_functions.append((import_function_hash, import_function_name))
                        import_dll_functions.append((import_dll_hash, import_function_hash))
                        file_import_functions.append((file_hash, import_function_hash))
                cursor.executemany("INSERT OR IGNORE INTO import_dlls VALUES (?, ?)", import_dlls)
                cursor.executemany("INSERT OR IGNORE INTO import_functions VALUES (?, ?)", import_functions)
                cursor.executemany("INSERT OR IGNORE INTO import_dll_functions VALUES (?, ?)", import_dll_functions)
                cursor.executemany("INSERT OR IGNORE INTO file_import_dlls VALUES (?, ?)", file_import_dlls)
                cursor.executemany("INSERT OR IGNORE INTO file_import_functions VALUES (?, ?)", file_import_functions)

            if headers["peheaders"].get("version_info"):
                version_infos = []
                file_version_infos = []
                for version_info in headers["peheaders"]["version_info"]:
                    value = headers["peheaders"]["version_info"][version_info] or ""
                    version_info_hash = hashlib.md5(version_info.encode('utf-8') + value.encode('utf-8')).hexdigest()
                    version_infos.append((version_info_hash, version_info, value))
                    file_version_infos.append((file_hash, version_info_hash))
                cursor.executemany("INSERT OR IGNORE INTO version_infos VALUES (?, ?, ?)", version_infos)
                cursor.executemany("INSERT OR IGNORE INTO file_version_infos VALUES (?, ?)", file_version_infos)

            if headers["peheaders"].get("resources"):
                resources = []
                for resource in headers["peheaders"]["resources"]:
                    resource_magic = hashlib.md5(resource["type"]).hexdigest()
                    resources.append((file_hash, resource["name"], resource["size"], resource_magic))
                cursor.executemany("INSERT OR IGNORE INTO resources VALUES (?, ?, ?, ?)", resources)

            if headers["peheaders"].get("sections"):
                sections = []
                for section in headers["peheaders"]["sections"]:
                    sections.append((file_hash, section["name"], section["size"], section["v_addr"],
                                     section["v_size"], section["entropy"]))
                cursor.executemany("INSERT OR IGNORE INTO sections VALUES (?, ?, ?, ?, ?, ?)", sections)

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

    def _update_fs_entry(self, file_hash, path_hash, filename, mtime, atime, ctime):
        # Insert/Update fs entry in the filer store
        cursor = self.conn.cursor()
        cursor.execute("REPLACE INTO fs VALUES (?, ?, ?, ?, ?, ?)", (file_hash, path_hash, filename, mtime, atime, ctime))
        cursor.close()
        self.conn.commit()

    def _check_meta_entry(self, file_hash):
        # Check to see if a file entry already exists in the filer store
        cursor = self.conn.cursor()
        cursor.execute("SELECT file_hash FROM files WHERE file_hash = ?", (file_hash,))
        results = cursor.fetchall()
        cursor.close()
        return len(results)