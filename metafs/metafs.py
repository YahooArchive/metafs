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


class MetaFSError(Exception):
    pass


class Filer(object):
    def __init__(self, max_parse_size=100000000, magic_file=None):
        try:
            if magic_file:
                self.file_magic = magic.Magic(magic_file=magic_file)
            else:
                self.file_magic = magic.Magic()
        except (ImportError, magic.MagicException):
            self.file_magic = None
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
                    if self.file_magic is not None:
                        try:
                            file_type = self.file_magic.from_file(fullpath)
                        except magic.MagicException:
                            file_type = "Unknown"
                    else:
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
                self._update_file_entry(file_hash, path_hash, filename, file_type, stat.st_size, stat.st_mtime,
                                        stat.st_atime, stat.st_ctime)

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

        cursor.execute('''CREATE TABLE IF NOT EXISTS hashes
(hash_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, hash TEXT UNIQUE NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS directories
(path_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, path TEXT UNIQUE NOT NULL, mtime REAL NOT NULL,
ctime REAL NOT NULL, atime REAL NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS files
(file_id INTEGER NOT NULL, path_id INTEGER NOT NULL, filename TEXT NOT NULL, magic_id INTEGER NOT NULL,
size INTEGER NOT NULL, mtime REAL NOT NULL, ctime REAL NOT NULL, atime REAL NOT NULL,
PRIMARY KEY (file_id, path_id))''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS magics
(magic_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, magic TEXT UNIQUE NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS peheaders
(file_id INTEGER PRIMARY KEY NOT NULL, export_dll_id INTEGER NOT NULL, compile_time INTEGER NOT NULL,
petype TEXT NOT NULL, subsystem INTEGER NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS export_dlls
(export_dll_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, export_dll TEXT UNIQUE NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS export_functions
(export_function_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, export_function TEXT UNIQUE NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS file_exports
(file_id INTEGER NOT NULL, export_function_id INTEGER NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS import_dlls
(import_dll_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, import_dll TEXT UNIQUE NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS file_import_dlls
(file_id INTEGER NOT NULL, import_dll_hash TEXT UNIQUE NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS import_functions
(import_function_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, import_function TEXT UNIQUE NOT NULL,
import_dll_id INTEGER NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS file_import_functions
(file_id INTEGER NOT NULL, import_function_id INTEGER NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS sections
(file_id INTEGER NOT NULL, name TEXT NOT NULL, size INTEGER NOT NULL, v_size INTEGER NOT NULL,
entropy REAL NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS version_info_fields
(version_info_field_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, version_info_field TEXT UNIQUE NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS version_info_values
(version_info_value_id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, version_info_value TEXT UNIQUE NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS file_version_info
(file_id INTEGER NOT NULL, version_info_field_id INTEGER NOT NULL, version_info_value_id INTEGER NOT NULL)''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS anomalies
(file_id INTEGER NOT NULL, anomaly TEXT NOT NULL)''')

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
        file_id = self._get_hash_id(file_hash)
        self._insert_pe_headers(file_id, headers.get("peheaders"))

    def _update_dir_entry(self, path_hash, path, mtime, atime, ctime):
        # Insert/Update directory entry in the filer store
        path_id = self._get_hash_id(path_hash)
        cursor = self.conn.cursor()
        cursor.execute("REPLACE INTO directories VALUES (?, ?, ?, ?, ?)", (path_id, path, mtime, atime, ctime))
        cursor.close()
        self.conn.commit()

    def _update_file_entry(self, file_hash, path_hash, filename, file_type, size, mtime, atime, ctime):
        # Insert/Update fs entry in the filer store
        file_id = self._get_hash_id(file_hash)
        path_id = self._get_hash_id(path_hash)

        if file_type is not None:
            magic_id = self._get_magic_id(file_type)
            cursor = self.conn.cursor()

            cursor.execute("REPLACE INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           (file_id, path_id, filename, magic_id, size, mtime, atime, ctime))
            cursor.close()
        else:
            cursor = self.conn.cursor()
            cursor.execute("UPDATE files SET mtime=?, atime=?, ctime=? WHERE file_id=? AND path_id=?",
                           (mtime, atime, ctime, file_id, path_id))
            cursor.close()
        self.conn.commit()

    def _check_meta_entry(self, file_hash):
        # Check to see if a file entry already exists in the filer store
        cursor = self.conn.cursor()
        cursor.execute("SELECT hash FROM hashes WHERE hash = ?", (file_hash,))
        results = cursor.fetchall()
        cursor.close()
        return len(results)

    def _insert_pe_headers(self, file_id, peheaders):
        if peheaders:
            export_dll_id = self._insert_pe_exports(file_id, peheaders.get("exports"))
            self._insert_pe_imports(file_id, peheaders.get("imports"))
            self._insert_pe_version_info(file_id, peheaders.get("version_info"))
            self._insert_pe_sections(file_id, peheaders.get("sections"))
            self._insert_pe_anomalies(file_id, peheaders.get("anomalies"))

            peheader = (file_id,
                        export_dll_id,
                        peheaders.get("compile_time"),
                        peheaders.get("petype"),
                        peheaders.get("subsystem"))
            cursor = self.conn.cursor()
            cursor.execute("INSERT OR IGNORE INTO peheaders VALUES (?, ?, ?, ?, ?)", peheader)
            cursor.close()
            self.conn.commit()

    def _insert_pe_exports(self, file_id, exports):
        if exports:
            export_dll_name = exports.get("dll_name") or ""
            export_dll_id = self._get_export_dll_id(export_dll_name)
            functions = exports.get("functions")

            file_exports = []
            for function in functions:
                export_function_name = function.get("name") or "0x%0.4x" % function.get("ordinal")
                export_function_id = self._get_export_function_id(export_function_name)
                file_exports.append((file_id, export_function_id))
            cursor = self.conn.cursor()
            cursor.executemany("INSERT OR IGNORE INTO file_exports VALUES (?, ?)", file_exports)
            cursor.close()
            self.conn.commit()
        else:
            export_dll_id = self._get_export_dll_id("")
        return export_dll_id

    def _insert_pe_imports(self, file_id, imports):
        if imports:
            file_import_dlls = []
            file_import_functions = []
            for import_dll_name in imports:
                import_dll_id = self._get_import_dll_id(import_dll_name)
                file_import_dlls.append((file_id, import_dll_id))
                for function in imports[import_dll_name]:
                    import_function_name = function.get("name") or "0x%0.4x" % function.get("ordinal")
                    import_function_id = self._get_import_function_id(import_function_name, import_dll_id)
                    file_import_functions.append((file_id, import_function_id))
            cursor = self.conn.cursor()
            cursor.executemany("INSERT OR IGNORE INTO file_import_dlls VALUES (?, ?)", file_import_dlls)
            cursor.executemany("INSERT OR IGNORE INTO file_import_functions VALUES (?, ?)", file_import_functions)
            cursor.close()
            self.conn.commit()

    def _insert_pe_version_info(self, file_id, version_info):
        if version_info:
            file_version_info = []
            for version_info_field in version_info:
                version_info_field_id = self._get_version_info_field_id(version_info_field)
                version_info_value = version_info[version_info_field] or ""
                version_info_value_id = self._get_version_info_value_id(version_info_value)
                file_version_info.append((file_id, version_info_field_id, version_info_value_id))
            cursor = self.conn.cursor()
            cursor.executemany("INSERT OR IGNORE INTO file_version_info VALUES (?, ?, ?)", file_version_info)
            cursor.close()
            self.conn.commit()

    def _insert_pe_sections(self, file_id, sections):
        if sections:
            file_sections = []
            for section in sections:
                file_sections.append((file_id, section["name"], section["size"], section["v_size"], section["entropy"]))
            cursor = self.conn.cursor()
            cursor.executemany("INSERT OR IGNORE INTO sections VALUES (?, ?, ?, ?, ?)", file_sections)
            cursor.close()
            self.conn.commit()

    def _insert_pe_anomalies(self, file_id, anomalies):
        if anomalies:
            file_anomalies = []
            for anomaly in anomalies:
                file_anomalies.append((file_id, anomaly))
            cursor = self.conn.cursor()
            cursor.executemany("INSERT OR IGNORE INTO anomalies VALUES (?, ?)", file_anomalies)
            cursor.close()
            self.conn.commit()

    def _get_hash_id(self, md5hash):
        cursor = self.conn.cursor()
        cursor.execute("SELECT hash_id FROM hashes WHERE hash=?", (md5hash,))
        result = cursor.fetchone()
        if not result:
            cursor.execute("INSERT OR IGNORE INTO hashes (hash) VALUES (?)", (md5hash,))
            self.conn.commit()
            cursor.execute("SELECT hash_id FROM hashes WHERE hash=?", (md5hash,))
            result = cursor.fetchone()
        cursor.close()
        return result[0]

    def _get_import_function_id(self, import_function_name, import_dll_id):
        cursor = self.conn.cursor()
        cursor.execute("SELECT import_function_id FROM import_functions WHERE import_function=?",
                       (import_function_name,))
        result = cursor.fetchone()
        if not result:
            cursor.execute("INSERT OR IGNORE INTO import_functions (import_function, import_dll_id) VALUES (?, ?)",
                           (import_function_name, import_dll_id))
            self.conn.commit()
            cursor.execute("SELECT import_function_id FROM import_functions WHERE import_function=?",
                           (import_function_name,))
            result = cursor.fetchone()
        cursor.close()
        return result[0]

    def _get_import_dll_id(self, import_dll_name):
        import_dll_name = import_dll_name.lower()
        cursor = self.conn.cursor()
        cursor.execute("SELECT import_dll_id FROM import_dlls WHERE import_dll=?", (import_dll_name,))
        result = cursor.fetchone()
        if not result:
            cursor.execute("INSERT OR IGNORE INTO import_dlls (import_dll) VALUES (?)", (import_dll_name,))
            self.conn.commit()
            cursor.execute("SELECT import_dll_id FROM import_dlls WHERE import_dll=?", (import_dll_name,))
            result = cursor.fetchone()
        cursor.close()
        return result[0]

    def _get_export_dll_id(self, export_dll_name):
        cursor = self.conn.cursor()
        cursor.execute("SELECT export_dll_id FROM export_dlls WHERE export_dll=?", (export_dll_name,))
        result = cursor.fetchone()
        if not result:
            cursor.execute("INSERT OR IGNORE INTO export_dlls (export_dll) VALUES (?)", (export_dll_name,))
            self.conn.commit()
            cursor.execute("SELECT export_dll_id FROM export_dlls WHERE export_dll=?", (export_dll_name,))
            result = cursor.fetchone()
        cursor.close()
        return result[0]

    def _get_export_function_id(self, export_function_name):
        cursor = self.conn.cursor()
        cursor.execute("SELECT export_function_id FROM export_functions WHERE export_function=?",
                       (export_function_name,))
        result = cursor.fetchone()
        if not result:
            cursor.execute("INSERT OR IGNORE INTO export_functions (export_function) VALUES (?)",
                           (export_function_name,))
            self.conn.commit()
            cursor.execute("SELECT export_function_id FROM export_functions WHERE export_function=?",
                           (export_function_name,))
            result = cursor.fetchone()
        cursor.close()
        return result[0]

    def _get_magic_id(self, file_type):
        cursor = self.conn.cursor()
        cursor.execute("SELECT magic_id FROM magics WHERE magic=?", (file_type,))
        result = cursor.fetchone()
        if not result:
            cursor.execute("INSERT OR IGNORE INTO magics (magic) VALUES (?)", (file_type,))
            self.conn.commit()
            cursor.execute("SELECT magic_id FROM magics WHERE magic=?", (file_type,))
            result = cursor.fetchone()
        cursor.close()
        return result[0]

    def _get_version_info_field_id(self, version_info_field):
        cursor = self.conn.cursor()
        cursor.execute("SELECT version_info_field_id FROM version_info_fields WHERE version_info_field=?",
                       (version_info_field,))
        result = cursor.fetchone()
        if not result:
            cursor.execute("INSERT OR IGNORE INTO version_info_fields (version_info_field) VALUES (?)",
                           (version_info_field,))
            self.conn.commit()
            cursor.execute("SELECT version_info_field_id FROM version_info_fields WHERE version_info_field=?",
                           (version_info_field,))
            result = cursor.fetchone()
        cursor.close()
        return result[0]

    def _get_version_info_value_id(self, version_info_value):
        cursor = self.conn.cursor()
        cursor.execute("SELECT version_info_value_id FROM version_info_values WHERE version_info_value=?",
                       (version_info_value,))
        result = cursor.fetchone()
        if not result:
            cursor.execute("INSERT OR IGNORE INTO version_info_values (version_info_value) VALUES (?)",
                           (version_info_value,))
            self.conn.commit()
            cursor.execute("SELECT version_info_value_id FROM version_info_values WHERE version_info_value=?",
                           (version_info_value,))
            result = cursor.fetchone()
        cursor.close()
        return result[0]