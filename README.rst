MetaFS
******************************
MetaFS is for generating a datastore of file metadata for rapid complex searches

Build Status
============

.. image:: https://img.shields.io/pypi/dm/metafs.svg
    :target: https://pypi.python.org/pypi/metafs/
    
.. image:: https://img.shields.io/pypi/v/metafs.svg
   :target: https://pypi.python.org/pypi/metafs

.. image:: https://img.shields.io/badge/python-2.7-blue.svg
    :target: https://pypi.python.org/pypi/metafs/

.. image:: https://img.shields.io/pypi/l/metafs.svg
    :target: https://pypi.python.org/pypi/metafs/


Installation
============

To install metafs, simply:

.. code-block::

    $ pip install metafs

or using easy_install:

.. code-block::

    $ easy_install metafs

or from source:

.. code-block::

    $ python setup.py install


Getting Started
===============

.. code-block:: python

    >>> import metafs
    >>> filer = metafs.SQLiteFiler("./test.db")
    >>> filer.update("/")
    >>> filer.search("SELECT * FROM files")
    >>> filer.close()

SQLiteFiler Tables
==================

+-----------------------------+
| hashes                      |
+=================+===========+
| hash_id INTEGER | hash TEXT |
+-----------------+-----------+

+-------------------------------+
| magics                        |
+==================+============+
| magic_id INTEGER | magic TEXT |
+------------------+------------+



+--------------------------------------------------------------------+
| directories                                                        |
+=================+===========+============+============+============+
| path_id INTEGER | path TEXT | mtime REAL | atime REAL | ctime REAL |
+-----------------+-----------+------------+------------+------------+

+----------------------------------------------------------------------+
| files                                                                |
+=================+=================+===============+==================+
| file_id INTEGER | path_id INTEGER | filename TEXT | magic_id INTEGER |
+-----------------+-----------------+---------------+------------------+
| size INTEGER    | mtime REAL      | ctime REAL    | atime REAL       |
+-----------------+-----------------+---------------+------------------+

+------------------------------------------------------------------------------+
| peheaders                                                                    |
+=================+=======================+======================+=============+
| file_id INTEGER | export_dll_id INTEGER | compile_time INTEGER | petype TEXT |
+-----------------+-----------------------+----------------------+-------------+

+-----------------------------------------+
| export_dlls                             |
+=======================+=================+
| export_dll_id INTEGER | export_dll TEXT |
+-----------------------+-----------------+

+---------------------------------------------------+
| export_functions                                  |
+============================+======================+
| export_function_id INTEGER | export_function TEXT |
+----------------------------+----------------------+

+-----------------------------------------+
| file_export_functions                   |
+=================+=======================+
| file_id INTEGER | export_dll_id INTEGER |
+-----------------+-----------------------+

+------------------------------------------+
| import_dlls                              |
+=======================+==================+
| import_dll_id INTEGER | import_dll TEXT  |
+-----------------------+------------------+

+---------------------------------------------------------------------------+
| import_functions                                                          |
+============================+======================+=======================+
| import_function_id INTEGER | import_function TEXT | import_dll_id INTEGER |
+----------------------------+----------------------+-----------------------+

+----------------------------------------+
| file_import_dlls                       |
+=================+======================+
| file_id INTEGER | import_dll_hash TEXT |
+-----------------+----------------------+

+---------------------------------------------+
| file_import_functions                       |
+=================+===========================+
| file_id INTEGER | import_function_id INTEER |
+-----------------+---------------------------+

+---------------------------------------------------------------------------------+
| file_version_info                                                               |
+=================+===============================+===============================+
| file_id INTEGER | version_info_field_id INTEGER | version_info_value_id INTEGER |
+-----------------+-------------------------------+-------------------------------+

+---------------------------------------------------------+
| version_info_fields                                     |
+===============================+=========================+
| version_info_field_id INTEGER | version_info_field TEXT |
+-------------------------------+-------------------------+

+---------------------------------------------------------+
| version_info_values                                     |
+===============================+=========================+
| version_info_value_id INTEGER | version_info_value TEXT |
+-------------------------------+-------------------------+

+----------------------------------------------------------------------------+
| sections                                                                   |
+=================+===========+==============+================+==============+
| file_id INTEGER | name TEXT | size INTEGER | v_size INTEGER | entropy REAL |
+-----------------+-----------+--------------+----------------+--------------+

+--------------------------------+
| anomalies                      |
+=================+==============+
| file_id INTEGER | anomaly TEXT |
+-----------------+--------------+

More Information
================
* Free software: BSD license, see LICENSE.txt for details
