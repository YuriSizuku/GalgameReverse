#!/usr/bin/env python3
#-*- coding: utf-8 -*-
"""Helper class for programmatically downloading/exporting Google Sheets

<https://docs.google.com/spreadsheets/d/1p03_q6VTfYQEjlDhpypgoPdLQREhXwXz2ObTUkz5dlY>
"""

__version__ = '1.0.0'
__date__    = '2021-04-29'
__author__  = 'Robert Jordan'

__all__ = ['GoogleSheet']

#######################################################################################

## runtime imports:
# import urllib.request  # used in GoogleSheet.download(...)

import io
from collections import namedtuple
from typing import Optional


#region ## GOOGLE SHEET DOWNLOAD ##

class GoogleSheet(namedtuple('GoogleSheet', ('longid', 'gid'))):
    def __new__(cls, longid:str, gid:Optional[int]=None):
        return super().__new__(cls, longid, gid)
    
    def with_gid(self, gid:int) -> 'GoogleSheet':
        """gsheet.with_gid(gid) -> GoogleSheet(gsheet.longid, gid)
        """
        return GoogleSheet(self.longid, gid)

    @property
    def url(self) -> str:
        """gsheet.url -> csv_download_url:str

        alias for: gsheet.geturl()
        """
        return self.geturl()
    def geturl(self, gid:int=..., *, format:str='csv') -> str:
        """gsheet.get_url() -> csv_download_url:str
        gsheet.get_url([gid], format='tsv') -> tsv_download_url:str for new gid

        arguments:
          gid      - override GID "sheet" ID.
          format   - file format supported by Google Sheets (i.e. 'csv', 'tsv').

        returns:
          str - download url for Google Sheet.
        """
        #source: <https://stackoverflow.com/a/37706008/7517185>
        if gid is Ellipsis:
            gid = 0 if self.gid is None else self.gid
        elif gid is None:
            gid = 0
        return f'https://docs.google.com/spreadsheets/d/{self.longid}/export?gid={gid}&format={format}&id={self.longid}'
    
    def download(self, gid:int=..., *, format:str='csv', remove_crlf:bool=True, ignore_status:bool=False) -> str:
        """gsheet.download() -> csv_file:str
        gsheet.download([gid], format='tsv') -> tsv_file:str for new gid

        arguments:
          gid      - override GID "sheet" ID.
          format   - file format supported by Google Sheets (i.e. 'csv', 'tsv').
          remove_crlf   - replace all newlines '\\r\\n' (CRLF) with '\\n' (LF).
          ignore_status - do not raise exception for non-200 HTTP statuses.

        returns:
          str - text data of downloaded Google Sheet in specified format.
        """
        url:str = self.geturl(gid, format=format)

        #source: <https://stackoverflow.com/a/7244263/7517185>
        import urllib.request  # this import is sloooooooooooow
        response = urllib.request.urlopen(url)
        if not ignore_status and response.status != 200:
            raise Exception(f'Unexpected HTTP response status {response.status}')
        data:str = response.read().decode('utf-8')
        if remove_crlf:
            data = data.replace('\r\n', '\n')
        return data
    
    def open(self, gid:int=..., *, format:str='csv', remove_crlf:bool=True, ignore_status:bool=False) -> io.StringIO:
        """gsheet.open() -> io.StringIO(csv_file:str)
        gsheet.open([gid], format='tsv') -> io.StringIO(tsv_file:str for new gid)

        arguments:
          gid      - override GID "sheet" ID.
          format   - file format supported by Google Sheets (i.e. 'csv', 'tsv').
          remove_crlf   - replace all newlines '\\r\\n' (CRLF) with '\\n' (LF).
          ignore_status - do not raise exception for non-200 HTTP statuses.

        returns:
          io.StringIO - string reader of downloaded Google Sheet in specified format.
        """
        return io.StringIO(self.download(gid, format=format, remove_crlf=remove_crlf, ignore_status=ignore_status))

#endregion


del namedtuple, Optional  # cleanup declaration-only imports
