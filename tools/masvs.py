#!/usr/bin/env python

''' MASVS document parser and converter class.

    By Bernhard Mueller, updated by Jeroen Beckers

    Copyright (c) 2019 OWASP Foundation

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

    '''

import os
import re
import json
from xml.sax.saxutils import escape
import csv

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class MASVS:
    ''' Creates requirements list out of markdown files. '''
    requirements = []

    def __init__(self, lang):

        target = "../Document" if lang == "en" else f"../Document-{lang}"
        for file in os.listdir(target):

            if re.match("0x\d{2}-V", file):
                for line in open(os.path.join(target, file)):
                    regex = re.compile(r'\*\*(\d\.\d+)\*\*\s\|\s{0,1}(.*?)\s{0,1}\|\s{0,1}(.*?)\s{0,1}\|\s{0,1}(.*?)\s{0,1}\|(\s{0,1}(.*?)\s{0,1}\|)?')
                    if lang=="fa" :
                        line=line.decode('utf-8')
                    if m := re.search(regex, line):
                        req = {'id': m[1].strip()}

                        req['text'] = m[3].strip()
                        req['category'] = m[2].replace(u"\u2011", "-")
                        if m[5]:
                            req['L1'] = len(m[4].strip()) > 0
                            req['L2'] = len(m[5].strip()) > 0
                            req['R'] = False
                        else:
                            req['R'] = True
                            req['L1'] = False
                            req['L2'] = False

                        self.requirements.append(req)
                   
    def to_json(self):
        ''' Returns a JSON-formatted string '''
        return json.dumps(self.requirements)


    def to_xml(self):
        ''' Returns XML '''
        xml = '<requirements>'

        for r in self.requirements:
            xml += f"<requirement id='{r['id']}' category='{r['category']}' L1='{int(r['L1'])}' L2='{int(r['L2'])}' R='{int(r['R'])}'>{escape(r['text'])}</requirement>\n"


        xml += '</requirements>'
        return xml

    def to_csv(self):
        ''' Returns CSV '''
        si = StringIO()

        writer = csv.DictWriter(si, ['id', 'text', 'category', 'L1', 'L2', 'R'], extrasaction='ignore')
        writer.writeheader()
        writer.writerows(self.requirements)

        return si.getvalue()
