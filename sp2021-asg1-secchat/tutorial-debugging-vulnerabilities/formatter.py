#!/usr/bin/python
import fileinput
import sys

for fileinput_line in fileinput.input():
    if 'close' in fileinput_line:
          break
    frm = "'"+fileinput_line.replace("\n", "")+"'"
    #print frm
    print eval(frm)
    sys.stdout.flush()
