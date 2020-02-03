#!/usr/bin/python3

import sys
import string
import random

chrs = string.ascii_letters

f =open('test_{}'.format(int(sys.argv[1])),'w')
for i in range(0,int(sys.argv[1])):
    f.write(random.choice(chrs))
