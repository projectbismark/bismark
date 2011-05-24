#!/usr/bin/env python

import os
import re
import sys
import time
import datetime
import shutil

def clean_data(dir):

    UKY_DIR = os.environ['HOME'] + '/var/archive/UKY-old'
    devices = []
    measurements = []
    types = {'arp.gz':'arp',
             'csv':'airodump',
             'csv.gz':'airodump',
             'events.gz':'events',
             'filt.csv':'airodump',
             'xml.gz':'active'}


    files = os.listdir(dir)
    for file in files:

        if os.path.isdir(dir+file):
            print 'skipping ' + file
            continue


        # move the Kentucky data out
        match = re.search(r'[Uu]ky',file)
        if match:
            shutil.move(dir+file, UKY_DIR)

        # get list of devices
        match = re.search(r'[0-9A-Za-z]+',file)
        if match:
            dev_name = match.group()
            
            # list of devices
            if dev_name not in devices:
                devices.append(dev_name)

        match = re.search(r'([0-9]{10})',file)
        if match:
            timestr = match.group(1)
            date = datetime.date.fromtimestamp(float(timestr))
            datedir = str(date.year) + '/' + str(date.month)

        match = re.search(r'.*?[0-9]\.(.*)$',file)
        if match:
            extension = match.group(1)
            typedir = types[extension]


        # make directories and move files
        datadir = dir+ dev_name + '/' + typedir + '/'+ datedir

        if not os.path.exists(datadir):
            os.makedirs(datadir)

        #print dir+file + '->' + datadir
        shutil.move(dir+file,datadir)


    for dev in devices:
        print dev
        

            


if __name__ == '__main__':
    HOME = os.environ['HOME'] + '/'
    MEASURE_FILE_DIR = 'var/data/'
    ARCHIVE_DIR = HOME + MEASURE_FILE_DIR + 'old/'

    clean_data(ARCHIVE_DIR)
