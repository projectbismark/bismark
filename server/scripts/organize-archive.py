#!/usr/bin/env python

import os
import re
import sys
import time
import datetime
import shutil
import tarfile

def clean_data(dir,targetdir):

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
            continue

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
        datadir = targetdir + dev_name + '/' + typedir + '/'+ datedir

        if not os.path.exists(datadir):
            os.makedirs(datadir)

        print dir+file + '->' + datadir
        shutil.move(dir+file,datadir)


    for dev in devices:
        print dev

def new_device_files(members,device,dir):
    for tarinfo in members:
        match = re.search(device,tarinfo.name)
        if match:
            yield tarinfo
        

def unpack_backup(device,dir,outdir):

    files = os.listdir(dir)
    for file in files:

        match = re.search(r'xml.tgz',file)
        if match:
            # unpack into the unpack dir
            print file
            try:
                tar = tarfile.open(dir+file,'r:gz')
                tar.extractall(outdir,members=new_device_files(tar,device))
                tar.close()
            except tarfile.ReadError:
                print "Warning Read Error"


if __name__ == '__main__':
    HOME = os.environ['HOME'] + '/'
    MEASURE_FILE_DIR = 'var/data/'

    ARCHIVE_DIR = HOME + MEASURE_FILE_DIR + 'old/'
    BACKUP_DIR = HOME + 'var/backup/'
    UNPACK_DIR = ARCHIVE_DIR + 'unpack/'

    PUBLISH_DIR = ARCHIVE_DIR

    clean_data(ARCHIVE_DIR,PUBLISH_DIR)

    # restore directory structure from backup
    #unpack_backup('NB105',BACKUP_DIR,UNPACK_DIR)    
    #clean_data(UNPACK_DIR,PUBLISH_DIR)
