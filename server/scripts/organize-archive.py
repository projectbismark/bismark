#!/usr/bin/env python

import os
import re
import sys
import time
import datetime
import shutil
import tarfile


def filename_to_dir(file):

    types = {'arp.gz':'arp',
             'csv':'airodump',
             'csv.gz':'airodump',
             'events.gz':'events',
             'filt.csv':'airodump',
             'xml.gz':'active'}

    # get device name
    match = re.search(r'[0-9A-Za-z]+',file)
    if match:
        dev_name = match.group()
    else:
        return ''
            
    # get date
    match = re.search(r'([0-9]{9,10})',file)
    if match:
        timestr = match.group(1)
        date = datetime.date.fromtimestamp(float(timestr))
        datedir = str(date.year) + '/' + str(date.month)
    else:
        return ''


    # get type
    match = re.search(r'.*?[0-9]\.(.*)$',file)
    if match:
        extension = match.group(1)
        typedir = types[extension]
    else:
        return ''


    return dev_name + '/' + typedir + '/'+ datedir



def clean_data(dir,targetdir):

    UKY_DIR = os.environ['HOME'] + '/var/archive/UKY-old'
    devices = []
    measurements = []

    files = os.listdir(dir)
    for file in files:

        if os.path.isdir(dir+file):
            print 'skipping ' + dir+file
            continue


        # move the Kentucky data out
        match = re.search(r'[Uu]ky',file)
        if match:
            shutil.move(dir+file, UKY_DIR)
            continue

        # make directories and move files
        datadir = targetdir + filename_to_dir(file)

        if not os.path.exists(datadir):
            os.makedirs(datadir)

        print dir+file + '->' + datadir
        shutil.move(dir+file,datadir)


    for dev in devices:
        print dev

def new_device_files(members,device,pubdir):
    for tarinfo in members:
        match = re.search(device,tarinfo.name)
        tfile = pubdir + filename_to_dir(tarinfo.name) + '/' + tarinfo.name
        #if match:
        #    print tfile
        if match and not os.path.exists(tfile):
            yield tarinfo
        

def unpack_backup(device,dir,tmpdir,pubdir):

    # get the tarfiles in the archive
    files = os.listdir(dir)
    for file in files:
        
        # make a directory to unpack the tarfile
        try: 
            os.mkdir(tmpdir)
        except OSError:
            pass

        # look for the active measurement files
        match = re.search(r'xml.tgz',file)
        if match:
            # unpack into the unpack dir
            print file
            try:
                tar = tarfile.open(dir+file,'r:gz')

                # unpack all device files that aren't yet published into the unpack dir
                tar.extractall(tmpdir,members=new_device_files(tar,device,pubdir))
                tar.close()
            except tarfile.ReadError:
                print "Warning Read Error"

        # publish the data with the correct directory structure
        clean_data(tmpdir,pubdir)
        
        # remove the temporary dir
        shutil.rmtree(tmpdir)


if __name__ == '__main__':
    HOME = os.environ['HOME'] + '/'
    MEASURE_FILE_DIR = 'var/data/'

    ARCHIVE_DIR = HOME + MEASURE_FILE_DIR + 'old/'
    BACKUP_DIR = HOME + 'var/backup/'
    UNPACK_DIR = '/data/bismark/unpack/'

    PUBLISH_DIR = '/data/bismark/public/'

    # restore directory structure from backup
    unpack_backup('NB105',BACKUP_DIR,UNPACK_DIR,PUBLISH_DIR)    
