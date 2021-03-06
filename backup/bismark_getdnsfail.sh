#!/bin/bash


for i in 2011 2012 2013 2014 2015 2016 2017 2018 2019 2019; do
l=$(expr $i + 1)
psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select deviceid,srcip,dstip,eventstamp,average,std,minimum,maximum,median,iqr,exitstatus,toolid from m_dnsfailc where eventstamp < '"$l"-01-01 00:00:00' and eventstamp >= '"$i"-01-01 00:00:00') to '/scratch/csv/bismark/live/bismark_m_dnsfailc_"$i".csv' with delimiter ';' csv header;"
done
psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select deviceid,srcip,dstip,eventstamp,average,std,minimum,maximum,median,iqr,exitstatus,toolid from m_dnsfailc where eventstamp < '2019-02-01 00:00:00' and eventstamp >= '2019-01-01 00:00:00' limit 100) to '/scratch/csv/bismark/live/bismark_m_dnsfailc_sample.csv' with delimiter ';' csv header;"
