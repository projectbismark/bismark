#!/bin/bash


for i in 2011 2012 2013 2014 2015 2016 2017 2018 2019 2019; do
l=$(expr $i + 1)
#psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select deviceid,srcip,dstip,eventstamp,average,std,minimum,maximum,median,iqr,exitstatus,direction,toolid from m_bitrate where eventstamp < '"$l"-01-01 00:00:00' and eventstamp >= '"$i"-01-01 00:00:00' and average > 0.0) to '/scratch/csv/bismark/live/bismark_m_bitrate_"$i".csv' with delimiter ';' csv header;"
psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select h.hop,h.ip,h.rtt,t.direction,t.srcip,t.dstip,t.eventstamp from traceroute_hops as h, traceroutes as t where h.id = t.id and eventstamp < '"$l"-01-01 00:00:00' and eventstamp >= '"$i"-01-01 00:00:00') to /scratch/csv/bismark/live/bismark_traceroute_"$i".csv with delimiter ';' csv header"
done
#psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select deviceid,srcip,dstip,eventstamp,average,std,minimum,maximum,median,iqr,exitstatus,direction,toolid from m_bitrate where eventstamp < '2019-02-01 00:00:00' and eventstamp >= '2019-01-01 00:00:00' and average > 0.0 limit 100) to '/scratch/csv/bismark/live/bismark_m_bitrate_sample.csv' with delimiter ';' csv header;"

psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select h.hop,h.ip,h.rtt,t.direction,t.srcip,t.dstip,t.eventstamp from traceroute_hops as h, traceroutes as t where h.id = t.id and eventstamp < '2014-01-01 00:00:00' and eventstamp >= '2013-01-01 00:00:00' limit 100) to /scratch/csv/bismark/live/bismark_traceroute_sample.csv with delimiter ';' csv header"
#psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select h.hop,h.ip,h.rtt,t.direction,t.srcip,t.dstip,t.eventstamp from traceroute_hops as h, traceroutes as t where h.id = t.id limit 100) to /scratch/csv/bismark/live/bismark_traceroute_sample.csv with delimiter ';' csv header"
