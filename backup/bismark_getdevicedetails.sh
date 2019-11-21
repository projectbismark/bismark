#!/bin/bash

psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select deviceid,name,isp,serviceplan,uploadrate,downloadrate,city,state,country,eventstamp,latitude,longitude,is_default,servicetype,geoip_country,geoip_city,geoip_isp,country_code from devicedetails) to '/scratch/csv/bismark/live/bismark_devicedetails_all.csv' with delimiter ';' csv header;"

psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select deviceid,name,isp,serviceplan,uploadrate,downloadrate,city,state,country,eventstamp,latitude,longitude,is_default,servicetype,geoip_country,geoip_city,geoip_isp,country_code from devicedetails limit 100) to '/scratch/csv/bismark/live/bismark_devicedetails_sample.csv' with delimiter ';' csv header;"
