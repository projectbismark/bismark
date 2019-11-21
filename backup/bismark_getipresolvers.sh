#!/bin/bash

psql -h ns2 -U bismark_wrt_admin -d bismark_openwrt_live_v0_1 -c "\\copy (select * from ip_resolver) to '/scratch/csv/bismark/live/bismark_ipresolvers_all.csv' with delimiter ';' csv header;"
