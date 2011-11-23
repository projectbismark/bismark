CREATE SCHEMA public;

CREATE DOMAIN id_t AS varchar(50);
CREATE DOMAIN inetn_t AS inet;
CREATE DOMAIN version_t AS varchar(50);
CREATE DOMAIN user_t AS varchar(50);
CREATE DOMAIN ip_t AS inet;
CREATE DOMAIN ts_t AS integer;
CREATE DOMAIN cat_t AS varchar(50);
CREATE DOMAIN msg_from_t AS varchar(50);
CREATE DOMAIN msg_to_t AS varchar(50);
CREATE DOMAIN msg_t AS varchar(100);
CREATE DOMAIN zone_t AS varchar(50);
CREATE DOMAIN cli_t AS integer;
CREATE DOMAIN prio_t AS integer;
CREATE DOMAIN info_t AS varchar(500);
CREATE DOMAIN mtype_t AS varchar(50);
CREATE DOMAIN mexc_t AS int;

CREATE TABLE  devices(
                id     		id_t,
                bversion 	version_t, 
                duser    	user_t, 
                ip      	ip_t, 
                ts      	ts_t
              	);

CREATE TABLE  tunnels(
                id 	id_t,
                port 	INTEGER, 
                ts 	ts_t 
               );

CREATE TABLE messages(
		rowid		serial,
                msgfrom 	msg_from_t,
                msgto   	msg_to_t, 
                msg 		msg_t 
               );

CREATE TABLE targets(
                ip       ip_t,
                cat      cat_t, 
                zone     zone_t,
                free_ts  ts_t,
                curr_cli cli_t,
                max_cli  cli_t
		);

CREATE TABLE device_targets(
		device		id_t,
		server		ip_t,
		priority	prio_t
		);

CREATE TABLE capabilities(
                ip      ip_t,
                service	mtype_t,
                info 	info_t	    
               );

CREATE TABLE mtypes(
                mtype       mtype_t PRIMARY KEY,
                mexclusive  mexc_t
               );

CREATE TABLE  blacklist(
                id     		id_t
		);
 
