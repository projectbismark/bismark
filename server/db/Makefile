all: create

create:
	psql -f tables.sql $(DB)

createall: clean create 

functions:

clean:
	psql -c 'DROP SCHEMA public CASCADE' $(DB)
