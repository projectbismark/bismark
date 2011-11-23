all: create

create:
	psql -U bismark -f tables.sql $(DB)

createall: clean create 

functions:

clean:
	psql -U bismark -c 'DROP SCHEMA public CASCADE' $(DB)
