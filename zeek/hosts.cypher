USING PERIODIC COMMIT
LOAD CSV WITH HEADERS FROM "file:///hosts.csv" AS row
MERGE (h:Host {name: row.name})
ON CREATE
SET h.type = row.type;