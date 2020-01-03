USING PERIODIC COMMIT
LOAD CSV WITH HEADERS FROM "file:///domains.csv" AS row
MERGE (d:Domain {name: row.name});