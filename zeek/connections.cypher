USING PERIODIC COMMIT
LOAD CSV WITH HEADERS FROM "file:///connections.csv" AS row
MATCH (h1:Host {name: row.originator})
MATCH (h2:Host {name: row.responder})
MERGE (h1)-[r:CONNECTS_TO]->(h2)
ON CREATE SET r.port = row.port, r.proto = row.proto, r.state = row.state, r.first_seen = row.ts
ON MATCH SET r.last_seen = row.ts;