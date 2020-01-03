USING PERIODIC COMMIT
LOAD CSV WITH HEADERS FROM "file:///dns_resolutions.csv" AS row
MATCH (d:Domain {name: row.query})
MATCH (h:Host {name: row.answer})
MERGE (d)-[r:RESOLVES_TO]->(h)
ON CREATE SET r.resolver = row.resolver, r.first_seen = row.ts
ON MATCH SET r.last_seen = row.ts;