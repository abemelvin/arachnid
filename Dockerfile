FROM neo4j
COPY conf/neo4j.conf /var/lib/neo4j/conf/neo4j.conf
ADD zeek/ /var/lib/neo4j/import/
