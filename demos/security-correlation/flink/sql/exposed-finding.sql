-- A failed scanner result and a still-open port for the same host and CVE.
-- incident_id is MD5(kind|correlation_key|sorted source event ids).

SET 'table.dml-sync' = 'false';
SET 'pipeline.name' = 'exposed-finding';
SET 'table.exec.source.idle-timeout' = '5 s';
SET 'parallelism.default' = '1';

CREATE TABLE scanner_findings (
  event_id STRING,
  `host` STRING,
  cve STRING,
  `result` STRING,
  ts STRING,
  event_time AS TO_TIMESTAMP(REPLACE(ts, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  WATERMARK FOR event_time AS event_time
) WITH (
  'connector' = 'kafka',
  'topic' = 'scanner.findings',
  'properties.bootstrap.servers' = 'broker:9092',
  'properties.group.id' = 'flink-exposed-scan',
  'scan.startup.mode' = 'earliest-offset',
  'format' = 'json',
  'json.fail-on-missing-field' = 'false',
  'json.ignore-parse-errors' = 'false'
);

CREATE TABLE exposure_observations (
  event_id STRING,
  `host` STRING,
  cve STRING,
  port_open BOOLEAN,
  ts STRING,
  event_time AS TO_TIMESTAMP(REPLACE(ts, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  WATERMARK FOR event_time AS event_time
) WITH (
  'connector' = 'kafka',
  'topic' = 'exposure.observations',
  'properties.bootstrap.servers' = 'broker:9092',
  'properties.group.id' = 'flink-exposed-obs',
  'scan.startup.mode' = 'earliest-offset',
  'format' = 'json',
  'json.fail-on-missing-field' = 'false',
  'json.ignore-parse-errors' = 'false'
);

CREATE TABLE security_incidents (
  incident_id STRING,
  kind STRING,
  correlation_key STRING,
  `window` STRING,
  source_event_ids ARRAY<STRING>,
  attributes ROW<`host` STRING, cve STRING>
) WITH (
  'connector' = 'kafka',
  'topic' = 'security.incidents',
  'properties.bootstrap.servers' = 'broker:9092',
  'format' = 'json'
);

INSERT INTO security_incidents
SELECT
  MD5(CONCAT(
    'exposed_finding|',
    CONCAT(f.`host`, '|', f.cve),
    '|',
    CASE
      WHEN f.event_id <= e.event_id THEN CONCAT(f.event_id, '|', e.event_id)
      ELSE CONCAT(e.event_id, '|', f.event_id)
    END
  )) AS incident_id,
  'exposed_finding' AS kind,
  CONCAT(f.`host`, '|', f.cve) AS correlation_key,
  '15 minutes' AS `window`,
  ARRAY[f.event_id, e.event_id] AS source_event_ids,
  CAST(ROW(f.`host`, f.cve) AS ROW<`host` STRING, cve STRING>) AS attributes
FROM scanner_findings AS f
JOIN exposure_observations AS e
  ON f.`host` = e.`host`
 AND f.cve = e.cve
 AND e.event_time BETWEEN f.event_time - INTERVAL '15' MINUTE AND f.event_time + INTERVAL '15' MINUTE
WHERE f.`result` = 'Failed'
  AND e.port_open = TRUE;
