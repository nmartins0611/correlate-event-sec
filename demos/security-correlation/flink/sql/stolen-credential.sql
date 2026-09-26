-- A failed login and a later secret read for the same identity.
-- incident_id is MD5(kind|correlation_key|sorted source event ids).

SET 'table.dml-sync' = 'false';
SET 'pipeline.name' = 'stolen-credential';
SET 'table.exec.source.idle-timeout' = '5 s';
SET 'parallelism.default' = '1';

CREATE TABLE auth_failures (
  event_id STRING,
  `identity` STRING,
  `host` STRING,
  `result` STRING,
  ts STRING,
  event_time AS TO_TIMESTAMP(REPLACE(ts, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  WATERMARK FOR event_time AS event_time
) WITH (
  'connector' = 'kafka',
  'topic' = 'auth.failures',
  'properties.bootstrap.servers' = 'broker:9092',
  'properties.group.id' = 'flink-stolen-auth',
  'scan.startup.mode' = 'earliest-offset',
  'format' = 'json',
  'json.fail-on-missing-field' = 'false',
  'json.ignore-parse-errors' = 'false'
);

CREATE TABLE vault_audit (
  event_id STRING,
  `identity` STRING,
  `path` STRING,
  operation STRING,
  ts STRING,
  event_time AS TO_TIMESTAMP(REPLACE(ts, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  WATERMARK FOR event_time AS event_time
) WITH (
  'connector' = 'kafka',
  'topic' = 'vault.audit',
  'properties.bootstrap.servers' = 'broker:9092',
  'properties.group.id' = 'flink-stolen-vault',
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
  attributes ROW<`identity` STRING, `path` STRING>
) WITH (
  'connector' = 'kafka',
  'topic' = 'security.incidents',
  'properties.bootstrap.servers' = 'broker:9092',
  'format' = 'json'
);

INSERT INTO security_incidents
SELECT
  MD5(CONCAT(
    'stolen_credential|',
    a.`identity`,
    '|',
    CASE
      WHEN a.event_id <= v.event_id THEN CONCAT(a.event_id, '|', v.event_id)
      ELSE CONCAT(v.event_id, '|', a.event_id)
    END
  )) AS incident_id,
  'stolen_credential' AS kind,
  a.`identity` AS correlation_key,
  '5 minutes' AS `window`,
  ARRAY[a.event_id, v.event_id] AS source_event_ids,
  CAST(ROW(a.`identity`, v.`path`) AS ROW<`identity` STRING, `path` STRING>) AS attributes
FROM auth_failures AS a
JOIN vault_audit AS v
  ON a.`identity` = v.`identity`
 AND v.event_time BETWEEN a.event_time + INTERVAL '1' SECOND AND a.event_time + INTERVAL '5' MINUTE
WHERE a.`result` = 'failure'
  AND v.operation = 'read';
