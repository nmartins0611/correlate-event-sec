-- Three failures, then a success from the same source, then egress from the target.
-- All of that is inside 10 minutes of the first failure.
-- incident_id is MD5 of kind, correlation_key, and the five ids in match order.

SET 'table.dml-sync' = 'false';
SET 'pipeline.name' = 'break-in';
SET 'table.exec.source.idle-timeout' = '5 s';
SET 'parallelism.default' = '1';

CREATE TABLE auth_attempts (
  event_id STRING,
  src_ip STRING,
  `host` STRING,
  account STRING,
  `result` STRING,
  ts STRING,
  event_time AS TO_TIMESTAMP(REPLACE(ts, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  WATERMARK FOR event_time AS event_time
) WITH (
  'connector' = 'kafka',
  'topic' = 'auth.attempts',
  'properties.bootstrap.servers' = 'broker:9092',
  'properties.group.id' = 'flink-breakin-attempts',
  'scan.startup.mode' = 'earliest-offset',
  'format' = 'json',
  'json.fail-on-missing-field' = 'false',
  'json.ignore-parse-errors' = 'false'
);

CREATE TABLE auth_accepted (
  event_id STRING,
  src_ip STRING,
  `host` STRING,
  account STRING,
  `result` STRING,
  ts STRING,
  event_time AS TO_TIMESTAMP(REPLACE(ts, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  WATERMARK FOR event_time AS event_time
) WITH (
  'connector' = 'kafka',
  'topic' = 'auth.accepted',
  'properties.bootstrap.servers' = 'broker:9092',
  'properties.group.id' = 'flink-breakin-accepted',
  'scan.startup.mode' = 'earliest-offset',
  'format' = 'json',
  'json.fail-on-missing-field' = 'false',
  'json.ignore-parse-errors' = 'false'
);

CREATE TABLE host_egress (
  event_id STRING,
  `host` STRING,
  src_ip STRING,
  dest_port INT,
  direction STRING,
  ts STRING,
  event_time AS TO_TIMESTAMP(REPLACE(ts, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  WATERMARK FOR event_time AS event_time
) WITH (
  'connector' = 'kafka',
  'topic' = 'host.egress',
  'properties.bootstrap.servers' = 'broker:9092',
  'properties.group.id' = 'flink-breakin-egress',
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
  attributes ROW<src_ip STRING, `host` STRING, account STRING>
) WITH (
  'connector' = 'kafka',
  'topic' = 'security.incidents',
  'properties.bootstrap.servers' = 'broker:9092',
  'format' = 'json'
);

CREATE TEMPORARY VIEW breakin_events AS
SELECT event_id, src_ip, `host`, account, event_time, 'failure' AS step
FROM auth_attempts
UNION ALL
SELECT event_id, src_ip, `host`, account, event_time, 'success' AS step
FROM auth_accepted
UNION ALL
SELECT
  event_id,
  src_ip,
  `host`,
  CAST(NULL AS STRING) AS account,
  event_time,
  'egress' AS step
FROM host_egress;

CREATE TEMPORARY VIEW breakin_matches AS
SELECT *
FROM breakin_events
MATCH_RECOGNIZE (
  PARTITION BY src_ip, `host`
  ORDER BY event_time
  MEASURES
    F1.event_id AS id1,
    F2.event_id AS id2,
    F3.event_id AS id3,
    S.event_id AS id4,
    G.event_id AS id5,
    S.account AS account
  ONE ROW PER MATCH
  AFTER MATCH SKIP PAST LAST ROW
  PATTERN (F1 F2 F3 S G) WITHIN INTERVAL '10' MINUTE
  DEFINE
    F1 AS F1.step = 'failure',
    F2 AS F2.step = 'failure',
    F3 AS F3.step = 'failure',
    S AS S.step = 'success',
    G AS G.step = 'egress'
);

INSERT INTO security_incidents
SELECT
  MD5(CONCAT(
    'break_in|',
    CONCAT(src_ip, '|', `host`),
    '|', id1, '|', id2, '|', id3, '|', id4, '|', id5
  )) AS incident_id,
  'break_in' AS kind,
  CONCAT(src_ip, '|', `host`) AS correlation_key,
  '10 minutes' AS `window`,
  ARRAY[id1, id2, id3, id4, id5] AS source_event_ids,
  CAST(ROW(src_ip, `host`, account) AS ROW<src_ip STRING, `host` STRING, account STRING>) AS attributes
FROM breakin_matches;
