-- A change with no approval window covering its timestamp.
-- Absence means no matching approval is in this job's state.
-- incident_id is MD5(kind|correlation_key|sorted source event ids).

SET 'table.dml-sync' = 'false';
SET 'pipeline.name' = 'change-outside-window';
SET 'table.exec.source.idle-timeout' = '5 s';
SET 'parallelism.default' = '1';

CREATE TABLE changes_applied (
  event_id STRING,
  `host` STRING,
  `change` STRING,
  actor STRING,
  ts STRING,
  event_time AS TO_TIMESTAMP(REPLACE(ts, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  WATERMARK FOR event_time AS event_time
) WITH (
  'connector' = 'kafka',
  'topic' = 'changes.applied',
  'properties.bootstrap.servers' = 'broker:9092',
  'properties.group.id' = 'flink-change-applied',
  'scan.startup.mode' = 'earliest-offset',
  'format' = 'json',
  'json.fail-on-missing-field' = 'false',
  'json.ignore-parse-errors' = 'false'
);

CREATE TABLE changes_approvals (
  event_id STRING,
  `host` STRING,
  `start` STRING,
  `end` STRING,
  event_time AS TO_TIMESTAMP(REPLACE(`start`, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  window_end AS TO_TIMESTAMP(REPLACE(`end`, 'Z', ''), 'yyyy-MM-dd''T''HH:mm:ss'),
  WATERMARK FOR event_time AS event_time
) WITH (
  'connector' = 'kafka',
  'topic' = 'changes.approvals',
  'properties.bootstrap.servers' = 'broker:9092',
  'properties.group.id' = 'flink-change-approval',
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
  attributes ROW<`host` STRING, `change` STRING, actor STRING>
) WITH (
  'connector' = 'kafka',
  'topic' = 'security.incidents',
  'properties.bootstrap.servers' = 'broker:9092',
  'format' = 'json'
);

CREATE TEMPORARY VIEW change_events AS
SELECT
  event_id,
  `host`,
  `change` AS change_name,
  actor,
  event_time,
  CAST(NULL AS TIMESTAMP(3)) AS window_start,
  CAST(NULL AS TIMESTAMP(3)) AS window_end,
  'change' AS step
FROM changes_applied
UNION ALL
SELECT
  event_id,
  `host`,
  CAST(NULL AS STRING) AS change_name,
  CAST(NULL AS STRING) AS actor,
  event_time,
  event_time AS window_start,
  window_end,
  'approval' AS step
FROM changes_approvals;

INSERT INTO security_incidents
SELECT
  MD5(CONCAT(
    'change_outside_window|',
    CONCAT(host_name, '|', event_id),
    '|',
    event_id
  )) AS incident_id,
  'change_outside_window' AS kind,
  CONCAT(host_name, '|', event_id) AS correlation_key,
  'approval overlap' AS `window`,
  ARRAY[event_id] AS source_event_ids,
  CAST(ROW(host_name, change_name, actor) AS ROW<`host` STRING, `change` STRING, actor STRING>) AS attributes
FROM (
  SELECT *
  FROM change_events
  MATCH_RECOGNIZE (
    PARTITION BY `host`
    ORDER BY event_time
    MEASURES
      C.event_id AS event_id,
      C.`host` AS host_name,
      C.change_name AS change_name,
      C.actor AS actor,
      C.event_time AS change_time,
      COUNT(A.event_id) AS approval_rows,
      MIN(A.window_start) AS earliest_start,
      MAX(A.window_end) AS latest_end
    ONE ROW PER MATCH
    AFTER MATCH SKIP PAST LAST ROW
    PATTERN (A* C)
    DEFINE
      A AS A.step = 'approval',
      C AS C.step = 'change'
  )
)
WHERE approval_rows = 0
   OR change_time < earliest_start
   OR change_time > latest_end;
