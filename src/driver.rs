use irodori_connector_abi::{collect_url_auth, option_string, push_sensitive};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, OnceLock};

use scylla::client::session::Session;
use scylla::client::session_builder::SessionBuilder;
use scylla::value::{CqlValue, Row};
use serde_json::{json, Map, Value};
use tokio::runtime::Runtime;

use crate::abi::{self, IrodoriConnectorBuffer};
use crate::{ABI_VERSION, CONFIG_JSON, DRIVER_LINKED, ENGINE, MANIFEST_JSON};

static CONNECTIONS: OnceLock<Mutex<HashMap<String, CassandraConnection>>> = OnceLock::new();
static RUNTIME: OnceLock<Runtime> = OnceLock::new();

#[derive(Clone)]
struct CassandraConnection {
    session: Arc<Session>,
    config: CassandraConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CassandraConfig {
    node: String,
    keyspace: Option<String>,
    username: Option<String>,
    password: Option<String>,
    redaction_values: Vec<String>,
}

type QueryRows = Vec<Vec<Value>>;
type QueryOutput = (Vec<String>, QueryRows, bool);

fn connections() -> &'static Mutex<HashMap<String, CassandraConnection>> {
    CONNECTIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn runtime() -> Result<&'static Runtime, String> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = Runtime::new().map_err(|err| format!("create tokio runtime failed: {err}"))?;
    let _ = RUNTIME.set(runtime);
    RUNTIME
        .get()
        .ok_or_else(|| "create tokio runtime failed.".to_string())
}

pub fn call_json(request: IrodoriConnectorBuffer) -> IrodoriConnectorBuffer {
    let request = match abi::parse_request(request) {
        Ok(request) => request,
        Err(response) => return response,
    };
    let method = match abi::request_method(request.as_ref()) {
        Ok(method) => method,
        Err(response) => return response,
    };

    match method {
        "health" | "ping" => abi::ok(Map::from_iter([
            ("engine".to_string(), Value::String(ENGINE.to_string())),
            ("abiVersion".to_string(), json!(ABI_VERSION)),
            ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
        ])),
        "describe" | "capabilities" => abi::ok(Map::from_iter([
            ("engine".to_string(), Value::String(ENGINE.to_string())),
            ("abiVersion".to_string(), json!(ABI_VERSION)),
            ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
            (
                "manifest".to_string(),
                serde_json::from_str(MANIFEST_JSON).unwrap_or(Value::Null),
            ),
            (
                "config".to_string(),
                serde_json::from_str(CONFIG_JSON).unwrap_or(Value::Null),
            ),
        ])),
        "manifest" => abi::owned_buffer(MANIFEST_JSON.to_string()),
        "config" => abi::owned_buffer(CONFIG_JSON.to_string()),
        "connect" => connect(request.as_ref().expect("connect has request")),
        "query" => query(request.as_ref().expect("query has request")),
        "metadata" => metadata(request.as_ref().expect("metadata has request")),
        "close" => close(request.as_ref().expect("close has request")),
        other => abi::error(
            "connector.unknownMethod",
            format!("unknown connector method: {other}"),
        ),
    }
}

fn connect(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let config = match CassandraConfig::from_request(request) {
        Ok(config) => config,
        Err(err) => return abi::error("connector.invalidRequest", err),
    };
    let connection =
        match runtime().and_then(|runtime| runtime.block_on(CassandraConnection::new(config))) {
            Ok(connection) => connection,
            Err(err) => return abi::error("connector.connectFailed", err),
        };
    let version = match runtime().and_then(|runtime| runtime.block_on(load_version(&connection))) {
        Ok(version) => version,
        Err(err) => return abi::error("connector.connectFailed", connection.config.redact(&err)),
    };
    let mut guard = match connections().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    let mut response = Map::from_iter([
        ("engine".to_string(), Value::String(ENGINE.to_string())),
        (
            "connectionId".to_string(),
            Value::String(connection_id.clone()),
        ),
        ("driverLinked".to_string(), Value::Bool(DRIVER_LINKED)),
        (
            "node".to_string(),
            Value::String(connection.config.node.clone()),
        ),
        ("serverVersion".to_string(), Value::String(version)),
    ]);
    if let Some(keyspace) = connection.config.keyspace.as_deref() {
        response.insert("keyspace".to_string(), Value::String(keyspace.to_string()));
    }
    guard.insert(connection_id, connection);
    abi::ok(response)
}

fn query(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let Some(sql) = abi::string_field(request, "sql")
        .or_else(|| abi::string_field(request, "query"))
        .or_else(|| abi::string_field(request, "statement"))
    else {
        return abi::error(
            "connector.invalidRequest",
            "query requires a string sql, query, or statement field.",
        );
    };
    let connection = match connection(&connection_id) {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    match runtime()
        .and_then(|runtime| runtime.block_on(run_query(&connection, sql, abi::max_rows(request))))
    {
        Ok((columns, rows, truncated)) => abi::ok(Map::from_iter([
            ("connectionId".to_string(), Value::String(connection_id)),
            (
                "columns".to_string(),
                Value::Array(columns.into_iter().map(Value::String).collect()),
            ),
            (
                "rows".to_string(),
                Value::Array(rows.into_iter().map(Value::Array).collect()),
            ),
            ("truncated".to_string(), Value::Bool(truncated)),
        ])),
        Err(err) => abi::error("connector.queryFailed", connection.config.redact(&err)),
    }
}

fn metadata(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let connection = match connection(&connection_id) {
        Ok(connection) => connection,
        Err(response) => return response,
    };
    match runtime().and_then(|runtime| runtime.block_on(load_metadata(&connection))) {
        Ok(metadata) => abi::ok(Map::from_iter([
            ("connectionId".to_string(), Value::String(connection_id)),
            ("metadata".to_string(), metadata),
        ])),
        Err(err) => abi::error("connector.metadataFailed", connection.config.redact(&err)),
    }
}

fn close(request: &Value) -> IrodoriConnectorBuffer {
    let connection_id = abi::connection_id(Some(request));
    let mut guard = match connections().lock() {
        Ok(guard) => guard,
        Err(_) => {
            return abi::error(
                "connector.statePoisoned",
                "Connector connection state is poisoned.",
            )
        }
    };
    let existed = guard.remove(&connection_id).is_some();
    abi::ok(Map::from_iter([
        ("connectionId".to_string(), Value::String(connection_id)),
        ("closed".to_string(), Value::Bool(existed)),
    ]))
}

impl CassandraConnection {
    async fn new(config: CassandraConfig) -> Result<Self, String> {
        let mut builder = SessionBuilder::new().known_node(config.node.clone());
        if let (Some(username), Some(password)) = (config.username.clone(), config.password.clone())
        {
            builder = builder.user(username, password);
        }
        let session = builder
            .build()
            .await
            .map_err(|err| config.redact(&format!("Cassandra connect failed: {err}")))?;
        if let Some(keyspace) = config.keyspace.as_deref().filter(|value| !value.is_empty()) {
            if keyspace != "system" {
                session
                    .use_keyspace(keyspace, false)
                    .await
                    .map_err(|err| config.redact(&format!("select keyspace failed: {err}")))?;
            }
        }
        Ok(Self {
            session: Arc::new(session),
            config,
        })
    }
}

impl CassandraConfig {
    fn from_request(request: &Value) -> Result<Self, String> {
        let node = option_string(request, &["connectionString", "url", "dsn"])
            .and_then(|value| node_from_url(&value))
            .unwrap_or_else(|| {
                let host = option_string(request, &["host", "endpoint"])
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                let port = option_string(request, &["port"]).unwrap_or_else(|| "9042".to_string());
                format!("{host}:{port}")
            });
        let keyspace = option_string(request, &["keyspace", "database", "db"]);
        let username = option_string(request, &["user", "username"]);
        let password = option_string(request, &["password", "token"]);
        let mut redaction_values = Vec::new();
        push_sensitive(&mut redaction_values, password.as_deref());
        collect_url_auth(&node, &mut redaction_values);
        Ok(Self {
            node,
            keyspace,
            username,
            password,
            redaction_values,
        })
    }

    fn redact(&self, message: &str) -> String {
        self.redaction_values.iter().fold(
            message.replace(&self.node, "<cassandra-node>"),
            |message, secret| {
                if secret.is_empty() {
                    message
                } else {
                    message.replace(secret, "****")
                }
            },
        )
    }
}

async fn load_version(connection: &CassandraConnection) -> Result<String, String> {
    let res = connection
        .session
        .query_unpaged("SELECT release_version FROM system.local", &[])
        .await
        .map_err(|err| format!("version query failed: {err}"))?;
    if let Ok(rows_result) = res.into_rows_result() {
        if let Ok(mut rows) = rows_result.rows::<Row>() {
            if let Some(Ok(row)) = rows.next() {
                if let Some(Some(value)) = row.columns.first() {
                    return Ok(format!("{ENGINE} {}", value_to_string(value)));
                }
            }
        }
    }
    Ok(ENGINE.to_string())
}

async fn run_query(
    connection: &CassandraConnection,
    sql: &str,
    cap: usize,
) -> Result<QueryOutput, String> {
    let res = connection
        .session
        .query_unpaged(sql, &[])
        .await
        .map_err(|err| format!("CQL query failed: {err}"))?;
    let mut columns = Vec::new();
    let mut rows = Vec::new();
    let mut truncated = false;
    if res.is_rows() {
        let rows_result = res.into_rows_result().map_err(|err| err.to_string())?;
        columns = rows_result
            .column_specs()
            .iter()
            .map(|column| column.name().to_string())
            .collect();
        let res_rows = rows_result.rows::<Row>().map_err(|err| err.to_string())?;
        for row in res_rows {
            if rows.len() >= cap {
                truncated = true;
                break;
            }
            let row = row.map_err(|err| err.to_string())?;
            rows.push(
                row.columns
                    .iter()
                    .map(|value| value.as_ref().map(cql_value_to_json).unwrap_or(Value::Null))
                    .collect(),
            );
        }
    }
    Ok((columns, rows, truncated))
}

async fn load_metadata(connection: &CassandraConnection) -> Result<Value, String> {
    let (columns, rows, _) = run_query(
        connection,
        "SELECT keyspace_name, table_name, column_name, type FROM system_schema.columns",
        100_000,
    )
    .await?;
    let mut schemas: BTreeMap<String, BTreeMap<String, Vec<Value>>> = BTreeMap::new();
    for row in rows {
        let keyspace = field(&columns, &row, "keyspace_name").unwrap_or_default();
        let table = field(&columns, &row, "table_name").unwrap_or_default();
        let column = field(&columns, &row, "column_name").unwrap_or_default();
        if keyspace.is_empty() || table.is_empty() || column.is_empty() {
            continue;
        }
        let object_columns = schemas
            .entry(keyspace)
            .or_default()
            .entry(table)
            .or_default();
        object_columns.push(json!({
            "name": column,
            "dataType": field(&columns, &row, "type").unwrap_or_else(|| "text".to_string()),
            "nullable": true,
            "ordinal": object_columns.len() + 1
        }));
    }
    Ok(json!({
        "schemas": schemas
            .into_iter()
            .map(|(schema, objects)| json!({
                "name": schema,
                "objects": objects
                    .into_iter()
                    .map(|(name, columns)| json!({
                        "schema": schema,
                        "name": name,
                        "kind": "table",
                        "columns": columns,
                        "indexes": [],
                        "primaryKey": [],
                        "foreignKeys": []
                    }))
                    .collect::<Vec<_>>()
            }))
            .collect::<Vec<_>>()
    }))
}

fn cql_value_to_json(value: &CqlValue) -> Value {
    match value {
        CqlValue::Ascii(value) | CqlValue::Text(value) => Value::String(value.clone()),
        CqlValue::Int(value) => json!(value),
        CqlValue::BigInt(value) => json!(value),
        CqlValue::Boolean(value) => Value::Bool(*value),
        CqlValue::Double(value) => json!(value),
        CqlValue::Float(value) => json!(*value as f64),
        _ => Value::String(format!("{value:?}")),
    }
}

fn value_to_string(value: &CqlValue) -> String {
    match cql_value_to_json(value) {
        Value::String(value) => value,
        other => other.to_string(),
    }
}

fn field(columns: &[String], row: &[Value], name: &str) -> Option<String> {
    columns
        .iter()
        .position(|column| column.eq_ignore_ascii_case(name))
        .and_then(|index| row.get(index))
        .and_then(|value| match value {
            Value::Null => None,
            Value::String(value) => Some(value.clone()),
            other => Some(other.to_string()),
        })
}

fn connection(connection_id: &str) -> Result<CassandraConnection, IrodoriConnectorBuffer> {
    let guard = connections().lock().map_err(|_| {
        abi::error(
            "connector.statePoisoned",
            "Connector connection state is poisoned.",
        )
    })?;
    guard.get(connection_id).cloned().ok_or_else(|| {
        abi::error(
            "connector.connectionNotFound",
            format!("no open connection: {connection_id}"),
        )
    })
}

fn node_from_url(value: &str) -> Option<String> {
    let without_scheme = value
        .strip_prefix("cassandra://")
        .or_else(|| value.strip_prefix("scylla://"))
        .or_else(|| value.strip_prefix("scylladb://"))
        .unwrap_or(value);
    let host_port = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split('@')
        .next_back()
        .unwrap_or(without_scheme);
    (!host_port.trim().is_empty()).then(|| host_port.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_node_from_url() {
        assert_eq!(
            node_from_url("cassandra://user:pass@localhost:9042/keyspace"),
            Some("localhost:9042".to_string())
        );
    }

    #[test]
    fn converts_cql_values() {
        assert_eq!(
            cql_value_to_json(&CqlValue::Text("x".to_string())),
            json!("x")
        );
        assert_eq!(cql_value_to_json(&CqlValue::Int(3)), json!(3));
    }
}
