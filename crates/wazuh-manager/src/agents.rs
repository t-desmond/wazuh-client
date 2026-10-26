//! Agents resource (feature: `agents`).
//!
//! Only what you need today: list agents, get one by id, and a lazy streaming
//! iterator over all agents. Uses a params struct instead of positional
//! `Option` arguments (an anti-pattern in `wazuh-client-rs`).

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use wazuh_core::WazuhError;

use crate::client::{BulkResponse, HttpMethod, ManagerClient, Query};

/// A Wazuh agent.
///
/// Unknown fields are preserved in `extra` for forward compatibility rather
/// than being dropped.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Agent {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub os: Option<AgentOs>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub group: Option<Vec<String>>,
    #[serde(default)]
    pub last_keepalive: Option<String>,
    #[serde(default)]
    pub date_add: Option<String>,
    /// Any fields not modeled above, preserved for forward compatibility.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentOs {
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
}

/// Query parameters for `GET /agents`.
#[derive(Debug, Default, Clone)]
pub struct ListAgentsParams {
    pub limit: Option<u32>,
    pub offset: Option<u64>,
    pub status: Option<String>,
    pub group: Option<String>,
    pub search: Option<String>,
    pub older_than: Option<String>,
    pub select: Option<Vec<String>>,
    pub sort: Option<String>,
}

impl ListAgentsParams {
    pub fn to_query(&self) -> Query {
        let mut q: Query = Vec::new();
        if let Some(v) = self.limit {
            q.push(("limit".into(), v.to_string()));
        }
        if let Some(v) = self.offset {
            q.push(("offset".into(), v.to_string()));
        }
        if let Some(v) = &self.status {
            q.push(("status".into(), v.clone()));
        }
        if let Some(v) = &self.group {
            q.push(("group".into(), v.clone()));
        }
        if let Some(v) = &self.search {
            q.push(("search".into(), v.clone()));
        }
        if let Some(v) = &self.older_than {
            q.push(("older_than".into(), v.clone()));
        }
        if let Some(items) = &self.select {
            q.push(("select".into(), items.join(",")));
        }
        if let Some(v) = &self.sort {
            q.push(("sort".into(), v.clone()));
        }
        q
    }
}

impl ManagerClient {
    /// List agents matching `params`.
    pub async fn list_agents(
        &self,
        params: &ListAgentsParams,
    ) -> Result<BulkResponse<Agent>, WazuhError> {
        let q = params.to_query();
        self.request(HttpMethod::Get, "/agents", Some(&q), None)
            .await?
            .into_bulk()
    }

    /// Get a single agent by id.
    pub async fn get_agent(&self, id: &str) -> Result<Agent, WazuhError> {
        let q = vec![("agents_list".into(), id.to_string())];
        let mut bulk: BulkResponse<Agent> = self
            .request(HttpMethod::Get, "/agents", Some(&q), None)
            .await?
            .into_bulk()?;
        bulk.affected_items
            .pop()
            .ok_or_else(|| WazuhError::NotFound {
                resource: "agent".into(),
                id: id.to_string(),
            })
    }

    /// Lazily iterate over all agents, fetching pages of `page_size` on demand.
    ///
    /// Note: Wazuh pagination is offset-based, not cursor-based, so results can
    /// shift if agents change mid-iteration.
    pub fn stream_agents(&self, params: ListAgentsParams) -> AgentStream<'_> {
        AgentStream::new(self, params)
    }
}

/// Lazy streaming iterator over agents (offset pagination, "short page ⇒ stop").
pub struct AgentStream<'a> {
    client: &'a ManagerClient,
    params: ListAgentsParams,
    offset: u64,
    page_size: u32,
    buffer: VecDeque<Agent>,
    done: bool,
}

impl<'a> AgentStream<'a> {
    pub fn new(client: &'a ManagerClient, params: ListAgentsParams) -> Self {
        Self {
            client,
            params,
            offset: 0,
            page_size: 500,
            buffer: VecDeque::new(),
            done: false,
        }
    }

    /// Fetch the next agent, or `None` when exhausted.
    pub async fn next(&mut self) -> Result<Option<Agent>, WazuhError> {
        loop {
            if let Some(agent) = self.buffer.pop_front() {
                return Ok(Some(agent));
            }
            if self.done {
                return Ok(None);
            }

            let mut page_params = self.params.clone();
            page_params.limit = Some(self.page_size);
            page_params.offset = Some(self.offset);

            let bulk = self.client.list_agents(&page_params).await?;
            self.offset += bulk.affected_items.len() as u64;
            if bulk.affected_items.len() < self.page_size as usize {
                self.done = true;
            }
            self.buffer.extend(bulk.affected_items);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_query_only_includes_set_fields() {
        let params = ListAgentsParams {
            status: Some("active".into()),
            limit: Some(10),
            ..Default::default()
        };
        let q = params.to_query();
        assert_eq!(q, vec![("limit".into(), "10".into()), ("status".into(), "active".into())]);
    }

    #[test]
    fn to_query_joins_select() {
        let params = ListAgentsParams {
            select: Some(vec!["id".into(), "name".into()]),
            ..Default::default()
        };
        let q = params.to_query();
        assert_eq!(q, vec![("select".into(), "id,name".into())]);
    }
}
