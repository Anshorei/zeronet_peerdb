use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use lazy_static::lazy_static;
use log::*;
use rusqlite::{named_params, params, Connection};
use rusqlite_migration::{Migrations, M};
use thiserror::Error;
use zeronet_protocol::PeerAddr;

use super::{Hash, Peer, PeerDatabase};

// SQLite has limits, and a chunk size of 2048 is well below those limits,
// but I don't see any benefits with a higher chunk size.
const CHUNK_SIZE: usize = 2048;

fn unix_to_timestamp(seconds: i64) -> SystemTime {
  UNIX_EPOCH
    .checked_add(Duration::from_secs(seconds as u64))
    .unwrap()
}

fn timestamp_to_unix(timestamp: SystemTime) -> i64 {
  timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

lazy_static! {
  static ref MIGRATIONS: Migrations<'static> = Migrations::new(vec![M::up(
    "
    CREATE TABLE peers (
      pk INTEGER PRIMARY KEY AUTOINCREMENT,
      address TEXT UNIQUE NOT NULL,
      date_added TIMESTAMP,
      last_seen TIMESTAMP
    );
    CREATE UNIQUE INDEX peer_address_idx ON peers (address);
    CREATE TABLE hashes (
      pk INTEGER PRIMARY KEY AUTOINCREMENT,
      hash BLOB UNIQUE NOT NULL
    );
    CREATE UNIQUE INDEX hash_idx ON hashes (hash);
    CREATE TABLE peer_hashes (
      peer_pk INTEGER REFERENCES peers(pk),
      hash_pk INTEGER REFERENCES hashes(pk),
      UNIQUE(peer_pk, hash_pk)
    );
    CREATE UNIQUE INDEX peer_hash_idx ON peer_hashes (peer_pk, hash_pk);
    "
  ),]);
}

#[derive(Error, Debug)]
pub enum Error {
  #[error("error with rusqlite")]
  SQLite(#[from] rusqlite::Error),
  #[error("error with rusqlite_migrations")]
  SQLiteMigrations(#[from] rusqlite_migration::Error),
}

pub struct PeerDB {
  conn: Connection,
}

impl PeerDB {
  pub fn new(database_file: Option<PathBuf>) -> Result<PeerDB, Error> {
    let mut conn = match database_file {
      None => Connection::open_in_memory(),
      Some(path) => Connection::open(path),
    }?;

    MIGRATIONS.to_latest(&mut conn)?;

    return Ok(PeerDB { conn });
  }

  pub fn upsert_peer(&mut self, peer: &Peer) -> Result<bool, Error> {
    let date_added: i64 = self.conn.query_row(
      "
        INSERT INTO peers
          (address, date_added, last_seen)
        VALUES
          (:address, :date_added, :last_seen)
        ON CONFLICT (address) DO UPDATE SET
          last_seen = :last_seen
        RETURNING last_seen;",
      named_params! {
        ":address": peer.address.to_string(),
        ":date_added": timestamp_to_unix(peer.date_added),
        ":last_seen": timestamp_to_unix(peer.last_seen),
      },
      |row| row.get(0),
    )?;

    let date_updated = timestamp_to_unix(peer.date_added);
    let was_created = date_updated == date_added;

    return Ok(!was_created);
  }

  pub fn insert_hashes(&mut self, hashes: &[Hash]) -> Result<(), Error> {
    let mut stmt = self.conn.prepare_cached(
      "INSERT INTO hashes
        (hash)
      VALUES
        (:hash)
      ON CONFLICT (hash) DO NOTHING;",
    )?;
    for hash in hashes.iter() {
      stmt.execute(params![hash.0.as_slice()])?;
    }
    Ok(())
  }

  pub fn insert_hashes_chunked(&mut self, hashes: &[Hash]) -> Result<(), Error> {
    for chunk in hashes.chunks(CHUNK_SIZE) {
      let value_queries: Vec<String> = chunk
        .iter()
        .enumerate()
        .map(|(i, _)| format!("(:hash_{})", i))
        .collect();
      let query = format!(
        "INSERT INTO hashes
            (hash)
          VALUES {}
          ON CONFLICT (hash) DO NOTHING;",
        value_queries.join(",")
      );
      let mut stmt = self.conn.prepare(&query)?;
      for (i, hash) in chunk.iter().enumerate() {
        let hash_param_idx = stmt.parameter_index(&format!(":hash_{}", i))?.unwrap();
        stmt.raw_bind_parameter(hash_param_idx, hash.0.as_slice())?;
      }
      stmt.raw_execute()?;
    }
    Ok(())
  }

  pub fn link_hashes(&mut self, peer_address: &PeerAddr, hashes: &[Hash]) -> Result<(), Error> {
    let mut stmt = self.conn.prepare_cached(
      "
        INSERT INTO peer_hashes
          (peer_pk, hash_pk)
        VALUES (
          (SELECT pk FROM peers WHERE address = :address),
          (SELECT pk FROM hashes WHERE hash = :hash)
        )
        ON CONFLICT (peer_pk, hash_pk) DO NOTHING;",
    )?;
    for hash in hashes.iter() {
      stmt.execute(named_params![
      ":hash": hash.0.as_slice(),
      ":address": peer_address.to_string(),
      ])?;
    }
    Ok(())
  }

  pub fn link_hashes_chunked(
    &mut self,
    peer_address: &PeerAddr,
    hashes: &[Hash],
  ) -> Result<(), Error> {
    for chunk in hashes.chunks(CHUNK_SIZE) {
      let value_queries: Vec<String> = chunk.iter().enumerate().map(|(i, _)|
                format!("((SELECT pk FROM peers WHERE address = :address), (SELECT pk FROM hashes WHERE hash = :hash_{}))", i)
            ).collect();
      let query = format!(
        "
            INSERT INTO peer_hashes
              (peer_pk, hash_pk)
            VALUES {}
            ON CONFLICT (peer_pk, hash_pk) DO NOTHING;
            ",
        value_queries.join(",")
      );
      let mut stmt = self.conn.prepare(&query)?;
      let address_param_idx = stmt.parameter_index(":address")?.unwrap();
      stmt.raw_bind_parameter(address_param_idx, peer_address.to_string())?;
      for (i, hash) in chunk.iter().enumerate() {
        let hash_param_idx = stmt.parameter_index(&format!(":hash_{}", i))?.unwrap();
        stmt.raw_bind_parameter(hash_param_idx, hash.0.as_slice())?;
      }
      stmt.raw_execute()?;
    }
    Ok(())
  }
}

impl PeerDatabase for PeerDB {
  type Error = Error;

  fn update_peer(&mut self, peer: &Peer, hashes: &Vec<Hash>) -> Result<bool, Self::Error> {
    let was_known_peer = self.upsert_peer(&peer)?;
    if hashes.len() > 1 {
      self.insert_hashes_chunked(hashes.as_slice())?;
      self.link_hashes_chunked(&peer.address, hashes.as_slice())?;
    } else {
      self.insert_hashes(hashes.as_slice())?;
      self.link_hashes(&peer.address, hashes.as_slice())?;
    }

    Ok(was_known_peer)
  }

  fn remove_peer(&mut self, peer_address: &PeerAddr) -> Result<Option<Peer>, Self::Error> {
    self
      .conn
      .execute(
        "
        DELETE FROM peer_hashes
        WHERE peer_pk IN (
          SELECT pk FROM peers WHERE address = ?
        );",
        params![peer_address.to_string()],
      )
      .unwrap();
    let peer = self
      .conn
      .query_row(
        "
      DELETE FROM peers
      WHERE address = ?
      RETURNING address, date_added, last_seen;",
        params![peer_address.to_string()],
        |row| {
          let addr: String = row.get(0)?;
          Ok(Peer {
            address:    PeerAddr::parse(addr).unwrap(),
            date_added: unix_to_timestamp(row.get(1)?),
            last_seen:  unix_to_timestamp(row.get(2)?),
          })
        },
      )
      .ok();

    return Ok(peer);
  }

  fn get_peer(&self, peer_address: &PeerAddr) -> Result<Option<Peer>, Self::Error> {
    let peer = self
      .conn
      .query_row(
        "
      SELECT address, date_added, last_seen
      FROM peers
      WHERE address = ?;",
        params![peer_address.to_string()],
        |row| {
          let addr: String = row.get(0)?;
          Ok(Peer {
            address:    PeerAddr::parse(addr).unwrap(),
            date_added: unix_to_timestamp(row.get(1)?),
            last_seen:  unix_to_timestamp(row.get(2)?),
          })
        },
      )
      .ok();

    return Ok(peer);
  }

  fn get_peers(&self) -> Result<Vec<Peer>, Self::Error> {
    let mut stmt = self.conn.prepare(
      "
      SELECT address, date_added, last_seen
      FROM peers;",
    )?;
    let rows = stmt.query_map([], |row| {
      let addr: String = row.get(0)?;
      Ok(Peer {
        address:    PeerAddr::parse(addr).unwrap(),
        date_added: unix_to_timestamp(row.get(1)?),
        last_seen:  unix_to_timestamp(row.get(2)?),
      })
    })?;

    let mut peers = Vec::new();
    for row in rows {
      peers.push(row?);
    }

    return Ok(peers);
  }

  fn get_peers_for_hash(&self, hash: &Hash) -> Result<Vec<Peer>, Self::Error> {
    let mut stmt = self.conn.prepare(
      "
      SELECT address, date_added, last_seen
      FROM hashes h
        INNER JOIN peer_hashes ph ON (h.pk = ph.hash_pk)
        LEFT JOIN peers p ON (p.pk = ph.peer_pk)
      WHERE hash = ?;",
    )?;

    let rows = stmt.query_map(params![hash.0.as_slice()], |row| {
      let addr: String = row.get(0)?;
      Ok(Peer {
        address:    PeerAddr::parse(addr).unwrap(),
        date_added: unix_to_timestamp(row.get(1)?),
        last_seen:  unix_to_timestamp(row.get(2)?),
      })
    })?;

    let mut peers = Vec::new();
    for row in rows {
      peers.push(row?);
    }

    return Ok(peers);
  }

  fn get_hashes(&self) -> Result<Vec<(Hash, usize)>, Self::Error> {
    let mut stmt = self.conn.prepare(
      "
      SELECT hash, COUNT(peer_pk)
      FROM hashes h
        INNER JOIN peer_hashes ph ON (h.pk = ph.hash_pk)
      GROUP BY (hash);",
    )?;
    let rows = stmt.query_map([], |row| Ok((Hash(row.get(0)?), row.get(1)?)))?;

    let mut hashes = Vec::new();
    for row in rows {
      hashes.push(row?);
    }

    return Ok(hashes);
  }

  fn get_peer_count(&self) -> Result<usize, Self::Error> {
    let count = self
      .conn
      .query_row("SELECT COUNT(pk) FROM peers;", [], |row| row.get(0))?;

    Ok(count)
  }

  fn get_hash_count(&self) -> Result<usize, Self::Error> {
    let count: usize = self
      .conn
      .query_row("SELECT COUNT(pk) FROM hashes;", [], |row| row.get(0))?;

    Ok(count)
  }

  fn cleanup_peers(&mut self, timestamp: SystemTime) -> Result<usize, Self::Error> {
    let count: usize = self.conn.execute(
      "
      DELETE FROM peer_hashes WHERE peer_pk IN (SELECT pk FROM peers WHERE last_seen < :timestamp);
      DELETE FROM peers WHERE last_seen < :timestamp;",
      named_params![":timestamp": timestamp_to_unix(timestamp),],
    )?;

    Ok(count)
  }

  fn cleanup_hashes(&mut self) -> Result<usize, Self::Error> {
    let count: usize = self.conn.execute(
      "
      DELETE FROM hashes
      WHERE pk IN (
        SELECT pk FROM (
          SELECT hash_pk pk, COUNT(peer_pk) count FROM peer_hashes
        )
        WHERE count = 0
      );",
      [],
    )?;

    Ok(count)
  }
}
