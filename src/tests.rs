use std::time::{SystemTime, Duration};

use zeronet_protocol::PeerAddr;

#[cfg(not(feature = "sql"))]
use crate::basic::PeerDB;
#[cfg(feature = "sql")]
use crate::sqlite::PeerDB;
use crate::{Hash, Peer, PeerDatabase};

#[cfg(not(feature = "sql"))]
fn get_peerdb() -> PeerDB {
  return PeerDB::new().unwrap();
}

#[cfg(feature = "sql")]
fn get_peerdb() -> PeerDB {
  return PeerDB::new(None).unwrap();
}

fn generate_hash() -> Hash {
  let hash = (0..8).map(|_| rand::random()).collect();
  return Hash(hash);
}

fn generate_peer_address() -> PeerAddr {
  return PeerAddr::IPV4(
    [
      rand::random(),
      rand::random(),
      rand::random(),
      rand::random(),
    ],
    rand::random(),
  );
}

fn generate_peer() -> Peer {
  return Peer {
    address:    generate_peer_address(),
    last_seen:  SystemTime::now(),
    date_added: SystemTime::now(),
  };
}

#[test]
fn test_update_peer() {
  use std::time::Duration;

  let mut peer_db = get_peerdb();
  let hashes = vec![Hash(vec![0u8])];
  let peer1 = Peer {
    address:    PeerAddr::parse("127.0.0.1:11111").unwrap(),
    last_seen:  SystemTime::now(),
    date_added: SystemTime::now(),
  };
  let peer2 = Peer {
    date_added: SystemTime::now() + Duration::from_secs(5),
    ..peer1.clone()
  };

  assert_eq!(
    peer_db.update_peer(&peer1, &hashes).unwrap(),
    false,
    "Peer inserted"
  );
  assert_eq!(
    peer_db.update_peer(&peer2, &hashes).unwrap(),
    true,
    "Peer updated"
  );
}

#[test]
fn test_remove_peer() {
  let mut peer_db = get_peerdb();
  let hashes = vec![Hash(vec![0u8])];
  let peer = Peer {
    address:    PeerAddr::parse("127.0.0.1:11111").unwrap(),
    last_seen:  SystemTime::now(),
    date_added: SystemTime::now(),
  };

  peer_db
    .update_peer(&peer, &hashes)
    .expect("Could not update peer");

  assert!(peer_db.remove_peer(&peer.address).is_ok());
  assert_eq!(peer_db.get_peer_count().unwrap(), 0);
}

#[test]
fn test_get_peer() {
  let mut peer_db = get_peerdb();
  let hash = Hash(vec![0u8]);
  let peer = Peer {
    address:    PeerAddr::parse("127.0.0.1:11111").unwrap(),
    last_seen:  SystemTime::now(),
    date_added: SystemTime::now(),
  };
  peer_db
    .update_peer(&peer, &vec![hash])
    .expect("Could not update peer");

  assert_eq!(peer_db.get_peer_count().unwrap(), 1);
}

#[test]
fn test_get_peer_count() {
  let mut peer_db = get_peerdb();
  let hash = Hash(vec![0u8]);
  let peer = Peer {
    address:    PeerAddr::parse("127.0.0.1:11111").unwrap(),
    last_seen:  SystemTime::now(),
    date_added: SystemTime::now(),
  };

  assert_eq!(peer_db.get_peer_count().unwrap(), 0);
  peer_db
    .update_peer(&peer, &vec![hash])
    .expect("Could not update peer");
  assert_eq!(peer_db.get_peer_count().unwrap(), 1);
}

#[test]
fn test_get_hash_count() {
  let mut peer_db = get_peerdb();
  let hash = Hash(vec![0u8]);
  let peer = Peer {
    address:    PeerAddr::parse("127.0.0.1:11111").unwrap(),
    last_seen:  SystemTime::now(),
    date_added: SystemTime::now(),
  };

  assert_eq!(peer_db.get_hash_count().unwrap(), 0);
  peer_db
    .update_peer(&peer, &vec![hash])
    .expect("Could not update peer");
  assert_eq!(peer_db.get_hash_count().unwrap(), 1);
}

#[test]
fn test_get_peers_for_hash() {
  let mut peer_db = get_peerdb();
  let hash = Hash(vec![0u8]);
  let peer = Peer {
    address:    PeerAddr::parse("127.0.0.1:11111").unwrap(),
    last_seen:  SystemTime::now(),
    date_added: SystemTime::now(),
  };
  peer_db
    .update_peer(&peer, &vec![hash.clone()])
    .expect("Could not update peer");

  let peers = peer_db
    .get_peers_for_hash(&hash)
    .expect("Could not get peers for hash");

  assert_eq!(peers.len(), 1);
  assert_eq!(
    PeerAddr::parse("127.0.0.1:11111").unwrap(),
    peers[0].address
  );
}

#[test]
fn test_get_hashes() {
  let mut peer_db = get_peerdb();
  let hash = Hash(vec![0u8]);
  let peer = Peer {
    address:    PeerAddr::parse("127.0.0.1:11111").unwrap(),
    last_seen:  SystemTime::now(),
    date_added: SystemTime::now(),
  };
  let peer2 = Peer {
    address:    PeerAddr::parse("1.1.1.1:11111").unwrap(),
    last_seen:  SystemTime::now(),
    date_added: SystemTime::now(),
  };
  let hashes = vec![hash];
  peer_db
    .update_peer(&peer, &hashes)
    .expect("Could not update peer");
  peer_db
    .update_peer(&peer2, &hashes)
    .expect("Could not update peer");

  let hashes = peer_db.get_hashes().expect("Could not get hashes");

  assert_eq!(hashes.len(), 1);
  let (hash, peercount) = &hashes[0];
  assert_eq!(&Hash(vec![0u8]), hash);
  assert_eq!(&2, peercount);
}

#[test]
fn test_cleanup_peers() {
  let mut peer_db = get_peerdb();
  let mut peer = generate_peer();
  peer.last_seen = peer.last_seen.checked_sub(Duration::from_secs(10)).unwrap();
  peer_db.update_peer(&peer, &vec![]).unwrap();

  assert_eq!(peer_db.get_peer_count().unwrap(), 1);

  let result = peer_db.cleanup_peers(SystemTime::now());

  assert_eq!(result.unwrap(), 1);
  assert_eq!(peer_db.get_peer_count().unwrap(), 0);
}

#[test]
fn test_cleanup_hashes() {
  let mut peer_db = get_peerdb();
  let peer = generate_peer();
  let hash = generate_hash();
  peer_db.update_peer(&peer, &vec![hash]).unwrap();
  peer_db.remove_peer(&peer.address).unwrap();

  assert_eq!(peer_db.get_hash_count().unwrap(), 1);
  assert_eq!(peer_db.get_peer_count().unwrap(), 0);

  let result = peer_db.cleanup_hashes();

  assert_eq!(result.unwrap(), 1);
  assert_eq!(peer_db.get_hash_count().unwrap(), 0);
}
