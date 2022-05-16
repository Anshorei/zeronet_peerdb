use std::process::{Command, Stdio};
use std::time::SystemTime;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use log::*;
use zeronet_peerdb::{Hash, Peer, PeerDB, PeerDatabase};
use zeronet_protocol::PeerAddr;

#[cfg(not(feature = "sql"))]
fn get_peerdb() -> PeerDB {
  return PeerDB::new().unwrap();
}

#[cfg(feature = "sql")]
fn get_peerdb() -> PeerDB {
  std::fs::create_dir_all("./tmp").expect("Could not create tmp folder, check privileges");
  let temporary_database_removed = Command::new("rm")
    .args(&["./tmp/peers.db"])
    .stderr(Stdio::null())
    .status()
    .unwrap()
    .success();
  if temporary_database_removed {
    info!("Cleaned up temporary database");
  }
  return PeerDB::new(Some("./tmp/peers.db".into())).unwrap();
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

fn bench_get_1000_peers_for_hash(c: &mut Criterion) {
  let mut peer_db = get_peerdb();
  let hash = generate_hash();

  for _ in 0..1000 {
    let peer = generate_peer();
    let mut unique_hash = generate_hash();
    unique_hash.0.push(0u8); // Make sure hash does not collide
    peer_db
      .update_peer(&peer, &vec![hash.clone(), unique_hash])
      .unwrap();
  }

  c.bench_function("get 1000 peers for hash", |b| {
    b.iter(|| peer_db.get_peers_for_hash(&hash).unwrap())
  });
}

fn bench_insert_peer_for_1000_hashes(c: &mut Criterion) {
  let peer = generate_peer();
  let hashes: Vec<Hash> = (0..1000).map(|_| generate_hash()).collect();

  c.bench_function("insert peer for 1000 hashes", |b| {
    b.iter_batched(
      || (get_peerdb(), peer.clone(), hashes.clone()),
      |(mut peerdb, peer, hashes)| peerdb.update_peer(&peer, &hashes),
      criterion::BatchSize::SmallInput,
    )
  });
}

fn bench_insert_1000th_hash(c: &mut Criterion) {
  let hashes: Vec<Hash> = (0..1000).map(|_| generate_hash()).collect();

  c.bench_function("insert 1000th hash", |b| {
    b.iter_batched(
      || {
        let mut peerdb = get_peerdb();
        peerdb
          .insert_hashes(hashes.as_slice())
          .expect("Could not insert hashes");
        // hashes
        //     .iter()
        //     .for_each(|hash| peerdb.insert_hash(&hash).expect("Could not insert hash"));
        (peerdb, generate_hash())
      },
      |(mut peerdb, hash)| {
        peerdb
          .insert_hashes(&[hash])
          .expect("Could not insert hash")
      },
      criterion::BatchSize::SmallInput,
    )
  });
}

criterion_group!(get_benches, bench_get_1000_peers_for_hash,);
criterion_group! {
    name = insert_benches;
    config = Criterion::default().sample_size(10);
    targets = bench_insert_peer_for_1000_hashes,
    bench_insert_1000th_hash
}
criterion_main!(get_benches, insert_benches);
