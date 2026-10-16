use {super::*, solana_account::WritableAccount};

fn account(lamports: u64, owner: Pubkey, data: &[u8]) -> AccountSharedData {
    Account {
        lamports,
        owner,
        data: data.to_vec(),
        rent_epoch: 17,
        executable: false,
    }
    .into()
}

fn load(
    db: &AccountsDb,
    ancestors: &Ancestors,
    address: &Pubkey,
) -> Option<(AccountSharedData, Slot)> {
    db.load(
        ancestors,
        address,
        LoadHint::FixedMaxRoot,
        PopulateReadCache::False,
        None::<fn(_, &_, _) -> _>,
    )
}

#[test]
fn immutable_pq_overlays_isolate_siblings_tombstones_and_persist_only_winner_delta() {
    let base = Arc::new(AccountsDb::default_for_tests());
    let owner = Pubkey::new_unique();
    let changed_owner = Pubkey::new_unique();
    let unchanged = Pubkey::new_unique();
    let changed = Pubkey::new_unique();
    let deleted = Pubkey::new_unique();
    let created = Pubkey::new_unique();
    let original = vec![
        (unchanged, account(100, owner, b"immutable shared page")),
        (changed, account(200, owner, b"before")),
        (deleted, account(300, owner, b"delete and recreate")),
    ];
    base.store_for_tests((0, original.as_slice()));
    base.add_root(0);
    let initial_ancestors = Ancestors::from(vec![0]);
    let (parent, stock_delta) = base
        .pq_account_snapshot_with_delta(&initial_ancestors, BankId::new(0))
        .unwrap();
    assert!(
        stock_delta.is_none(),
        "stock scans cannot provide an overlay delta"
    );
    let state = [0x41; 48];
    let a = Arc::new(AccountsDb::new_pq_overlay(
        Arc::clone(&parent),
        state,
        Arc::clone(&base),
    ));
    let b = AccountsDb::new_pq_overlay(Arc::clone(&parent), state, Arc::clone(&base));
    let ancestors = Ancestors::from(vec![0, 1]);
    assert!(a.accounts_cache.slot_cache(0).is_none());
    assert_eq!(
        load(&a, &ancestors, &changed),
        Some((original[1].1.clone(), 0))
    );
    assert_eq!(load(&a, &ancestors, &created), None);
    let mut changed_account = account(220, changed_owner, b"fork A owns these bytes");
    changed_account.set_rent_epoch(99);
    let delta = vec![
        (changed, changed_account.clone()),
        (deleted, AccountSharedData::default()),
        (created, account(400, changed_owner, b"new")),
    ];
    a.store_for_tests((1, delta.as_slice()));
    a.mark_slot_frozen(1);
    assert_eq!(a.accounts_cache.slot_cache(1).unwrap().len(), 3);
    assert!(
        load(&a, &ancestors, &deleted).is_none(),
        "tombstone must hide inherited account"
    );
    assert_eq!(
        load(&b, &ancestors, &deleted),
        Some((original[2].1.clone(), 0))
    );
    assert!(load(&b, &ancestors, &created).is_none());
    assert_eq!(
        load(&a, &ancestors, &changed),
        Some((changed_account.clone(), 1))
    );
    assert!(
        a.load(
            &ancestors,
            &changed,
            LoadHint::FixedMaxRoot,
            PopulateReadCache::False,
            Some(|_, loaded_owner: &Pubkey, _| loaded_owner == &owner)
        )
        .is_none(),
        "filter rejection must not reveal inherited ownership"
    );
    let (snapshot, written) = a
        .pq_account_snapshot_with_delta(&ancestors, BankId::new(1))
        .unwrap();
    let written = written.unwrap();
    assert_eq!(written.len(), 3);
    assert_eq!(
        written.into_iter().collect::<HashSet<_>>(),
        HashSet::from([changed, deleted, created]),
        "the exact local delta must retain deletions absent from the merged view"
    );
    let (sibling_snapshot, sibling_delta) = b
        .pq_account_snapshot_with_delta(&ancestors, BankId::new(2))
        .unwrap();
    assert_eq!(*sibling_snapshot, *parent);
    assert!(sibling_delta.unwrap().is_empty());
    assert_eq!(snapshot.len(), 3);
    assert!(!snapshot.contains_key(&deleted));
    assert_eq!(snapshot[&unchanged], parent[&unchanged]);
    assert_eq!(snapshot[&changed], (changed_account, 1));
    let expected_hash = a.calculate_accounts_lt_hash_at_startup_from_index(&ancestors);
    a.promote_pq_overlay(1, 0, BankId::new(1), &ancestors, state)
        .unwrap();
    a.add_root(1);
    assert_eq!(
        base.accounts_cache.slot_cache(1).unwrap().len(),
        3,
        "canonical storage receives only changed accounts"
    );
    assert_eq!(
        base.calculate_accounts_lt_hash_at_startup_from_index(&ancestors),
        expected_hash
    );
    base.flush_accounts_cache(true, Some(1));
    base.clean_accounts_for_tests();
    let (persisted_snapshot, persisted_delta) = a
        .pq_account_snapshot_with_delta(&ancestors, BankId::new(1))
        .unwrap();
    assert_eq!(*persisted_snapshot, *snapshot);
    assert_eq!(
        persisted_delta.unwrap().into_iter().collect::<HashSet<_>>(),
        HashSet::from([changed, deleted, created]),
        "canonical persistence must not add inherited writes to the overlay delta"
    );
    assert_eq!(
        load(&b, &ancestors, &deleted),
        Some((original[2].1.clone(), 0)),
        "base cleanup and root advance cannot change a sibling's immutable view"
    );
    assert_eq!(
        load(&b, &ancestors, &changed),
        Some((original[1].1.clone(), 0))
    );
    assert!(
        b.promote_pq_overlay(1, 0, BankId::new(2), &ancestors, state)
            .is_err()
    );

    let child = AccountsDb::new_pq_overlay(snapshot, [0x42; 48], Arc::clone(&base));
    let child_ancestors = Ancestors::from(vec![0, 1, 2]);
    assert!(load(&child, &child_ancestors, &deleted).is_none());
    let recreated = account(900, owner, b"recreated independently");
    child.store_for_tests((2, &[(deleted, recreated.clone())][..]));
    child.mark_slot_frozen(2);
    let (recreated_snapshot, recreated_delta) = child
        .pq_account_snapshot_with_delta(&child_ancestors, BankId::new(3))
        .unwrap();
    assert_eq!(recreated_delta.unwrap(), vec![deleted]);
    assert_eq!(recreated_snapshot[&deleted], (recreated.clone(), 2));
    assert_eq!(
        load(&child, &child_ancestors, &deleted),
        Some((recreated, 2))
    );
    assert!(load(&a, &ancestors, &deleted).is_none());
    assert!(
        child
            .promote_pq_overlay(2, 1, BankId::new(3), &child_ancestors, [0xff; 48])
            .is_err()
    );
    child
        .promote_pq_overlay(2, 1, BankId::new(3), &child_ancestors, [0x42; 48])
        .unwrap();
    child.add_root(2);
    assert_eq!(base.max_root(), 2);
    assert_eq!(
        load(&base, &child_ancestors, &deleted).unwrap().0.data(),
        b"recreated independently"
    );
    assert!(
        child
            .promote_pq_overlay(2, 1, BankId::new(3), &child_ancestors, [0x42; 48])
            .is_err()
    );
}

#[test]
fn pq_overlay_secondary_owner_scan_includes_inherited_and_excludes_changed_owners() {
    let base = Arc::new(AccountsDb::default_for_tests());
    let owner = Pubkey::new_unique();
    let other_owner = Pubkey::new_unique();
    let addresses = [
        Pubkey::new_unique(),
        Pubkey::new_unique(),
        Pubkey::new_unique(),
    ];
    base.store_for_tests((
        0,
        &[
            (addresses[0], account(1, owner, b"untouched")),
            (addresses[1], account(1, owner, b"reassigned")),
        ][..],
    ));
    base.add_root(0);
    let parent = base
        .pq_account_snapshot(&Ancestors::from(vec![0]), BankId::new(0))
        .unwrap();
    let fork = AccountsDb::new_pq_overlay(parent, [9; 48], base);
    fork.store_for_tests((
        1,
        &[
            (addresses[1], account(1, other_owner, b"new owner")),
            (addresses[2], account(1, owner, b"created")),
        ][..],
    ));
    let ancestors = Ancestors::from(vec![0, 1]);
    let mut found = std::collections::BTreeSet::new();
    let used_index = fork
        .index_scan_accounts(
            &ancestors,
            BankId::new(1),
            IndexKey::ProgramId(owner),
            |entry| {
                if let Some((key, account, _)) = entry
                    && account.owner() == &owner
                {
                    found.insert(*key);
                }
            },
            &ScanConfig::default(),
        )
        .unwrap();
    assert!(
        !used_index,
        "overlay owner queries use the exact merged view"
    );
    assert_eq!(
        found,
        std::collections::BTreeSet::from([addresses[0], addresses[2]])
    );
}
