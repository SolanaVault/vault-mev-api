use {
    serde::{Deserialize, Serialize},
    solana_clock::{Slot, UnixTimestamp},
    solana_pubkey::Pubkey,
};

/// Maximum number of messages that can be sent from server to client after a single
/// KeepAlive control message from the client.
pub const MAX_MESSAGES_PER_KEEPALIVE: u64 = 10000;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MemcmpFilter {
    pub offset: usize,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AccountFilter {
    pub owner: Pubkey,
    /// All memcmp filters must match.
    pub memcmp: Vec<MemcmpFilter>,
    /// If set, account data length must match exactly.
    pub data_size: Option<u64>,
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct SubscriptionConfig {
    pub filters: Vec<AccountFilter>,
    pub accounts: Vec<Pubkey>,
    /// Optional IpcOneShotServer name for account updates. If provided, we
    /// connect and replace the outgoing updates channel.
    pub updates_sink: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ControlMessage {
    SetSubscriptions(SubscriptionConfig),
    SubmitTx {
        tx: Vec<u8>,
        enqueue: bool,
        simulate: bool,
        threshold_bps: u16,
    },
    SimulateTx {
        request_id: u64,
        tx: Vec<u8>,
        sig_verify: bool,
        replace_recent_blockhash: bool,
    },
    /// A client must send KeepAlive periodically, one KeepAlive message sent allows for
    /// MAX_MESSAGES_PER_KEEPALIVE messages to be sent back from the server before another
    /// KeepAlive is required.
    KeepAlive,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccountInfo {
    pub pubkey: Pubkey,
    pub owner: Pubkey,
    pub lamports: u64,
    pub data: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SlotUpdate {
    pub slot: Slot,
    pub parent: Option<u64>,
    pub status: SlotStatus,
    pub recent_blockhash: Option<[u8; 32]>,
}

/// Slot status mirrored from `agave_geyser_plugin_interface::geyser_plugin_interface::SlotStatus`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SlotStatus {
    Processed,
    Rooted,
    Confirmed,
    FirstShredReceived,
    Completed,
    CreatedBank,
    Dead(String),
    PrunedPredicted,
    PrunedConfirmed,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxWithAccountsUpdate {
    pub signature: String,
    pub is_vote: bool,
    pub status: String,
    pub slot: Slot,
    pub chain_unix_timestamp: UnixTimestamp,
    pub index: Option<usize>,
    pub writable_accounts: Vec<AccountInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SimulateTxUpdate {
    pub request_id: u64,
    pub status: String,
    pub slot: Slot,
    pub err: Option<String>,
    pub logs: Vec<String>,
    pub units_consumed: u64,
    pub loaded_accounts_data_size: u32,
    pub fee: Option<u64>,
}

/// Authoritative current-state push for specific accounts.
///
/// Sent after a `SetSubscriptions` replace carries newly-added literal accounts: the
/// updates stream only delivers account bytes when a matching transaction writes the
/// account, so without this push a freshly subscribed low-activity account would stay
/// at whatever stale bytes the client last held until its next natural on-chain write.
#[derive(Debug, Serialize, Deserialize)]
pub struct AccountSnapshotUpdate {
    /// Working-bank slot the accounts were read from.
    pub slot: Slot,
    /// Accounts exactly as read from the working bank (missing accounts are omitted).
    pub accounts: Vec<AccountInfo>,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageContent {
    Slot(SlotUpdate),
    TransactionWithAccounts(Vec<TxWithAccountsUpdate>),
    SimulateTx(SimulateTxUpdate),
    /// Appended last: bincode encodes variants positionally, so mixed-version
    /// deployments break if a server newer than the client sends this. Deploy
    /// clients before enabling server-side snapshots.
    AccountSnapshot(AccountSnapshotUpdate),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMessage {
    pub slot: Slot,
    pub is_leader: bool,
    pub content: MessageContent,
}
