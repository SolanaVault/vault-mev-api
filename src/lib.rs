use {
    ipc_channel::ipc::IpcSender,
    serde::{Deserialize, Serialize},
    solana_clock::{Slot, UnixTimestamp},
    solana_pubkey::Pubkey,
};

/// Maximum number of messages that can be sent from server to client after a single
/// KeepAlive control message from the client.
pub const MAX_MESSAGES_PER_KEEPALIVE: u64 = 10000;
/// v6: every `SubmitTxRequest` carries a client `request_id`, and the validator answers each
/// submission with a `SimulationStreamMessage::SubmitResult` on the dedicated result stream.
pub const STREAM_PROTOCOL_VERSION: u16 = 6;
pub const SIMULATION_CHANNEL_COUNT: usize = 2;
pub type StreamSessionId = [u8; 16];

/// Controls how much execution detail a simulation returns. Classification mode
/// preserves the fields needed to make an admission decision without retaining
/// or transporting the transaction's complete program log.
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
pub enum SimulationResultMode {
    FullLogs,
    Classification,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsupportedProtocolVersion {
    pub received: u16,
    pub supported: u16,
}

impl std::fmt::Display for UnsupportedProtocolVersion {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "unsupported Vault-MEV stream protocol version {} (supported {})",
            self.received, self.supported
        )
    }
}

impl std::error::Error for UnsupportedProtocolVersion {}

pub fn validate_protocol_version(version: u16) -> Result<(), UnsupportedProtocolVersion> {
    if version == STREAM_PROTOCOL_VERSION {
        Ok(())
    } else {
        Err(UnsupportedProtocolVersion {
            received: version,
            supported: STREAM_PROTOCOL_VERSION,
        })
    }
}

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
    OpenStream {
        protocol_version: u16,
        session_id: StreamSessionId,
        config: SubscriptionConfig,
        pumpfun_hints: Vec<Pubkey>,
        /// Dedicated response sink for latency-sensitive simulations. Simulation
        /// results never share the ordered account/transaction update stream.
        simulation_results_sink: String,
    },
    SubscribeAccounts {
        session_id: StreamSessionId,
        request_id: u64,
        accounts: Vec<Pubkey>,
    },
    CompactAccounts {
        session_id: StreamSessionId,
        request_id: u64,
        base_membership_generation: u64,
        retain: Vec<Pubkey>,
    },
    SetFilters {
        session_id: StreamSessionId,
        request_id: u64,
        filters: Vec<AccountFilter>,
    },
    SetPumpfunHints {
        session_id: StreamSessionId,
        request_id: u64,
        bonding_curves: Vec<Pubkey>,
    },
    ReplayFrom {
        session_id: StreamSessionId,
        sequence: u64,
    },
    /// A client must send KeepAlive periodically, one KeepAlive message sent allows for
    /// MAX_MESSAGES_PER_KEEPALIVE messages to be sent back from the server before another
    /// KeepAlive is required.
    KeepAlive,
}

/// Submission is always enqueued by the validator; this receiver must remain responsive.
/// The outcome of every request is reported back as a [`SubmitTxResult`] carrying the same
/// `request_id` on the dedicated result stream, including requests the validator rejects
/// before execution (not leader, slot tail, deserialization).
#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitTxRequest {
    pub session_id: StreamSessionId,
    /// Client-chosen correlation id, echoed on the matching [`SubmitTxResult`].
    pub request_id: u64,
    pub tx: Vec<u8>,
    pub simulate: bool,
    pub threshold_bps: u16,
}

/// Terminal outcome of one [`SubmitTxRequest`] as seen by the validator's leader bank.
///
/// `status` is the validator's `SubmitTransactionStatus` name (`success`, `not_leader`,
/// `too_close_to_end_of_slot`, `execution_failed`, `account_in_use`, ...). `success` with
/// `simulate=false` means the transaction was recorded and committed into the validator's own
/// block at `slot`; with `simulate=true` it means the dry run executed cleanly. Any other
/// status means the transaction will never land from this submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxResult {
    pub request_id: u64,
    pub status: String,
    /// Leader bank slot the request was processed against; 0 when no leader bank existed.
    pub slot: Slot,
    /// Runtime error text for `execution_failed`, or the rejection reason for the other
    /// non-success statuses when the validator has one.
    pub err: Option<String>,
    /// Compute units the transaction consumed when it executed (success or execution failure).
    pub units_consumed: u64,
    /// Lamport change of the arber WSOL account across the whole transaction, when the validator
    /// recognised an arber instruction and the transaction executed.
    pub profit_lamports: Option<i64>,
    /// Instruction-level attribution of an `execution_failed` outcome. Submissions execute
    /// without log recording, so `profit_guard_program_id` is never proven here; callers must
    /// pair `instruction_index`/`custom_error` with their own instruction list.
    pub failure_provenance: Option<SimulationFailureProvenance>,
    /// First signature of the submitted transaction, when it deserialized.
    pub signature: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SimulateTxRequest {
    pub session_id: StreamSessionId,
    pub request_id: u64,
    pub tx: Vec<u8>,
    pub sig_verify: bool,
    pub replace_recent_blockhash: bool,
    pub result_mode: SimulationResultMode,
}

/// Persistent, independent request channels transferred through the IPC handshake.
/// Every request must carry the negotiated session; a channel handle alone grants
/// no authority to operate on a replacement session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionControlChannels {
    pub submit: IpcSender<SubmitTxRequest>,
    pub simulations: [IpcSender<SimulateTxRequest>; SIMULATION_CHANNEL_COUNT],
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimulationFailureProvenance {
    /// Top-level instruction index reported by the runtime.
    pub instruction_index: Option<u32>,
    /// Custom instruction error, when the runtime reported one.
    pub custom_error: Option<u32>,
    /// First program whose stable execution log reported failure.
    pub failed_program_id: Option<Pubkey>,
    /// Program active when the authenticated ARBER_PROFIT_GUARD_FAILURE marker
    /// was emitted. A child program cannot forge its parent's identity here.
    pub profit_guard_program_id: Option<Pubkey>,
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
    pub failure_provenance: Option<SimulationFailureProvenance>,
}

/// Messages sent on the dedicated simulation-result IPC channel.
#[derive(Debug, Serialize, Deserialize)]
pub enum SimulationStreamMessage {
    /// Mandatory first message, used to bind the response channel to the same
    /// negotiated protocol and session as the ordered update stream.
    Opened {
        protocol_version: u16,
        session_id: StreamSessionId,
        transaction_channels: TransactionControlChannels,
    },
    Response {
        session_id: StreamSessionId,
        update: SimulateTxUpdate,
    },
    /// Terminal outcome of one `SubmitTxRequest`, matched by `result.request_id`.
    SubmitResult {
        session_id: StreamSessionId,
        result: SubmitTxResult,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamOpenedUpdate {
    pub protocol_version: u16,
    pub membership_generation: u64,
    pub filter_generation: u64,
    pub pumpfun_hint_generation: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsActivatedUpdate {
    pub request_id: u64,
    pub membership_generation: u64,
    /// Completed-bank slot used for the authoritative account image.
    pub slot: Slot,
    pub chunk_index: u32,
    pub chunk_count: u32,
    pub accounts: Vec<AccountInfo>,
    /// Requested keys that were absent from the completed bank.
    pub missing: Vec<Pubkey>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsCompactedUpdate {
    pub request_id: u64,
    pub membership_generation: u64,
    pub physical_account_count: usize,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum AppliedControlKind {
    Filters,
    PumpfunHints,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlAppliedUpdate {
    pub request_id: u64,
    pub kind: AppliedControlKind,
    pub generation: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum MessageContent {
    StreamOpened(StreamOpenedUpdate),
    Slot(SlotUpdate),
    TransactionWithAccounts(Vec<TxWithAccountsUpdate>),
    SimulateTx(SimulateTxUpdate),
    AccountsActivated(AccountsActivatedUpdate),
    AccountsCompacted(AccountsCompactedUpdate),
    ControlApplied(ControlAppliedUpdate),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateMessage {
    pub session_id: StreamSessionId,
    pub sequence: u64,
    pub slot: Slot,
    pub is_leader: bool,
    pub content: MessageContent,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(value: &T) -> T
    where
        T: Serialize + for<'de> Deserialize<'de>,
    {
        bincode::deserialize(&bincode::serialize(value).unwrap()).unwrap()
    }

    #[test]
    fn control_variants_roundtrip() {
        let session_id = [7; 16];
        let key = Pubkey::new_from_array([3; 32]);
        let messages = [
            ControlMessage::OpenStream {
                protocol_version: STREAM_PROTOCOL_VERSION,
                session_id,
                config: SubscriptionConfig::default(),
                pumpfun_hints: vec![key],
                simulation_results_sink: "simulation-results".to_string(),
            },
            ControlMessage::SubscribeAccounts {
                session_id,
                request_id: 1,
                accounts: vec![key],
            },
            ControlMessage::CompactAccounts {
                session_id,
                request_id: 2,
                base_membership_generation: 4,
                retain: vec![key],
            },
            ControlMessage::SetFilters {
                session_id,
                request_id: 3,
                filters: Vec::new(),
            },
            ControlMessage::SetPumpfunHints {
                session_id,
                request_id: 4,
                bonding_curves: vec![key],
            },
            ControlMessage::ReplayFrom {
                session_id,
                sequence: 9,
            },
        ];
        for message in messages {
            let _: ControlMessage = roundtrip(&message);
        }
    }

    #[test]
    fn simulation_stream_roundtrip() {
        let session_id = [9; 16];
        // Channel handles must be transferred through IPC, not bare bincode.
        let (submit, submit_rx) = ipc_channel::ipc::channel().unwrap();
        let (sim0, _sim0_rx) = ipc_channel::ipc::channel().unwrap();
        let (sim1, _sim1_rx) = ipc_channel::ipc::channel().unwrap();
        let (handshake_tx, handshake_rx) = ipc_channel::ipc::channel().unwrap();
        handshake_tx
            .send(SimulationStreamMessage::Opened {
                protocol_version: STREAM_PROTOCOL_VERSION,
                session_id,
                transaction_channels: TransactionControlChannels {
                    submit,
                    simulations: [sim0, sim1],
                },
            })
            .unwrap();
        let opened = handshake_rx.recv().unwrap();
        assert!(matches!(
            &opened,
            SimulationStreamMessage::Opened {
                protocol_version: STREAM_PROTOCOL_VERSION,
                session_id: decoded_session,
                ..
            } if *decoded_session == session_id
        ));
        if let SimulationStreamMessage::Opened {
            transaction_channels,
            ..
        } = opened
        {
            transaction_channels
                .submit
                .send(SubmitTxRequest {
                    session_id,
                    request_id: 21,
                    tx: vec![1, 2],
                    simulate: false,
                    threshold_bps: 1000,
                })
                .unwrap();
            let received = submit_rx.recv().unwrap();
            assert_eq!(received.request_id, 21);
            assert_eq!(received.tx, vec![1, 2]);
        }

        let response: SimulationStreamMessage = roundtrip(&SimulationStreamMessage::Response {
            session_id,
            update: SimulateTxUpdate {
                request_id: 11,
                status: "success".to_string(),
                slot: 12,
                err: None,
                logs: vec!["ok".to_string()],
                units_consumed: 13,
                loaded_accounts_data_size: 14,
                fee: Some(15),
                failure_provenance: Some(SimulationFailureProvenance {
                    instruction_index: Some(2),
                    custom_error: Some(6000),
                    failed_program_id: Some(Pubkey::new_from_array([4; 32])),
                    profit_guard_program_id: Some(Pubkey::new_from_array([5; 32])),
                }),
            },
        });
        assert!(matches!(
            &response,
            SimulationStreamMessage::Response {
                session_id: decoded_session,
                update: SimulateTxUpdate { request_id: 11, .. },
            } if *decoded_session == session_id
        ));
        if let SimulationStreamMessage::Response { update, .. } = response {
            let provenance = update.failure_provenance.unwrap();
            assert_eq!(provenance.instruction_index, Some(2));
            assert_eq!(provenance.custom_error, Some(6000));
        }

        let submit_result: SimulationStreamMessage =
            roundtrip(&SimulationStreamMessage::SubmitResult {
                session_id,
                result: SubmitTxResult {
                    request_id: 21,
                    status: "execution_failed".to_string(),
                    slot: 33,
                    err: Some("InstructionError(3, Custom(6001))".to_string()),
                    units_consumed: 44,
                    profit_lamports: Some(-5),
                    failure_provenance: Some(SimulationFailureProvenance {
                        instruction_index: Some(3),
                        custom_error: Some(6001),
                        failed_program_id: Some(Pubkey::new_from_array([6; 32])),
                        profit_guard_program_id: None,
                    }),
                    signature: Some("sig".to_string()),
                },
            });
        let SimulationStreamMessage::SubmitResult {
            session_id: decoded_session,
            result,
        } = submit_result
        else {
            panic!("submit result variant expected");
        };
        assert_eq!(decoded_session, session_id);
        assert_eq!(result.request_id, 21);
        assert_eq!(result.status, "execution_failed");
        assert_eq!(result.slot, 33);
        assert_eq!(result.units_consumed, 44);
        assert_eq!(result.profit_lamports, Some(-5));
        assert_eq!(
            result.failure_provenance.unwrap().custom_error,
            Some(6001)
        );
    }

    #[test]
    fn sequenced_updates_roundtrip() {
        let updates = [
            MessageContent::StreamOpened(StreamOpenedUpdate {
                protocol_version: STREAM_PROTOCOL_VERSION,
                membership_generation: 3,
                filter_generation: 4,
                pumpfun_hint_generation: 5,
            }),
            MessageContent::AccountsActivated(AccountsActivatedUpdate {
                request_id: 8,
                membership_generation: 9,
                slot: 100,
                chunk_index: 0,
                chunk_count: 1,
                accounts: Vec::new(),
                missing: vec![Pubkey::new_from_array([1; 32])],
            }),
            MessageContent::AccountsCompacted(AccountsCompactedUpdate {
                request_id: 10,
                membership_generation: 11,
                physical_account_count: 12,
            }),
            MessageContent::ControlApplied(ControlAppliedUpdate {
                request_id: 13,
                kind: AppliedControlKind::PumpfunHints,
                generation: 14,
            }),
        ];
        for (index, content) in updates.into_iter().enumerate() {
            let message = UpdateMessage {
                session_id: [5; 16],
                sequence: 42 + index as u64,
                slot: 100,
                is_leader: true,
                content,
            };
            let decoded: UpdateMessage = roundtrip(&message);
            assert_eq!(decoded.session_id, [5; 16]);
            assert_eq!(decoded.sequence, 42 + index as u64);
            assert_eq!(decoded.slot, 100);
            assert!(decoded.is_leader);
        }
    }

    #[test]
    fn protocol_version_validation_rejects_mismatches() {
        assert_eq!(validate_protocol_version(STREAM_PROTOCOL_VERSION), Ok(()));
        assert_eq!(
            validate_protocol_version(STREAM_PROTOCOL_VERSION + 1),
            Err(UnsupportedProtocolVersion {
                received: STREAM_PROTOCOL_VERSION + 1,
                supported: STREAM_PROTOCOL_VERSION,
            })
        );
    }
}
