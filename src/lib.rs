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
/// v7: `SimulateTxRequest::post_accounts` names accounts whose post-execution images the
/// validator returns in `SimulateTxUpdate::post_accounts`, so an oracle refresh can be strictly
/// simulated and certified on the validator's working bank instead of over HTTP RPC.
/// v8: a `SubmitTxRequest` may carry a [`StandingPolicy`]. A submission that executes without
/// landing then stays registered on the validator and is re-executed, on the leader bank, every
/// time another committed leader-bank transaction writes one of its `watch` accounts, until it
/// lands, runs out of attempts, or `until_slot` passes. Each execution is reported as its own
/// `SubmitTxResult`; `standing` on the result says whether the entry is still registered.
/// `ControlMessage::CancelStanding` withdraws an entry early.
/// v9: transactions and account activations identify their session-local bank; bank lifecycle
/// events carry ancestry, full Clock state and explicit abandonment. Submit success identifies
/// a local commit, while a rooted bank or rooted descendant proves its finality. Transactions
/// carry their executing Clock; Frozen events carry the post-footer Clock inherited by a child.
/// Both peers must upgrade together; v8 cannot represent these fields.
/// v10: every `SubmitTxRequest` carries a `priority`. The validator runs submissions that share a
/// fee payer one at a time, and gives the turn to the waiting submission with the highest
/// priority (ties in arrival order), including the copies it held for the leader bank, which all
/// become runnable the moment that bank opens; a standing entry keeps its request's priority for
/// every re-execution. Both peers must upgrade together.
pub const STREAM_PROTOCOL_VERSION: u16 = 10;
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
    /// Withdraw a standing submission (v8). The validator answers with a final
    /// `SubmitTxResult` of status `standing_cancelled` when the entry was still registered; an
    /// entry that already reached a terminal result has nothing to answer.
    CancelStanding {
        session_id: StreamSessionId,
        request_id: u64,
    },
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
    /// Keep the submission registered for re-execution on touch after a non-landing first
    /// attempt (v8). `None` is the classic one-shot submission. Ignored for `simulate=true`.
    pub standing: Option<StandingPolicy>,
    /// Order among this client's submissions that share a fee payer (v10): when several wait for
    /// the payer, the highest priority runs first, ties in arrival order. The validator compares
    /// it only with other submissions of the same fee payer, so the unit is the client's own
    /// (the arber client sends the expected profit in lamports, and 0 or 1 for copies whose
    /// value is not a current quote). It never reorders anyone else's transactions.
    pub priority: u64,
}

/// How long, and how often, the validator may re-execute a submission that did not land on its
/// first attempt (v8).
///
/// The validator re-executes the same signed bytes whenever a committed transaction in one of
/// its own leader banks writes any account in `watch`. A failed execution is never recorded,
/// so a profit-guard revert costs nothing but validator time and the signature stays free to
/// go again; a landed copy makes later attempts fail as already processed and removes the
/// entry. The validator clamps `max_attempts` to its own ceiling and refuses registration when
/// its registry is full, reporting either through `SubmitTxResult::standing`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingPolicy {
    /// Last slot, inclusive, in which a re-execution may run. Entries past it are removed with
    /// a final `standing_expired` result.
    pub until_slot: Slot,
    /// Re-executions allowed after the initial attempt.
    pub max_attempts: u32,
    /// Accounts whose commit by another leader-bank transaction re-triggers the submission.
    pub watch: Vec<Pubkey>,
}

/// Terminal outcome of one [`SubmitTxRequest`] as seen by the validator's leader bank.
///
/// `status` is the validator's `SubmitTransactionStatus` name (`success`, `not_leader`,
/// `too_close_to_end_of_slot`, `execution_failed`, `account_in_use`, ...). `success` with
/// `simulate=false` means the transaction was recorded and committed into the validator's own
/// block at `slot`; with `simulate=true` it means the dry run executed cleanly. Any other
/// status means the transaction will never land from this submission — unless `standing` is
/// true (v8), in which case the validator still holds the entry and further results for the
/// same `request_id` follow, one per re-execution, until one arrives with `standing=false`.
/// Standing-only statuses: `standing_expired` (`until_slot` passed) and `standing_cancelled`
/// (withdrawn by `ControlMessage::CancelStanding`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitTxResult {
    /// Node-local bank identity; interpreted only within this stream session.
    pub bank_id: Option<u64>,
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
    /// Which execution this result reports (v8): 0 is the initial submission, `n` the n-th
    /// standing re-execution.
    pub attempt: u32,
    /// The entry remains registered for further re-executions (v8); `false` marks the last
    /// result this `request_id` will ever produce.
    pub standing: bool,
}

/// Status name of the final result of a standing entry whose `until_slot` passed.
pub const STANDING_EXPIRED_STATUS: &str = "standing_expired";
/// Status name of the final result of a standing entry withdrawn by `CancelStanding`.
pub const STANDING_CANCELLED_STATUS: &str = "standing_cancelled";

#[derive(Debug, Serialize, Deserialize)]
pub struct SimulateTxRequest {
    pub session_id: StreamSessionId,
    pub request_id: u64,
    pub tx: Vec<u8>,
    pub sig_verify: bool,
    pub replace_recent_blockhash: bool,
    pub result_mode: SimulationResultMode,
    /// Accounts whose post-execution images are returned (v7). Empty requests none. The
    /// validator returns every requested account it loaded, in request order; a requested
    /// account the transaction did not load is omitted.
    pub post_accounts: Vec<Pubkey>,
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

/// Full program-visible Clock. A frozen bank's Clock is the context inherited by its child.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionClock {
    pub slot: Slot,
    pub epoch_start_timestamp: UnixTimestamp,
    pub epoch: u64,
    pub leader_schedule_epoch: u64,
    pub unix_timestamp: UnixTimestamp,
}

/// Bank IDs are opaque, node-local, and scoped to the enclosing stream session.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BankContext {
    pub parent_block_id: Option<[u8; 32]>,
    pub bank_id: u64,
    pub parent_bank_id: Option<u64>,
    pub parent_slot: Slot,
    pub clock: ExecutionClock,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BankEventKind {
    Created,
    Frozen,
    Confirmed,
    Rooted,
    Abandoned,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct BankEvent {
    pub recent_blockhash: Option<[u8; 32]>,
    pub alpenglow: bool,
    pub block_id: Option<[u8; 32]>,
    pub slot: Slot,
    pub bank_id: u64,
    pub parent_slot: Option<Slot>,
    pub parent_bank_id: Option<u64>,
    /// Created: executing Clock. Frozen: post-footer Clock. Other events may omit it.
    pub clock: Option<ExecutionClock>,
    pub kind: BankEventKind,
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
    /// Executing Clock and parent identity captured before the bank footer.
    pub bank: Option<BankContext>,
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
    /// Post-execution images of the requested `post_accounts` (v7), in request order.
    pub post_accounts: Vec<AccountInfo>,
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
    pub bank_id: Option<u64>,
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
    Bank(BankEvent),
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
                    standing: Some(StandingPolicy {
                        until_slot: 40,
                        max_attempts: 5,
                        watch: vec![Pubkey::new_from_array([9; 32])],
                    }),
                    priority: 2_179_562_846,
                })
                .unwrap();
            let received = submit_rx.recv().unwrap();
            assert_eq!(received.request_id, 21);
            assert_eq!(received.tx, vec![1, 2]);
            assert_eq!(received.priority, 2_179_562_846);
            let standing = received.standing.unwrap();
            assert_eq!(standing.until_slot, 40);
            assert_eq!(standing.max_attempts, 5);
            assert_eq!(standing.watch, vec![Pubkey::new_from_array([9; 32])]);
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
                post_accounts: Vec::new(),
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
                    bank_id: None,
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
                    attempt: 2,
                    standing: true,
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
        assert_eq!(result.failure_provenance.unwrap().custom_error, Some(6001));
        assert_eq!(result.attempt, 2);
        assert!(result.standing);

        let cancel: ControlMessage = roundtrip(&ControlMessage::CancelStanding {
            session_id,
            request_id: 21,
        });
        assert!(matches!(
            cancel,
            ControlMessage::CancelStanding {
                session_id: decoded,
                request_id: 21
            } if decoded == session_id
        ));
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
                bank_id: None,
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
        assert!(
            validate_protocol_version(8).is_err(),
            "v8 cannot carry bank identity or finality"
        );
        assert_eq!(
            validate_protocol_version(STREAM_PROTOCOL_VERSION + 1),
            Err(UnsupportedProtocolVersion {
                received: STREAM_PROTOCOL_VERSION + 1,
                supported: STREAM_PROTOCOL_VERSION,
            })
        );
    }

    #[test]
    fn bank_identity_parent_and_full_clocks_roundtrip() {
        let clock = ExecutionClock {
            slot: 432_003,
            epoch: 1,
            leader_schedule_epoch: 2,
            epoch_start_timestamp: 1234,
            unix_timestamp: 1234,
        };
        let context = BankContext {
            parent_block_id: Some([4; 32]),
            bank_id: 3,
            parent_bank_id: Some(99),
            parent_slot: 431_995,
            clock,
        };
        assert_eq!(roundtrip::<BankContext>(&context), context);
        for kind in [
            BankEventKind::Created,
            BankEventKind::Frozen,
            BankEventKind::Confirmed,
            BankEventKind::Rooted,
            BankEventKind::Abandoned,
        ] {
            let event = BankEvent {
                recent_blockhash: Some([5; 32]),
                alpenglow: true,
                block_id: Some([6; 32]),
                slot: clock.slot,
                bank_id: 3,
                parent_slot: Some(431_995),
                parent_bank_id: Some(99),
                clock: Some(clock),
                kind,
            };
            let content: MessageContent = roundtrip(&MessageContent::Bank(event));
            assert!(matches!(content,MessageContent::Bank(decoded) if decoded==event));
        }
    }
}
