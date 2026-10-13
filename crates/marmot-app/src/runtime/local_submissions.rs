use super::*;
use crate::local_submissions::LocalMessageRequest;

#[cfg(feature = "experimental-device-sync")]
enum LocalSubmissionAdmission {
    Local(crate::LocalSendAcceptance),
    Forwarded(Box<ForwardedLocalSubmission>),
}

#[cfg(feature = "experimental-device-sync")]
struct ForwardedLocalSubmission {
    group: GroupId,
    token: String,
    request: LocalMessageRequest,
}

impl MarmotAppRuntime {
    /// Upload first, then durably admit the resulting message when `send` is set.
    /// Cancellation does not abandon an upload already handed to this task.
    pub async fn upload_media_with_client_token(
        &self,
        account: &str,
        group: &GroupId,
        mut request: MediaUploadRequest,
        client_token: String,
    ) -> Result<(MediaUploadResult, Option<crate::LocalSendAcceptance>), AppError> {
        if client_token.is_empty() || client_token.len() > 128 {
            return Err(AppError::InvalidAppMessagePayload(
                "client token must contain 1 to 128 UTF-8 bytes".into(),
            ));
        }
        let runtime = self.clone();
        let account = account.to_owned();
        let group = group.clone();
        tokio::spawn(async move {
            let send = request.send;
            request.send = false;
            let caption = request.caption.clone();
            let upload = runtime.upload_media(&account, &group, request).await?;
            let accepted = if send {
                let submission = runtime
                    .submit_media_attachments(
                        &account,
                        &group,
                        upload
                            .attachments
                            .iter()
                            .map(|a| a.reference.clone())
                            .collect(),
                        caption,
                        client_token,
                    )
                    .await;
                match submission {
                    Ok(accepted) => Some(accepted),
                    Err(error) => {
                        let cleanup = (|| -> Result<(), AppError> {
                            let resolved = runtime.accounts.resolve(&account)?;
                            let slots = upload
                                .attachments
                                .iter()
                                .map(|a| {
                                    serde_json::to_value(a.reference.imeta_tag()).map_err(|_| {
                                        AppError::InvalidEncryptedMedia(
                                            "invalid upload descriptor".into(),
                                        )
                                    })
                                })
                                .collect::<Result<Vec<_>, _>>()?;
                            runtime
                                .accounts
                                .app
                                .account_storage(&resolved.label)?
                                .abandon_bound_attachment_uploads(
                                    &hex::encode(group.as_slice()),
                                    &slots,
                                )?;
                            Ok(())
                        })();
                        return Err(crate::client::preserve_encrypted_media_upload_error(
                            error, cleanup,
                        ));
                    }
                }
            } else {
                None
            };
            Ok((upload, accepted))
        })
        .await
        .map_err(|_| AppError::TransportClosed)?
    }

    pub fn local_send_status(
        &self,
        account: &str,
        group: &GroupId,
        token: &str,
    ) -> Result<Option<crate::LocalSendStatus>, AppError> {
        self.accounts.shared.lifecycle().ensure_running()?;
        let account = self.accounts.resolve(account)?;
        let submission = self
            .accounts
            .app
            .account_storage(&account.label)?
            .local_submission(&hex::encode(group.as_slice()), token)?;
        #[cfg(feature = "experimental-device-sync")]
        if submission.is_none() {
            return self
                .accounts
                .app
                .forwarded_local_send_status(&account.label, group, token);
        }
        submission
            .map(|s| {
                Ok(if let Some(json) = s.outcome_json {
                    crate::LocalSendStatus::Completed(
                        crate::local_submissions::decode_local_outcome(&json)?,
                    )
                } else {
                    match s.state {
                        0 => crate::LocalSendStatus::Queued,
                        1 => crate::LocalSendStatus::EngineOwned,
                        _ => crate::LocalSendStatus::Rejected,
                    }
                })
            })
            .transpose()
    }

    pub async fn submit_media_attachments(
        &self,
        account: &str,
        group: &GroupId,
        attachments: Vec<MediaAttachmentReference>,
        caption: Option<String>,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: caption.unwrap_or_default(),
                reply_to: None,
                attachments,
            },
            None,
            None,
        )
        .await
    }

    /// Persist local ownership and correlation before returning. Publication is
    /// independent of this future. Reusing a token with the same request returns
    /// the same identity unless its attempt was rejected before engine acceptance.
    /// Rejected attempts require a new token; a changed request is also rejected.
    pub async fn submit_text(
        &self,
        account: &str,
        group: &GroupId,
        text: String,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: text,
                reply_to: None,
                attachments: vec![],
            },
            None,
            None,
        )
        .await
    }

    pub async fn submit_reply(
        &self,
        account: &str,
        group: &GroupId,
        target: String,
        text: String,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: text,
                reply_to: Some(target),
                attachments: vec![],
            },
            None,
            None,
        )
        .await
    }

    pub async fn submit_message_draft(
        &self,
        account: &str,
        group: &GroupId,
        revision: crate::MessageDraftRevision,
        attachments: Vec<MediaAttachmentReference>,
        client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            client_token,
            LocalMessageRequest {
                content: String::new(),
                reply_to: None,
                attachments,
            },
            Some(revision),
            None,
        )
        .await
    }

    /// Admit an edit tied to a durable local send. The edit is retained across
    /// restart and the worker publishes it only after the original is engine-owned.
    pub async fn submit_edit_for_local_send(
        &self,
        account: &str,
        group: &GroupId,
        original_client_token: String,
        content: String,
        edit_client_token: String,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.submit_local_message(
            account,
            group,
            edit_client_token,
            LocalMessageRequest {
                content,
                reply_to: None,
                attachments: vec![],
            },
            None,
            Some(original_client_token),
        )
        .await
    }

    async fn submit_local_message(
        &self,
        account: &str,
        group: &GroupId,
        token: String,
        request: LocalMessageRequest,
        draft: Option<crate::MessageDraftRevision>,
        edit_of_client_token: Option<String>,
    ) -> Result<crate::LocalSendAcceptance, AppError> {
        self.accounts.worker_commands(account).await?;
        let account = self.accounts.resolve(account)?;
        #[cfg(feature = "experimental-device-sync")]
        let forwarding = (self.accounts.clone(), account.label.clone());
        let app = self.accounts.app.clone();
        let shared = self.accounts.shared.clone();
        let events = self.accounts.events.clone();
        let group = group.clone();
        // Classification and its continuation belong to one owned task, so
        // cancelling the host's wait cannot abandon a forwarded submission.
        let admission = async move {
            let outcome = blocking_app_task(move || {
                // This blocking task owns only its account's admission gate. The
                // worker cannot select a commit before timing registration; other
                // accounts never wait for this database. Global map locks stay short.
                let gate = shared.local_submission_gate(&account.account_id_hex);
                let admission = gate.blocking_lock();
                shared.lifecycle().ensure_running()?;
                #[cfg(feature = "experimental-device-sync")]
                {
                    use cgka_traits::storage::GroupStorage;
                    match app.account_storage(&account.label)?.get_group(&group) {
                        Err(cgka_traits::storage::StorageError::NotFound) => {
                            if draft.is_some() || edit_of_client_token.is_some() {
                                return Err(crate::AppError::InvalidAppMessagePayload(
                                    "forwarded draft correlation is unavailable".into(),
                                ));
                            }
                            return Ok(LocalSubmissionAdmission::Forwarded(Box::new(
                                ForwardedLocalSubmission {
                                    group,
                                    token,
                                    request,
                                },
                            )));
                        }
                        Err(error) => return Err(error.into()),
                        Ok(_) => {}
                    }
                }
                let (accepted, update) = if let Some(original) = edit_of_client_token {
                    app.admit_local_message_with_edit_at(
                        &account.label,
                        &group,
                        token,
                        request,
                        draft,
                        Some(original),
                        crate::unix_now_seconds(),
                    )?
                } else {
                    app.admit_local_message(&account.label, &group, token, request, draft)?
                };
                if update.is_some() {
                    let mut queue = shared
                        .local_submission_queue
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    // Shutdown sets stopping before clearing under this same map
                    // lock. Recheck here so no admission can register after clear.
                    if !shared.lifecycle().is_stopping() {
                        queue.admitted(
                            &account.account_id_hex,
                            &hex::encode(group.as_slice()),
                            &accepted.message_id_hex,
                            &shared.app_performance_telemetry(),
                        );
                    }
                }
                drop(admission);
                if let Some(update) = update {
                    account_worker::publish_app_runtime_projection_update(
                        &events,
                        &account.account_id_hex,
                        &account.label,
                        update,
                    );
                }
                shared.local_submission_wakeups.send_replace(());
                #[cfg(feature = "experimental-device-sync")]
                {
                    Ok(LocalSubmissionAdmission::Local(accepted))
                }
                #[cfg(not(feature = "experimental-device-sync"))]
                {
                    Ok(accepted)
                }
            })
            .await?;
            #[cfg(feature = "experimental-device-sync")]
            {
                match outcome {
                    LocalSubmissionAdmission::Local(accepted) => Ok(accepted),
                    LocalSubmissionAdmission::Forwarded(submission) => {
                        let (accounts, label) = forwarding;
                        let ForwardedLocalSubmission {
                            group,
                            token,
                            request,
                        } = *submission;
                        accounts
                            .admit_forwarded_chat(&label, group, token, request)
                            .await
                    }
                }
            }
            #[cfg(not(feature = "experimental-device-sync"))]
            {
                Ok(outcome)
            }
        };
        #[cfg(feature = "experimental-device-sync")]
        {
            tokio::spawn(admission)
                .await
                .map_err(|_| crate::AppError::TransportClosed)?
        }
        #[cfg(not(feature = "experimental-device-sync"))]
        {
            admission.await
        }
    }
}
