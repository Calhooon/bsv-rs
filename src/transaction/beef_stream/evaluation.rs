//! Local script settings, absent from the cursor and reapplied on resume.

use std::io::{Read, Seek, SeekFrom};

use crate::block::ChainParams;
use crate::script::{NotJudgedCause, ScriptFlags};

use super::{
    referenced_outpoints, AsyncStreamVerifier, ChainTip, Hash32, Headers, StreamError,
    StreamVerifier, Verdict,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Evaluation {
    pub(super) work: Option<u64>,
    pub(super) memory: Option<usize>,
    pub(super) chain: Option<ChainParams>,
}

impl Evaluation {
    pub(super) const NONE: Self = Self {
        work: None,
        memory: None,
        chain: None,
    };

    pub(super) fn flags(
        &self,
        tip: Option<ChainTip>,
        source_height: Option<u64>,
    ) -> Result<Option<ScriptFlags>, NotJudgedCause> {
        if let Some(chain) = &self.chain {
            let source_height = source_height
                .map(|height| {
                    u32::try_from(height)
                        .map_err(|_| NotJudgedCause::SourceHeightOverflow { height })
                })
                .transpose()?;
            return super::super::verification_flags::verification_flags(
                chain,
                tip.map(|t| t.height),
                source_height,
            )
            .map(Some);
        }
        Ok(None)
    }
}

impl<R: Read, H: Headers> StreamVerifier<R, H> {
    /// Selects the node's standard script word from these chain parameters,
    /// the headers' mining tip + 1 and each source's verified BUMP height.
    /// With no tip the latest era in the parameters applies; an unproven
    /// source takes the spend's era. Unsupported chain facts return
    /// [`Verdict::NotJudged`], with a typed cause, before script execution.
    ///
    /// Proven transactions still rely on their BUMP and run no script.
    /// Existing constructors without this builder keep SDK default evaluation.
    /// This is local configuration: reapply after every `resume`, including
    /// an in-memory cursor. Set it before stepping any transaction.
    #[must_use]
    pub fn with_chain_params(mut self, chain: ChainParams) -> Self {
        self.evaluation.chain = Some(chain);
        self
    }
}

impl AsyncStreamVerifier {
    /// As [`StreamVerifier::with_chain_params`], using the chain tracker's tip.
    /// Reapply after `resume` and set before feeding any transaction.
    #[must_use]
    pub fn with_chain_params(mut self, chain: ChainParams) -> Self {
        self.evaluation.chain = Some(chain);
        self
    }
}

/// Two-pass verification retaining only referenced output scripts, with the
/// node's standard word resolved inside the verifier from chain parameters,
/// the headers' tip and each source's verified BUMP height.
///
/// The no-tip and pre-Genesis rules are [`StreamVerifier::with_chain_params`]'s.
/// Structural, atomic, mining, value and resource checks are unchanged.
///
/// # Errors
/// Returns an I/O error if reading, seeking or rewinding the source fails;
/// byte and script refusals are returned as a [`Verdict`].
pub fn verify_stream_two_pass_with_chain_params<R: Read + Seek, H: Headers>(
    source: R,
    headers: H,
    subject: Option<Hash32>,
    chain: &ChainParams,
) -> std::io::Result<Verdict> {
    two_pass(source, headers, subject, Some(chain.clone()))
}

pub(super) fn two_pass<R: Read + Seek, H: Headers>(
    mut source: R,
    headers: H,
    subject: Option<Hash32>,
    chain: Option<ChainParams>,
) -> std::io::Result<Verdict> {
    let start = source.stream_position()?;
    let referenced = match referenced_outpoints(&mut source) {
        Ok(referenced) => referenced,
        Err(StreamError::Io(e)) => return Err(e),
        Err(StreamError::Refused(r)) => return Ok(r.into()),
    };
    source.seek(SeekFrom::Start(start))?;
    let mut verifier = StreamVerifier::retaining(source, headers, subject, referenced);
    verifier.evaluation.chain = chain;
    verifier.run()
}
