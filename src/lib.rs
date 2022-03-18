#![deny(
    clippy::all,
    clippy::missing_const_for_fn,
    clippy::pedantic,
    future_incompatible,
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    rustdoc::broken_intra_doc_links,
    unsafe_code,
    unused,
    warnings
)]

use core::fmt::{Debug, Display, Error as FmtError, Formatter};
use ed25519_dalek::{PublicKey, Verifier, PUBLIC_KEY_LENGTH};
use hex::FromHex;
use std::{error::Error, str};
use twilight_model::{application::interaction::Interaction, http::interaction::InteractionResponse};
use worker::{Request, Response};

/// Name of a required request header.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum InteractionRequestHeaderName {
    /// Signature header.
    Signature,
    /// Timestamp header.
    Timestamp,
}

impl InteractionRequestHeaderName {
    /// String name of the header.
    #[must_use = "retrieving the name of the header is not useful on its own"]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Signature => "x-signature-ed25519",
            Self::Timestamp => "x-signature-timestamp",
        }
    }
}

/// Interaction request could not be verified or otherwise processed.
#[derive(Debug)]
pub struct ProcessRequestError {
    kind: ProcessRequestErrorType,
    source: Option<Box<dyn Error>>,
}

impl ProcessRequestError {
    /// Immutable reference to the type of error that occurred.
    #[must_use = "retrieving the type has no effect if left unused"]
    pub const fn kind(&self) -> &ProcessRequestErrorType {
        &self.kind
    }

    /// Consume the error, returning the source error if there is any.
    #[must_use = "consuming the error and retrieving the source has no effect if left unused"]
    pub fn into_source(self) -> Option<Box<dyn Error>> {
        self.source
    }

    /// Consume the error, returning the owned error type and the source error.
    #[must_use = "consuming the error into its parts has no effect if left unused"]
    pub fn into_parts(
        self,
    ) -> (
        ProcessRequestErrorType,
        Option<Box<dyn Error>>,
    ) {
        (self.kind, None)
    }

    /// Create a response for the error.
    ///
    /// The returned response has a status code of 500 (Internal Service Error),
    /// with a message equal to the Display implementation for the error.
    #[must_use = "created responses must be used to actually send the response"]
    pub fn response(&self) -> Response {
        Response::error(self.to_string(), 500).expect("status code is valid")
    }
}

impl Display for ProcessRequestError {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        match self.kind() {
            ProcessRequestErrorType::ChunkingBody => {
                f.write_str("failed to chunk request body")?;
            }
            ProcessRequestErrorType::DeserializingInteraction { body } => {
                f.write_str("failed to deserialize request body as interaction: ")?;

                if let Ok(text) = str::from_utf8(body) {
                    Display::fmt(text, f)?;
                } else {
                    Debug::fmt(body, f)?;
                }
            },
            ProcessRequestErrorType::FromHex => {
                f.write_str("failed to register public key")?;
            }
            ProcessRequestErrorType::InvalidPublicKey => {
                f.write_str("public key is invalid")?;
            }
            ProcessRequestErrorType::InvalidSignature => {
                f.write_str("signature is invalid")?;
            }
            ProcessRequestErrorType::MissingHeader { header } => {
                f.write_str("header '")?;
                f.write_str(header.name())?;
                f.write_str("' is invalid")?;
            }
        }

        Ok(())
    }
}

impl Error for ProcessRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| &**source as &(dyn Error + 'static))
    }
}

/// Type of [`ProcessRequestError`] that occurred.
#[derive(Debug)]
pub enum ProcessRequestErrorType {
    /// Failed to chunk the request body.
    ChunkingBody,
    /// Failed to deserialize the request's interaction body.
    DeserializingInteraction {
        /// Body of the request.
        body: Vec<u8>,
    },
    /// Public key is not in a valid format.
    FromHex,
    /// Public key is invalid.
    InvalidPublicKey,
    /// Request signature could not be verified.
    InvalidSignature,
    /// Required verification header is not present.
    MissingHeader {
        /// Name of the missing header.
        header: InteractionRequestHeaderName,
    },
}

/// Process a request, returning the request's interaction body if the request
/// is valid.
///
/// # Errors
///
/// Returns an error of type [`ChunkingBody`] if the request body could not be
/// chunked.
///
/// Returns an error of type [`DeserializingInteraction`] if the request body
/// could not be deserialized as an interaction.
///
/// Returns an error of type [`FromHex`] if the provided public key is not in a
/// valid format.
///
/// Returns an error of type [`InvalidPublicKey`] if the provided public key is
/// invalid.
///
/// Returns an error of type [`InvalidSignature`] if the request signature could
/// not be verified.
///
/// Returns an error of type [`MissingHeader`] if a required verification header
/// is not present.
pub async fn process(
    req: &mut Request,
    public_key: &str,
) -> Result<Interaction, ProcessRequestError> {
    // Extract the timestamp header for use later to check the signature.
    let timestamp = req
        .headers()
        .get(InteractionRequestHeaderName::Timestamp.name())
        .expect("header name is valid")
        .ok_or(ProcessRequestError {
            kind: ProcessRequestErrorType::MissingHeader {
                header: InteractionRequestHeaderName::Timestamp,
            },
            source: None,
        })?;

    let signature_header = req
        .headers()
        .get(InteractionRequestHeaderName::Signature.name())
        .expect("header name is valid")
        .ok_or(ProcessRequestError {
            kind: ProcessRequestErrorType::MissingHeader {
                header: InteractionRequestHeaderName::Signature,
            },
            source: None,
        })?;

    let signature = signature_header
        .parse()
        .map_err(|source| ProcessRequestError {
            kind: ProcessRequestErrorType::InvalidSignature,
            source: Some(Box::new(source)),
        })?;

    let hex = <[u8; PUBLIC_KEY_LENGTH] as FromHex>::from_hex(public_key).map_err(|source| {
        ProcessRequestError {
            kind: ProcessRequestErrorType::FromHex,
            source: Some(Box::new(source)),
        }
    })?;
    let key = PublicKey::from_bytes(&hex).map_err(|source| ProcessRequestError {
        kind: ProcessRequestErrorType::InvalidPublicKey,
        source: Some(Box::new(source)),
    })?;

    // Fetch the whole body of the request as that is needed to check the
    // signature against.
    let body = req.bytes().await.map_err(|source| ProcessRequestError {
        kind: ProcessRequestErrorType::ChunkingBody,
        source: Some(Box::new(source)),
    })?;

    // Check if the signature matches and else return a error response.
    let message = Vec::from([timestamp.as_bytes(), &body]).concat();

    if let Err(source) = key.verify(&message, &signature) {
        return Err(ProcessRequestError {
            source: Some(Box::new(source)),
            kind: ProcessRequestErrorType::InvalidSignature,
        });
    }

    // Deserialize the body into a interaction.
    serde_json::from_slice(&body).map_err(|source| ProcessRequestError {
        kind: ProcessRequestErrorType::DeserializingInteraction { body },
        source: Some(Box::new(source)),
    })
}

/// Create a new worker response from an interaction response.
///
/// Sets the `Content-Type` header to a value of `application/json`.
///
/// If the interaction response could not be serialized then a 500 response is
/// created noting that the response could not be serialized.
#[must_use = "created responses must be used to actually send the response"]
pub fn response(response: &InteractionResponse) -> Response {
    let json = if let Ok(json) = serde_json::to_string(response) {
        json
    } else {
        return Response::error("failed to serialize interaction response", 500)
            .expect("status code is within acceptable range");
    };

    let mut response = Response::ok(json).expect("creating a response shouldn't fail");
    response.headers_mut().set("Content-Type", "application/json")
        .expect("Content-Type header is valid");

    response
}
