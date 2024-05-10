use jsonwebkey as jwk;
use std::{fs, path::PathBuf, str::FromStr};

use consts::MAX_TX_DATA;
use crypto::base64::Base64;
use error::Error;
use futures::{stream, Stream, StreamExt};
use pretend::StatusCode;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use transaction::{
    client::TxClient,
    tags::{FromUtf8Strs, Tag},
    Tx,
};
use types::TxStatus;
use upload::Uploader;
use verify::{verify, verify_transaction};

pub mod client;
pub mod consts;
pub mod crypto;
pub mod currency;
pub mod error;
pub mod network;
pub mod signer;
pub mod transaction;
pub mod types;
pub mod upload;
mod verify;
pub mod wallet;

pub use signer::ArweaveSigner;

#[derive(Serialize, Deserialize, Debug)]
pub struct OraclePrice {
    pub arweave: OraclePricePair,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OraclePricePair {
    pub usd: f32,
}

pub struct Arweave {
    pub base_url: url::Url,
    pub signer: Option<ArweaveSigner>,
    tx_client: TxClient,
    uploader: Uploader,
}

#[derive(Default)]
pub struct ArweaveBuilder {
    base_url: Option<url::Url>,
    keypair_path: Option<PathBuf>,
    jwk: Option<jwk::JsonWebKey>,
}

impl ArweaveBuilder {
    pub fn new() -> ArweaveBuilder {
        Default::default()
    }

    pub fn base_url(mut self, url: url::Url) -> ArweaveBuilder {
        self.base_url = Some(url);
        self
    }

    pub fn keypair_path(mut self, keypair_path: PathBuf) -> ArweaveBuilder {
        self.keypair_path = Some(keypair_path);
        self
    }

    pub fn jwk(mut self, jwk: jwk::JsonWebKey) -> ArweaveBuilder {
        self.jwk = Some(jwk);
        self
    }

    pub fn build(self) -> Result<Arweave, Error> {
        let base_url = self
            .base_url
            .unwrap_or_else(|| url::Url::from_str(consts::ARWEAVE_BASE_URL).unwrap()); //Checked unwrap

        let signer = match self.keypair_path {
            Some(p) => Some(ArweaveSigner::from_keypair_path(p)?),
            None => match self.jwk {
                Some(jwk) => Some(ArweaveSigner::from_jwk(jwk)),
                None => todo!(),
            },
        };

        Ok(Arweave {
            signer,
            base_url,
            tx_client: Default::default(),
            uploader: Default::default(),
        })
    }
}

impl Arweave {
    pub fn from_keypair_path(keypair_path: PathBuf, base_url: url::Url) -> Result<Arweave, Error> {
        let signer = Some(ArweaveSigner::from_keypair_path(keypair_path)?);
        let tx_client = TxClient::new(reqwest::Client::new(), base_url.clone())?;
        let uploader = Uploader::new(base_url.clone());
        let arweave = Arweave {
            base_url,
            signer,
            tx_client,
            uploader,
        };
        Ok(arweave)
    }

    pub async fn create_transaction(
        &self,
        target: Base64,
        other_tags: Vec<Tag<Base64>>,
        data: Vec<u8>,
        quantity: u128,
        fee: u64,
        auto_content_tag: bool,
    ) -> Result<Tx, Error> {
        let last_tx = self.get_last_tx().await?;
        let signer = match &self.signer {
            Some(s) => s,
            None => return Err(Error::NoneError("signer".to_owned())),
        };
        Tx::new(
            signer.get_provider(),
            target,
            data,
            quantity,
            fee,
            last_tx,
            other_tags,
            auto_content_tag,
        )
    }

    pub fn sign_transaction(&self, transaction: Tx) -> Result<Tx, Error> {
        let signer = match &self.signer {
            Some(s) => s,
            None => return Err(Error::NoneError("signer".to_owned())),
        };
        signer.sign_transaction(transaction)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let signer = match &self.signer {
            Some(s) => s,
            None => return Err(Error::NoneError("signer".to_owned())),
        };
        Ok(signer.sign(message)?.0)
    }

    pub fn verify_transaction(transaction: &Tx) -> Result<(), Error> {
        verify_transaction(transaction)
    }

    pub fn verify(pub_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), Error> {
        verify(pub_key, message, signature)
    }

    pub async fn post_transaction(&self, signed_transaction: Tx) -> Result<(String, u64), Error> {
        if signed_transaction.data.0.len() > MAX_TX_DATA as usize {
            self.post_transaction_chunks(signed_transaction, 100).await
        } else {
            self.tx_client
                .post_transaction(&signed_transaction)
                .await
                .map(|(id, reward)| (id.to_string(), reward))
        }
    }

    async fn get_last_tx(&self) -> Result<Base64, Error> {
        self.tx_client.get_last_tx().await
    }

    pub async fn get_fee(&self, target: Base64, data: Vec<u8>) -> Result<u64, Error> {
        self.tx_client.get_fee(target, data).await
    }

    pub async fn get_tx(&self, id: Base64) -> Result<(StatusCode, Option<Tx>), Error> {
        self.tx_client.get_tx(id).await
    }

    pub async fn get_tx_status(&self, id: Base64) -> Result<(StatusCode, Option<TxStatus>), Error> {
        self.tx_client.get_tx_status(id).await
    }

    pub fn get_pub_key(&self) -> Result<String, Error> {
        let signer = match &self.signer {
            Some(s) => s,
            None => return Err(Error::NoneError("signer".to_owned())),
        };
        Ok(signer.keypair_modulus().to_string())
    }

    pub fn get_wallet_address(&self) -> Result<String, Error> {
        let signer = match &self.signer {
            Some(s) => s,
            None => return Err(Error::NoneError("signer".to_owned())),
        };
        Ok(signer.wallet_address().to_string())
    }

    pub async fn upload_file_from_path(
        &self,
        file_path: PathBuf,
        additional_tags: Vec<Tag<Base64>>,
        fee: u64,
    ) -> Result<(String, u64), Error> {
        let mut auto_content_tag = true;
        let mut additional_tags = additional_tags;

        if let Some(content_type) = mime_guess::from_path(file_path.clone()).first() {
            auto_content_tag = false;
            let content_tag: Tag<Base64> =
                Tag::from_utf8_strs("Content-Type", content_type.as_ref())?;
            additional_tags.push(content_tag);
        }
        let data = fs::read(file_path)?;

        self.post_bytes(data, auto_content_tag, additional_tags, fee)
            .await
    }

    pub async fn upload_bytes<T: AsRef<[u8]>>(
        &self,
        buffer: T,
        mime_type: Option<&str>,
        additional_tags: Vec<Tag<Base64>>,
        fee: u64,
    ) -> Result<(String, u64), Error> {
        let mut auto_content_tag = true;
        let mut additional_tags = additional_tags;
        if let Some(mime_type) = mime_type {
            let content_tag: Tag<Base64> = Tag::from_utf8_strs("Content-Type", mime_type)?;
            additional_tags.push(content_tag);
            auto_content_tag = false;
        };
        self.post_bytes(buffer, auto_content_tag, additional_tags, fee)
            .await
    }

    async fn post_bytes<T: AsRef<[u8]>>(
        &self,
        buffer: T,
        auto_content_tag: bool,
        additional_tags: Vec<Tag<Base64>>,
        fee: u64,
    ) -> Result<(String, u64), Error> {
        let transaction = self
            .create_transaction(
                Base64(b"".to_vec()),
                additional_tags,
                buffer.as_ref().into(),
                0,
                fee,
                auto_content_tag,
            )
            .await?;
        let signed_transaction = self.sign_transaction(transaction)?;
        self.post_transaction(signed_transaction).await
    }

    async fn post_transaction_chunks(
        &self,
        signed_transaction: Tx,
        chunks_buffer: usize,
    ) -> Result<(String, u64), Error> {
        if signed_transaction.id.0.is_empty() {
            return Err(error::Error::UnsignedTransaction);
        }

        let transaction_with_no_data = signed_transaction.clone_with_no_data()?;
        let (id, reward) = self
            .tx_client
            .post_transaction(&transaction_with_no_data)
            .await
            .map(|(id, reward)| (id.to_string(), reward))?;

        let results: Vec<Result<usize, Error>> =
            Self::upload_transaction_chunks_stream(self, signed_transaction, chunks_buffer)
                .collect()
                .await;

        results.into_iter().collect::<Result<Vec<usize>, Error>>()?;

        Ok((id, reward))
    }

    fn upload_transaction_chunks_stream(
        arweave: &Arweave,
        signed_transaction: Tx,
        buffer: usize,
    ) -> impl Stream<Item = Result<usize, Error>> + '_ {
        let client = Client::new();
        stream::iter(0..signed_transaction.chunks.len())
            .map(move |i| {
                let chunk = signed_transaction.get_chunk(i).unwrap(); //TODO: remove this unwrap
                arweave
                    .uploader
                    .post_chunk_with_retries(chunk, client.clone())
            })
            .buffer_unordered(buffer)
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Read, str::FromStr};

    use crate::{error::Error, transaction::Tx, verify::verify_transaction};

    #[test]
    pub fn should_parse_and_verify_valid_tx() -> Result<(), Error> {
        let mut file = File::open("res/sample_tx.json").unwrap();
        let mut data = String::new();
        file.read_to_string(&mut data).unwrap();
        let tx = Tx::from_str(&data).unwrap();

        match verify_transaction(&tx) {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::InvalidSignature),
        }
    }
}
