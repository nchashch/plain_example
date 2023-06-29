use heed::types::*;
use heed::{RoTxn, RwTxn};
pub use plain_authorization::Authorization;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CustomContent;

impl plain_types::GetValue for CustomContent {
    fn get_value(&self) -> u64 {
        0
    }
}

#[derive(Clone)]
pub struct CustomState {
    custom_db: heed::Database<OwnedType<[u8; 32]>, OwnedType<[u8; 32]>>,
}

impl plain_node::State<Authorization, CustomContent> for CustomState {
    type Error = heed::Error;
    const NUM_DBS: u32 = 1;
    fn new(env: &heed::Env) -> std::result::Result<Self, Self::Error> {
        let custom_db = env.create_database(Some("custom_db"))?;
        Ok(Self { custom_db })
    }

    fn validate_body(
        &self,
        txn: &RoTxn,
        state: &plain_state::State<Authorization, CustomContent>,
        body: &plain_types::Body<Authorization, CustomContent>,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn validate_filled_transaction(
        &self,
        txn: &RoTxn,
        state: &plain_state::State<Authorization, CustomContent>,
        transaction: &plain_types::FilledTransaction<CustomContent>,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }

    fn connect_body(
        &self,
        txn: &mut RwTxn,
        state: &plain_state::State<Authorization, CustomContent>,
        body: &plain_types::Body<Authorization, CustomContent>,
    ) -> std::result::Result<(), Self::Error> {
        Ok(())
    }
}
