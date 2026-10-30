//! Exercise every changed public reader and the height/page response paths.
use bsv_rs::wallet::wire::{WalletWire, WalletWireTransceiver, WireReader};
use bsv_rs::wallet::{ListActionsArgs, ListOutputsArgs};
use bsv_rs::Error;

struct Answer(Vec<u8>);

#[async_trait::async_trait]
impl WalletWire for Answer {
    async fn transmit_to_wallet(&self, _: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.0.clone())
    }
}

pub fn exercise(data: &[u8]) {
    macro_rules! read {
        ($($method:ident),* $(,)?) => { $(let _ = WireReader::new(data).$method();)* };
    }
    read!(
        read_wallet_action,
        read_wallet_action_input,
        read_wallet_action_output,
        read_wallet_output,
        read_basket_insertion,
        read_sign_action_spends,
        read_send_with_result_array
    );
    let client = WalletWireTransceiver::new(Answer(data.to_vec()));
    futures::executor::block_on(async {
        let _ = client.get_height(None).await;
        let actions = ListActionsArgs {
            labels: Vec::new(),
            label_query_mode: None,
            include_labels: None,
            include_inputs: None,
            include_input_source_locking_scripts: None,
            include_input_unlocking_scripts: None,
            include_outputs: None,
            include_output_locking_scripts: None,
            limit: None,
            offset: None,
            seek_permission: None,
        };
        let _ = client.list_actions(actions, None).await;
        let outputs = ListOutputsArgs {
            basket: "fuzz".into(),
            tags: None,
            tag_query_mode: None,
            include: None,
            include_custom_instructions: None,
            include_tags: None,
            include_labels: None,
            limit: None,
            offset: None,
            seek_permission: None,
        };
        let _ = client.list_outputs(outputs, None).await;
        for call in [0, 1, 16] {
            crate::support::call_shared!(&client, call, None);
        }
    });
}
