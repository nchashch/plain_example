use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    path::PathBuf,
    str::FromStr,
};

use custom::{Authorization, CustomContent, CustomState};
use eframe::egui;
use futures::task::LocalSpawnExt;
use plain_miner::MainClient as _;
use plain_types::{bitcoin, GetValue, OutPoint, Transaction};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let native_options = eframe::NativeOptions::default();
    let app = MyEguiApp::new().await?;
    eframe::run_native(
        "Plain Sidechain",
        native_options,
        Box::new(|cc| Box::new(app)),
    );
    Ok(())
}

type Node = plain_node::Node<Authorization, CustomContent, CustomState>;
type Wallet = plain_wallet::Wallet<CustomContent>;
type Miner = plain_miner::Miner<Authorization, CustomContent>;

type Output = plain_types::Output<CustomContent>;
type AuthorizedTransaction = plain_types::AuthorizedTransaction<Authorization, CustomContent>;
type FilledTransaction = plain_types::FilledTransaction<CustomContent>;

#[derive(Clone)]
struct MyEguiApp {
    node: Node,
    wallet: Wallet,
    miner: Miner,
    seed: String,
    passphrase: String,
    address: Option<plain_types::Address>,
    deposit: bool,
    bmm_bribe: String,

    transaction: FilledTransaction,
    output_address: String,
    output_value: String,
    output_main_address: String,
    output_main_fee: String,

    withdrawal: bool,

    utxos: HashMap<OutPoint, Output>,

    error: bool,
    error_text: String,

    deposit_amount: String,
    deposit_fee: String,
    mine_tx: tokio::sync::mpsc::Sender<()>,
}

impl MyEguiApp {
    async fn new() -> anyhow::Result<Self> {
        const DEFAULT_NET_PORT: u16 = 4000;
        let net_port = DEFAULT_NET_PORT;
        let net_addr: SocketAddr = format!("127.0.0.1:{net_port}").parse()?;
        let datadir = project_root::get_project_root()?.join("target/plain");
        let node = Node::new(&datadir, net_addr, "localhost", 18443)?;
        let wallet_path = datadir.join("wallet.mdb");
        let wallet = Wallet::new(&wallet_path)?;
        let miner = Miner::new(0, "localhost", 18443)?;

        let (mine_tx, mut mine_rx) = tokio::sync::mpsc::channel(32);
        let app = MyEguiApp {
            transaction: FilledTransaction {
                transaction: Transaction {
                    inputs: vec![],
                    outputs: vec![],
                },
                spent_utxos: vec![],
            },
            output_address: "".into(),
            output_value: "".into(),
            output_main_address: "".into(),
            output_main_fee: "".into(),

            withdrawal: false,
            utxos: wallet.get_utxos().unwrap(),
            node,
            wallet,
            miner,
            seed: "".into(),
            passphrase: "".into(),
            address: None,
            deposit: false,
            bmm_bribe: "0.001".into(),
            deposit_amount: "".into(),
            deposit_fee: "0.001".into(),
            mine_tx,

            error: false,
            error_text: "".into(),
        };
        let app0 = app.clone();
        tokio::task::spawn(async move {
            loop {
                let addresses = app0.wallet.get_addresses().unwrap();
                let utxos = app0.node.get_utxos_by_addresses(&addresses).unwrap();
                let outpoints: Vec<_> = app0.wallet.get_utxos().unwrap().into_keys().collect();
                let spent = app0.node.get_spent_utxos(&outpoints).unwrap();
                app0.wallet.put_utxos(&utxos).unwrap();
                app0.wallet.delete_utxos(&spent).unwrap();
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        });
        let mut app0 = app.clone();
        tokio::task::spawn(async move {
            loop {
                let _ = mine_rx.recv().await;
                const NUM_TRANSACTIONS: usize = 1000;
                let (transactions, fee) = app0.node.get_transactions(NUM_TRANSACTIONS).unwrap();
                let coinbase = match fee {
                    0 => vec![],
                    _ => vec![Output {
                        address: app0.wallet.get_new_address().unwrap(),
                        content: plain_types::Content::Value(fee),
                    }],
                };
                let body = plain_types::Body::new(transactions, coinbase);
                // dbg!(&body);
                let prev_side_hash = app0.node.get_best_hash().unwrap();
                let prev_main_hash = app0.miner.drivechain.get_mainchain_tip().await.unwrap();
                println!("got mainchain tip");
                let header = plain_types::Header {
                    merkle_root: body.compute_merkle_root(),
                    prev_side_hash,
                    prev_main_hash,
                };
                let bribe =
                    bitcoin::Amount::from_str_in(&app0.bmm_bribe, bitcoin::Denomination::Bitcoin)
                        .unwrap_or(bitcoin::Amount::ZERO);
                app0.miner
                    .attempt_bmm(bribe.to_sat(), 0, header, body)
                    .await
                    .unwrap();
                println!("attempted bmm");
                app0.miner.generate().await.unwrap();
                println!("generated block");
                if let Ok(Some((header, body))) = app0.miner.confirm_bmm().await {
                    let result = app0.node.submit_block(&header, &body).await;
                    println!("submitted block: {:?}", result);
                }
            }
        });
        Ok(app)
    }

    fn seed(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let seed_edit = egui::TextEdit::singleline(&mut self.seed).hint_text("seed");
            ui.add(seed_edit);
            if ui.button("generate").clicked() {
                use itertools::Itertools;
                use rand::prelude::*;

                let mut rng = rand::thread_rng();
                let entropy: [u8; 32] = rng.gen();
                let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
                self.seed = mnemonic.word_iter().intersperse(" ").collect();
            }
        });
        let passphrase_edit =
            egui::TextEdit::singleline(&mut self.passphrase).hint_text("passphrase");
        ui.add(passphrase_edit);
        if ui.button("set").clicked() {
            let seed = bip39::Mnemonic::parse(&self.seed)
                .unwrap()
                .to_seed(&self.passphrase);
            self.wallet.set_seed(seed).unwrap();
        }
    }

    fn deposit(&mut self, ui: &mut egui::Ui) {
        let deposit_amount_edit =
            egui::TextEdit::singleline(&mut self.deposit_amount).hint_text("deposit amount");
        ui.add(deposit_amount_edit);
        let amount =
            bitcoin::Amount::from_str_in(&self.deposit_amount, bitcoin::Denomination::Bitcoin)
                .unwrap_or(bitcoin::Amount::ZERO);
        ui.label(format!("{amount}"));
        let deposit_fee_edit =
            egui::TextEdit::singleline(&mut self.deposit_fee).hint_text("deposit fee");
        ui.add(deposit_fee_edit);
        let fee = bitcoin::Amount::from_str_in(&self.deposit_fee, bitcoin::Denomination::Bitcoin)
            .unwrap_or(bitcoin::Amount::ZERO);
        ui.label(format!("{fee}"));

        if ui.button("Deposit").clicked() {
            let address = self.wallet.get_new_address().unwrap();
            let address = format_deposit_address(&format!("{address}"));
            futures::executor::block_on(self.miner.drivechain.client.createsidechaindeposit(
                plain_node::THIS_SIDECHAIN,
                &address,
                amount.into(),
                fee.into(),
            ))
            .unwrap();
        }
    }

    fn blockchain(&mut self, ui: &mut egui::Ui) {
        let block_height = self.node.get_height().unwrap();
        let best_hash = self.node.get_best_hash().unwrap();
        ui.label(format!("Block height: {block_height}"));
        ui.label(format!("Best hash: {best_hash}"));
        let bribe_edit = egui::TextEdit::singleline(&mut self.bmm_bribe).hint_text("BMM bribe");
        ui.add(bribe_edit);
        let bribe = bitcoin::Amount::from_str_in(&self.bmm_bribe, bitcoin::Denomination::Bitcoin)
            .unwrap_or(bitcoin::Amount::ZERO);
        ui.label(format!("{bribe}"));
        if ui.button("attempt bmm").clicked() {
            self.mine_tx.try_send(()).unwrap_or_else(|err| {
                println!("failed to trigger miner: {err}");
            });
            self.utxos = self.wallet.get_utxos().unwrap();
            self.transaction = FilledTransaction {
                transaction: Transaction {
                    inputs: vec![],
                    outputs: vec![],
                },
                spent_utxos: vec![],
            };
        }
    }

    fn pending_withdrawal_bundle(&mut self, ui: &mut egui::Ui) {
        // TODO: Show how much time is left until it becomes spent or failed.
        // TODO: Check if mainchain miners are upvoting the wrong bundle.
        let withdrawal_bundle = self.node.get_pending_withdrawal_bundle().unwrap();
        match withdrawal_bundle {
            Some(bundle) => {
                use plain_types::GetValue;
                let pending_balance = bundle
                    .spent_utxos
                    .values()
                    .map(|output| output.content.get_value())
                    .sum::<u64>();
                let pending_balance = bitcoin::Amount::from_sat(pending_balance);
                let mut pending_balance =
                    pending_balance.to_string_in(bitcoin::Denomination::Bitcoin);
                ui.heading("Pending Balance");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut pending_balance);
                    ui.label("BTC");
                });
                ui.heading("Pending Bundle");
                let mut spent_utxos: Vec<_> = bundle.spent_utxos.iter().collect();
                spent_utxos.sort_by_key(|(outpoint, _)| plain_types::hash(outpoint));
                egui::CollapsingHeader::new("Pending Withdrawals").show(ui, |ui| {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        egui::Grid::new("pending_withdrawals")
                            .striped(true)
                            .max_col_width(400.)
                            .show(ui, |ui| {
                                for (outpoint, output) in spent_utxos {
                                    ui.vertical(|ui| {
                                        ui.label(format!("outpoint: {outpoint}"));
                                        ui.label(format!("address: {}", output.address,));
                                        ui.label(format!("content: {:?}", output.content));
                                    });
                                    ui.end_row();
                                }
                            });
                    });
                });
                egui::CollapsingHeader::new("Mainchain Transaction").show(ui, |ui| {
                    let mut txid_str = format!("{}", bundle.transaction.txid());
                    let mut transaction_str = format!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!(bundle.transaction))
                            .unwrap()
                    );
                    ui.label("Mainchain Withdrawal Bundle TXID");
                    ui.text_edit_singleline(&mut txid_str);
                    ui.label("Mainchain Withdrawal Bundle Transaction");
                    let main_transaction_edit =
                        egui::TextEdit::multiline(&mut transaction_str).code_editor();
                    ui.add(main_transaction_edit);
                });
            }
            None => {
                ui.label("No bundle pending.");
            }
        }
    }

    fn connections(&mut self, ui: &mut egui::Ui) {}
    fn outpoint(&mut self, ui: &mut egui::Ui) {}
    fn output(&mut self, ui: &mut egui::Ui) {}
    fn mempool(&mut self, ui: &mut egui::Ui) {}

    fn transaction(&mut self, ui: &mut egui::Ui) {
        ui.heading("Summary");
        egui::Grid::new("inputs")
            .striped(true)
            .max_col_width(400.)
            .show(ui, |ui| {
                let txid = self.transaction.transaction.txid();
                ui.label(format!("txid: {txid}"));
                ui.end_row();
                let value_in = bitcoin::Amount::from_sat(self.transaction.get_value_in());
                ui.label(format!("value_in: {value_in}"));
                ui.end_row();
                let value_out = bitcoin::Amount::from_sat(self.transaction.get_value_out());
                ui.label(format!("value_out: {value_out}"));
                ui.end_row();
                let fee = self.transaction.get_fee();
                match fee {
                    Some(fee) => {
                        let fee = bitcoin::Amount::from_sat(fee);
                        ui.label(format!("fee: {fee}"));
                    }
                    None => {
                        ui.label("value in < value out");
                    }
                }
                ui.end_row();
            });

        if ui
            .add_enabled(
                self.node
                    .state
                    .validate_filled_transaction(&self.transaction)
                    .is_ok(),
                egui::Button::new("Sign and Send"),
            )
            .clicked()
        {
            let transaction = self
                .wallet
                .authorize(self.transaction.transaction.clone())
                .unwrap();
            if futures::executor::block_on(self.node.submit_transaction(&transaction)).is_err() {
                self.error = true;
                self.error_text = "Can't add double spending transaction.".into();
            }
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::CollapsingHeader::new("Transaction Inputs").show(ui, |ui| {
                egui::Grid::new("inputs")
                    .striped(true)
                    .max_col_width(400.)
                    .show(ui, |ui| {
                        let mut removed = None;
                        for (index, (input, spent_utxo)) in self
                            .transaction
                            .transaction
                            .inputs
                            .iter()
                            .zip(self.transaction.spent_utxos.iter())
                            .enumerate()
                        {
                            ui.vertical(|ui| {
                                ui.label(format!("input: {input}"));
                                ui.label(format!("address: {}", spent_utxo.address,));
                                let value = bitcoin::Amount::from_sat(spent_utxo.get_value());
                                ui.label(format!("value: {}", value));
                                ui.label(format!("content: {:?}", spent_utxo.content));
                            });
                            if ui.button("Remove").clicked() {
                                self.utxos.insert(*input, spent_utxo.clone());
                                removed = Some(index);
                            }
                            ui.end_row();
                        }
                        if let Some(index) = removed {
                            self.transaction.transaction.inputs.remove(index);
                            self.transaction.spent_utxos.remove(index);
                        }
                    });
            });

            egui::CollapsingHeader::new("Transaction Outputs").show(ui, |ui| {
                egui::Grid::new("outputs")
                    .striped(true)
                    .max_col_width(400.)
                    .show(ui, |ui| {
                        let mut remove = None;
                        for (vout, output) in
                            self.transaction.transaction.outputs.iter().enumerate()
                        {
                            ui.vertical(|ui| {
                                ui.label(format!("vout: {vout}"));
                                ui.label(format!("address: {}", output.address,));
                                let value = bitcoin::Amount::from_sat(output.get_value());
                                ui.label(format!("value: {}", value));
                                ui.label(format!("content: {:?}", output.content));
                            });
                            if ui.button("Remove").clicked() {
                                remove = Some(vout);
                            }
                            ui.end_row();
                        }
                        if let Some(vout) = remove {
                            self.transaction.transaction.outputs.remove(vout);
                        }
                    });
            });
        });
    }

    fn transaction_builder(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.heading("Spend UTXOs");
                self.utxo_selector(ui);
            });
            ui.separator();
            ui.vertical(|ui| {
                self.transaction(ui);
            });
            ui.separator();
            ui.vertical(|ui| {
                ui.heading("Create Output");
                self.utxo_creator(ui);
            });
        });
    }

    fn utxo_selector(&mut self, ui: &mut egui::Ui) {
        let balance: u64 = self.utxos.values().map(GetValue::get_value).sum();
        let balance = bitcoin::Amount::from_sat(balance);
        let mut balance = balance.to_string_in(bitcoin::Denomination::Bitcoin);
        ui.heading("Total Funds Available");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut balance);
            ui.label("BTC");
        });
        ui.heading("UTXOs");
        let mut removed = vec![];
        let mut utxos: Vec<_> = self
            .utxos
            .iter()
            .map(|(outpoint, output)| (outpoint.clone(), output.clone()))
            .collect();
        utxos.sort_by_key(|(outpoint, _)| plain_types::hash(outpoint));
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("utxos")
                .striped(true)
                .max_col_width(400.)
                .show(ui, |ui| {
                    for (outpoint, output) in utxos {
                        ui.vertical(|ui| {
                            ui.label(format!("outpoint: {outpoint}"));
                            ui.label(format!("address: {}", output.address,));
                            let value = bitcoin::Amount::from_sat(output.get_value());
                            ui.label(format!("value: {}", value));
                            ui.label(format!("content: {:?}", output.content));
                        });
                        if ui.button("Select").clicked() {
                            self.transaction.transaction.inputs.push(outpoint);
                            self.transaction.spent_utxos.push(output);
                            removed.push(outpoint);
                        }
                        ui.end_row();
                    }
                });
        });
        for outpoint in &removed {
            self.utxos.remove(outpoint);
        }
    }

    fn utxo_creator(&mut self, ui: &mut egui::Ui) {
        ui.checkbox(&mut self.withdrawal, "Withdrawal");
        ui.horizontal(|ui| {
            let address_edit =
                egui::TextEdit::singleline(&mut self.output_address).hint_text("address");
            ui.add(address_edit);
            if ui.button("Generate").clicked() {
                let address = self.wallet.get_new_address().unwrap();
                self.output_address = format!("{address}");
            }
        });
        ui.horizontal(|ui| {
            let value_edit = egui::TextEdit::singleline(&mut self.output_value).hint_text("value");
            ui.add(value_edit);
            ui.label("BTC");
        });
        if self.withdrawal {
            ui.horizontal(|ui| {
                let main_address_edit = egui::TextEdit::singleline(&mut self.output_main_address)
                    .hint_text("main_address");
                ui.add(main_address_edit);
                if ui.button("Generate").clicked() {
                    let main_address = futures::executor::block_on(
                        self.miner.drivechain.client.getnewaddress("", "legacy"),
                    )
                    .unwrap();
                    let main_address: bitcoin::Address<bitcoin::address::NetworkChecked> =
                        main_address
                            .require_network(bitcoin::Network::Regtest)
                            .unwrap();
                    self.output_main_address = format!("{main_address}");
                }
            });
            ui.horizontal(|ui| {
                let main_fee_edit = egui::TextEdit::singleline(&mut self.output_main_fee)
                    .hint_text("Mainchain Fee");
                ui.add(main_fee_edit);
                ui.label("BTC");
            });
        }

        let address: Option<plain_types::Address> = self.output_address.parse().ok();
        let value: Option<bitcoin::Amount> =
            bitcoin::Amount::from_str_in(&self.output_value, bitcoin::Denomination::Bitcoin).ok();
        let main_address: Option<bitcoin::Address<bitcoin::address::NetworkUnchecked>> =
            self.output_main_address.parse().ok();
        let main_fee: Option<bitcoin::Amount> =
            bitcoin::Amount::from_str_in(&self.output_main_fee, bitcoin::Denomination::Bitcoin)
                .ok();
        if ui
            .add_enabled(
                address.is_some()
                    && value.is_some()
                    && (!self.withdrawal
                        || self.withdrawal && main_address.is_some() && main_fee.is_some()),
                egui::Button::new("Create"),
            )
            .clicked()
        {
            let output = if self.withdrawal {
                Output {
                    address: address.unwrap(),
                    content: plain_types::Content::Withdrawal {
                        value: value.unwrap().to_sat(),
                        main_address: main_address.unwrap(),
                        main_fee: main_fee.unwrap().to_sat(),
                    },
                }
            } else {
                Output {
                    address: address.unwrap(),
                    content: plain_types::Content::Value(value.unwrap().to_sat()),
                }
            };
            self.transaction.transaction.outputs.push(output);
        }
        let num_addresses = self.wallet.get_num_addresses().unwrap();
        ui.label(format!("{num_addresses} addresses generated"));
    }
}

impl eframe::App for MyEguiApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // ctx.set_pixels_per_point(2.);
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.wallet.has_seed().unwrap() {
                egui::SidePanel::left("left").show(ctx, |ui| {
                    ui.heading("Select UTXOs to Spend");
                    self.utxo_selector(ui);
                });
                egui::CentralPanel::default().show(ctx, |ui| {
                    self.transaction(ui);
                });
                egui::SidePanel::right("right").show(ctx, |ui| {
                    ui.heading("Create Output");
                    self.utxo_creator(ui);
                    ui.separator();
                    ui.heading("Miner");
                    self.blockchain(ui);
                    ui.separator();
                    ui.heading("Deposit");
                    self.deposit(ui);
                    ui.separator();
                    ui.heading("Pending Withdrawal Bundle");
                    self.pending_withdrawal_bundle(ui);
                });
                egui::Window::new("Error")
                    .open(&mut self.error)
                    .show(ctx, |ui| {
                        ui.label(&self.error_text);
                    });
            } else {
                ui.centered_and_justified(|_| {});
                ui.vertical_centered(|ui| {
                    ui.heading("Set Seed");
                    self.seed(ui);
                });
            }
        });
    }
}

/// Format `str_dest` with the proper `s{sidechain_number}_` prefix and a
/// checksum postfix for calling createsidechaindeposit on mainchain.
pub fn format_deposit_address(str_dest: &str) -> String {
    let this_sidechain = 0;
    let deposit_address: String = format!("s{}_{}_", this_sidechain, str_dest);
    let hash = sha256::digest(deposit_address.as_bytes()).to_string();
    let hash: String = hash[..6].into();
    format!("{}{}", deposit_address, hash)
}

// Testing seed 0: resist miss peasant neither curve near chef crush chapter patch run best
// Testing seed 1: valve six lady gossip muscle rather dry elephant void catalog elder surprise
