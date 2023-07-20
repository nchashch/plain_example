use std::{collections::HashSet, net::SocketAddr, path::PathBuf, str::FromStr};

use custom::{Authorization, CustomContent, CustomState};
use eframe::egui;
use futures::task::LocalSpawnExt;
use plain_miner::MainClient as _;
use plain_types::bitcoin;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let native_options = eframe::NativeOptions::default();
    let app = MyEguiApp::new().await?;
    eframe::run_native("My egui App", native_options, Box::new(|cc| Box::new(app)));
    Ok(())
}

type Node = plain_node::Node<Authorization, CustomContent, CustomState>;
type Wallet = plain_wallet::Wallet<CustomContent>;
type Miner = plain_miner::Miner<Authorization, CustomContent>;

type Output = plain_types::Output<CustomContent>;
type AuthorizedTransaction = plain_types::AuthorizedTransaction<Authorization, CustomContent>;

#[derive(Clone)]
struct Config {
    net_addr: SocketAddr,
    datadir: PathBuf,
}

#[derive(Clone)]
struct MyEguiApp {
    node: Node,
    wallet: Wallet,
    miner: Miner,
    config: Config,
    seed: String,
    passphrase: String,
    address: Option<plain_types::Address>,
    deposit: bool,
    bmm_bribe: String,

    destination: String,
    value: String,
    fee: String,

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
        let config = Config { net_addr, datadir };

        let (mine_tx, mut mine_rx) = tokio::sync::mpsc::channel(32);
        let app = MyEguiApp {
            node,
            wallet,
            miner,
            config,
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

            destination: "".into(),
            value: "".into(),
            fee: "0.001".into(),
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

    fn addresses(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .max_height(300.)
            .show(ui, |ui| {
                let addresses = self.wallet.get_addresses().unwrap_or(HashSet::new());
                let mut addresses: Vec<_> = addresses.into_iter().collect();
                addresses.sort_by_key(|address| format!("{address}"));
                for address in addresses[..10].iter() {
                    let mut address = if self.deposit {
                        format_deposit_address(&format!("{address}"))
                    } else {
                        format!("{address}")
                    };
                    let address_edit =
                        egui::TextEdit::singleline(&mut address).hint_text("address");
                    ui.add(address_edit);
                    ui.end_row();
                }
            });
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

    fn get_new_address(&mut self, ui: &mut egui::Ui) {
        let mut address = self
            .address
            .map(|address| {
                if self.deposit {
                    format_deposit_address(&format!("{address}"))
                } else {
                    format!("{address}")
                }
            })
            .unwrap_or("".into());
        let address_edit = egui::TextEdit::singleline(&mut address).hint_text("address");
        ui.add(address_edit);
        ui.horizontal(|ui| {
            if ui.button("new address").clicked() {
                let address = self.wallet.get_new_address().unwrap();
                self.address = Some(address);
            }
            ui.checkbox(&mut self.deposit, "Deposit");
        });

        let num_addresses = self.wallet.get_num_addresses().unwrap();
        ui.label(format!("{num_addresses} addresses generated"));
    }

    fn balance(&mut self, ui: &mut egui::Ui) {
        let balance = self.wallet.get_balance().unwrap();
        let balance = bitcoin::Amount::from_sat(balance);
        let mut balance = balance.to_string_in(bitcoin::Denomination::Bitcoin);
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut balance);
            ui.label("BTC");
        });
    }

    fn utxos(&mut self, ui: &mut egui::Ui) {
        let mut utxos: Vec<_> = self.wallet.get_utxos().unwrap().into_iter().collect();
        utxos.sort_by_key(|(outpoint, _)| plain_types::hash(outpoint));
        let deposits = utxos
            .iter()
            .filter(|(outpoint, _)| matches!(outpoint, plain_types::OutPoint::Deposit(_)));
        let regulars = utxos
            .iter()
            .filter(|(outpoint, _)| matches!(outpoint, plain_types::OutPoint::Regular { .. }));
        let coinbases = utxos
            .iter()
            .filter(|(outpoint, _)| matches!(outpoint, plain_types::OutPoint::Coinbase { .. }));
        egui::CollapsingHeader::new("Deposits").show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(300.)
                .show(ui, |ui| {
                    egui::Grid::new("regulars")
                        .striped(true)
                        .max_col_width(400.)
                        .show(ui, |ui| {
                            for (outpoint, output) in deposits {
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

        egui::CollapsingHeader::new("Regulars").show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(300.)
                .show(ui, |ui| {
                    egui::Grid::new("regulars")
                        .striped(true)
                        .max_col_width(400.)
                        .show(ui, |ui| {
                            for (outpoint, output) in regulars {
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

        egui::CollapsingHeader::new("Coinbases").show(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(300.)
                .show(ui, |ui| {
                    egui::Grid::new("coinbases")
                        .striped(true)
                        .max_col_width(400.)
                        .show(ui, |ui| {
                            for (outpoint, output) in coinbases {
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
        }
    }

    fn send(&mut self, ui: &mut egui::Ui) {
        let destination_edit =
            egui::TextEdit::singleline(&mut self.destination).hint_text("Destination Address");
        ui.add(destination_edit);
        let value_edit = egui::TextEdit::singleline(&mut self.value).hint_text("Value");
        ui.add(value_edit);
        let fee_edit = egui::TextEdit::singleline(&mut self.fee).hint_text("Fee");
        ui.add(fee_edit);
        if ui.button("Send").clicked() {
            let destination: Option<plain_types::Address> = self.destination.parse().ok();
            let value: Option<bitcoin::Amount> =
                bitcoin::Amount::from_str_in(&self.value, bitcoin::Denomination::Bitcoin).ok();
            let fee: Option<bitcoin::Amount> =
                bitcoin::Amount::from_str_in(&self.fee, bitcoin::Denomination::Bitcoin).ok();

            dbg!(destination, value, fee);
            match (destination, value, fee) {
                (Some(destination), Some(value), Some(fee)) => {
                    let transaction = self
                        .wallet
                        .create_transaction(destination, value.to_sat(), fee.to_sat())
                        .unwrap();
                    let transaction = self.wallet.authorize(transaction).unwrap();
                    if futures::executor::block_on(self.node.submit_transaction(&transaction))
                        .is_err()
                    {
                        self.error = true;
                        self.error_text = "Can't add double spending transaction.".into();
                    }
                }
                _ => {}
            }
        }
    }
}

impl eframe::App for MyEguiApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // ctx.set_pixels_per_point(2.);
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.wallet.has_seed().unwrap() {
                egui::Window::new("Error")
                    .open(&mut self.error)
                    .show(ctx, |ui| {
                        ui.label(&self.error_text);
                    });
                egui::Window::new("Miner").show(ctx, |ui| {
                    self.blockchain(ui);
                });
                egui::Window::new("Deposit").show(ctx, |ui| {
                    self.deposit(ui);
                });
                egui::Window::new("Spendable UTXOs").show(ctx, |ui| {
                    self.utxos(ui);
                });
                egui::Window::new("Wallet").show(ctx, |ui| {
                    ui.heading("Balance");
                    self.balance(ui);
                    ui.heading("Receive Addresses");
                    self.get_new_address(ui);
                });
                egui::Window::new("Send").show(ctx, |ui| {
                    self.send(ui);
                });
                /*
                egui::Window::new("Seed").show(ctx, |ui| {
                    self.seed(ui);
                });
                */
            } else {
                ui.centered_and_justified(|ui| {});
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
