use std::{collections::HashSet, net::SocketAddr, path::PathBuf, str::FromStr};

use custom::{Authorization, CustomContent, CustomState};
use eframe::egui;
use plain_miner::MainClient as _;
use plain_types::bitcoin;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let native_options = eframe::NativeOptions::default();
    let app = MyEguiApp::new()?;
    eframe::run_native("My egui App", native_options, Box::new(|cc| Box::new(app)));
    Ok(())
}

type Node = plain_node::Node<Authorization, CustomContent, CustomState>;
type Wallet = plain_wallet::Wallet<CustomContent>;
type Miner = plain_miner::Miner<Authorization, CustomContent>;

type Output = plain_types::Output<CustomContent>;
type AuthorizedTransaction = plain_types::AuthorizedTransaction<Authorization, CustomContent>;

struct Config {
    net_addr: SocketAddr,
    datadir: PathBuf,
}

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

    deposit_amount: String,
    deposit_fee: String,
}

impl MyEguiApp {
    fn new() -> anyhow::Result<Self> {
        const DEFAULT_NET_PORT: u16 = 4000;
        let net_port = DEFAULT_NET_PORT;
        let net_addr: SocketAddr = format!("127.0.0.1:{net_port}").parse()?;
        let datadir = project_root::get_project_root()?.join("target/plain");
        let node = Node::new(&datadir, net_addr, "localhost", 18443)?;
        let wallet_path = datadir.join("wallet.mdb");
        let wallet = Wallet::new(&wallet_path)?;
        let miner = Miner::new(0, "localhost", 18443)?;
        let config = Config { net_addr, datadir };
        Ok(MyEguiApp {
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
            deposit_fee: "".into(),
        })
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
                    ui.text_edit_singleline(&mut address);
                    ui.end_row();
                }
            });
    }

    fn seed(&mut self, ui: &mut egui::Ui) {
        let seed_edit = egui::TextEdit::singleline(&mut self.seed).hint_text("seed");
        ui.add(seed_edit);
        let passphrase_edit =
            egui::TextEdit::singleline(&mut self.passphrase).hint_text("passphrase");
        ui.add(passphrase_edit);
        if ui.button("set seed").clicked() {
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
    }

    fn balance(&mut self, ui: &mut egui::Ui) {
        let balance = self.wallet.get_balance().unwrap();
        let balance = bitcoin::Amount::from_sat(balance);
        let mut balance = balance.to_string_in(bitcoin::Denomination::Bitcoin);
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut balance);
            ui.label("BTC");
        });
        if ui.button("Sync").clicked() {
            let addresses = self.wallet.get_addresses().unwrap();
            let utxos = self.node.get_utxos_by_addresses(&addresses).unwrap();
            let outpoints: Vec<_> = self.wallet.get_utxos().unwrap().into_keys().collect();
            let spent = self.node.get_spent_utxos(&outpoints).unwrap();
            self.wallet.put_utxos(&utxos).unwrap();
            self.wallet.delete_utxos(&spent).unwrap();
        }
    }

    fn utxos(&mut self, ui: &mut egui::Ui) {
        let mut utxos: Vec<_> = self.wallet.get_utxos().unwrap().into_iter().collect();
        utxos.sort_by_key(|(outpoint, _)| plain_types::hash(outpoint));
        egui::ScrollArea::vertical()
            .max_height(300.)
            .show(ui, |ui| {
                egui::Grid::new("utxos")
                    .striped(true)
                    .max_col_width(400.)
                    .show(ui, |ui| {
                        for (outpoint, output) in &utxos {
                            ui.vertical(|ui| {
                                ui.label(format!("outpoint: {outpoint}"));
                                ui.label(format!("address: {}", output.address,));
                                ui.label(format!("content: {:?}", output.content));
                            });
                            ui.end_row();
                        }
                    });
            });
    }

    fn deposit(&mut self, ui: &mut egui::Ui) {
        ui.text_edit_singleline(&mut self.deposit_amount);
        let amount =
            bitcoin::Amount::from_str_in(&self.deposit_amount, bitcoin::Denomination::Bitcoin)
                .unwrap_or(bitcoin::Amount::ZERO);
        ui.label(format!("{amount}"));
        ui.text_edit_singleline(&mut self.deposit_fee);
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
        ui.text_edit_singleline(&mut self.bmm_bribe);
        let bribe = bitcoin::Amount::from_str_in(&self.bmm_bribe, bitcoin::Denomination::Bitcoin)
            .unwrap_or(bitcoin::Amount::ZERO);
        ui.label(format!("{bribe}"));
        if ui.button("attempt bmm").clicked() {
            const NUM_TRANSACTIONS: usize = 1000;
            let (transactions, fee) = self.node.get_transactions(NUM_TRANSACTIONS).unwrap();
            let coinbase = match fee {
                0 => vec![],
                _ => vec![Output {
                    address: self.wallet.get_new_address().unwrap(),
                    content: plain_types::Content::Value(fee),
                }],
            };
            let body = plain_types::Body::new(transactions, coinbase);
            let prev_side_hash = self.node.get_best_hash().unwrap();
            // FIXME: Do this in a tokio task, so the app does not freeze.
            let prev_main_hash =
                futures::executor::block_on(self.miner.drivechain.get_mainchain_tip()).unwrap();
            let header = plain_types::Header {
                merkle_root: body.compute_merkle_root(),
                prev_side_hash,
                prev_main_hash,
            };
            futures::executor::block_on(self.miner.attempt_bmm(bribe.to_sat(), 0, header, body))
                .unwrap();
            futures::executor::block_on(self.miner.generate()).unwrap();
            if let Some((header, body)) =
                futures::executor::block_on(self.miner.confirm_bmm()).unwrap_or_else(|_err| None)
            {
                futures::executor::block_on(self.node.submit_block(&header, &body)).unwrap();
            }
        }
    }
}

impl eframe::App for MyEguiApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        // ctx.set_pixels_per_point(2.);
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::Window::new("Blockchain").show(ctx, |ui| {
                self.blockchain(ui);
            });
            egui::Window::new("Wallet").show(ctx, |ui| {
                ui.heading("Balance");
                self.balance(ui);
                ui.collapsing("Deposit", |ui| {
                    self.deposit(ui);
                });
                ui.collapsing("UTXOs", |ui| {
                    self.utxos(ui);
                });
                ui.heading("Receive Addresses");
                self.get_new_address(ui);
                ui.collapsing("Addresses", |ui| {
                    self.addresses(ui);
                });
                ui.collapsing("Seed", |ui| {
                    self.seed(ui);
                });
            });
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
