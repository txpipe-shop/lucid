use super::*;

use crate::witness_builder::RedeemerWitnessKey;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    str::FromStr,
};
use uplc::{tx::eval_phase_two_raw, Hash};


#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use js_sys::*;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use serde_json::{Map, Value as Val};
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use wasm_bindgen::JsCast;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use wasm_bindgen_futures::JsFuture;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
use web_sys::{Request, RequestInit, Response};

// creates a custom window object to parse the fetch API from JavaScript into Rust;
#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen]
    pub type globalThis;

    # [wasm_bindgen (structural , method , getter , js_name = global)]
    pub fn global(this: &globalThis) -> globalThis;

    # [wasm_bindgen (structural , method , getter , js_name = self)]
    pub fn self_(this: &globalThis) -> globalThis;

    # [wasm_bindgen (method , structural, js_name = fetch)]
    pub fn fetch_with_request(this: &globalThis, input: &web_sys::Request) -> ::js_sys::Promise;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RedeemerResult {
    pub result: Option<EvaluationResult>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluationResult {
    pub EvaluationResult: Option<HashMap<String, ExUnitResult>>,
    pub EvaluationFailure: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ExUnitResult {
    pub memory: u64,
    pub steps: u64,
}

#[wasm_bindgen]
#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub struct Blockfrost {
    url: String,
    project_id: String,
}

#[wasm_bindgen]
impl Blockfrost {
    pub fn new(url: String, project_id: String) -> Self {
        Self {
            url: url.clone(),
            project_id: project_id.clone(),
        }
    }
    pub fn url(&self) -> String {
        self.url.clone()
    }
    pub fn project_id(&self) -> String {
        self.project_id.clone()
    }
}

#[wasm_bindgen]
pub fn apply_params_to_plutus_script(
    params: &PlutusList,
    plutus_script: PlutusScript,
) -> Result<PlutusScript, JsError> {
    match uplc::tx::apply_params_to_script(&params.to_bytes(), &plutus_script.bytes()) {
        Ok(res) => Ok(PlutusScript::new(res)),
        Err(err) => Err(JsError::from_str(&err.to_string())),
    }
}

pub fn get_ex_units(
    tx: &Transaction,
    utxos: &TransactionUnspentOutputs,
    cost_mdls: &Costmdls,
    max_ex_units: &ExUnits,
    slot_config: (BigNum, BigNum, u32),
) -> Result<Redeemers, JsError> {
    let tx_bytes = tx.to_bytes();

    let utxos_bytes: Vec<(Vec<u8>, Vec<u8>)> = utxos
        .0
        .iter()
        .map(|utxo| (utxo.input.to_bytes(), utxo.output.to_bytes()))
        .collect();

    let cost_mdls_bytes = cost_mdls.to_bytes();

    let initial_budget = (
        from_bignum(&max_ex_units.steps()),
        from_bignum(&max_ex_units.mem()),
    );

    let sc = (
        from_bignum(&slot_config.0),
        from_bignum(&slot_config.1),
        slot_config.2,
    );

    let result = eval_phase_two_raw(
        &tx_bytes,
        &utxos_bytes,
        Some(&cost_mdls_bytes),
        initial_budget,
        sc,
        false,
        |_| (),
    );

    match result {
        Ok(redeemers_bytes) => Ok(Redeemers(
            redeemers_bytes
                .iter()
                .map(|r| Redeemer::from_bytes(r.to_vec()).unwrap())
                .collect(),
        )),
        Err(err) => Err(JsError::from_str(&err.to_string())),
    }
}

#[cfg(not(all(target_arch = "wasm32", not(target_os = "emscripten"))))]
pub async fn get_ex_units_blockfrost(
    tx: Transaction,
    bf: &Blockfrost,
    utxos: Option<TransactionUnspentOutputs>,
) -> Result<Redeemers, JsError> {
    Ok(Redeemers::new())
}

// TxIn struct
#[derive(Debug, Serialize, Deserialize)]
pub struct TxIn {
    pub txId: String, // Transaction hash for the input
    pub index: u32,   // Index of the output within the transaction
}

// Value struct for TxOut
#[derive(Debug, Serialize, Deserialize)]
pub struct BlockfrostValue {
    pub coins: u64,                           // Lovelace amount
    pub assets: Option<HashMap<String, u64>>, // Optional assets amounts
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockfrostScript {
    pub script_hash: String, // Script in hex
    #[serde(rename = "type")]
    pub type_: String, // Script type
    pub serialised_size: u64, // Script size in bytes
}

// TxOut struct
#[derive(Debug, Serialize, Deserialize)]
pub struct TxOut {
    pub address: String,                  // Output address
    pub value: BlockfrostValue,           // The value (coins and optional assets)
    pub datum_hash: Option<String>,       // Optional datum hash
    pub datum: Option<String>,            // Optional datum (string or null)
    pub script: Option<BlockfrostScript>, // Optional script (string or null)
}

// Main struct for the endpoint request
#[derive(Debug, Serialize, Deserialize)]
pub struct EvaluateRequestBody {
    pub cbor: String, // Transaction CBOR (base64 or base16)
    #[serde(rename = "additionalUtxoSet")]
    pub additional_utxo_set: Vec<(TxIn, TxOut)>, // Array of tuples [TxIn, TxOut]
}

fn to_blockfrost_utxo(u: TransactionUnspentOutput) -> Vec<(TxIn, TxOut)> {
    let tx_in = TxIn {
        txId: u.input().transaction_id().to_hex(),
        index: u.input().index().to_str().parse().unwrap(),
    };
    let multiasset = u.output().amount().multiasset();
    let assets: Option<HashMap<String, u64>> = match multiasset {
        Some(ma) => {
            let mut assets: HashMap<String, u64> = HashMap::new();
            let multi_assets = ma.keys();
            for i in 0..multi_assets.len() - 1 {
                let policy = multi_assets.get(i);
                let policy_assets = ma.get(&policy).unwrap();
                let asset_names = policy_assets.keys();
                for j in 0..asset_names.len() - 1 {
                    let policy_asset = asset_names.get(j);
                    let quantity = policy_assets.get(&policy_asset).unwrap();
                    let unit = policy.to_hex() + &hex::encode(&policy_asset.name());
                    assets.insert(unit, quantity.to_str().parse().unwrap());
                }
            }
            Some(assets)
        }
        _ => None,
    };
    let tx_out = TxOut {
        address: hex::encode(&u.output().address().to_bytes()),
        value: BlockfrostValue {
            coins: u.output().amount().coin().to_str().parse().unwrap(),
            assets,
        },
        datum_hash: u
            .output()
            .datum()
            .and_then(|datum| datum.as_data_hash().and_then(|dh| Some(dh.to_hex()))),
        datum: u
            .output()
            .datum()
            .and_then(|datum| datum.as_data().and_then(|d| Some(d.get().to_bytes())))
            .and_then(|bytes| Some(hex::encode(bytes))),
        script: u
            .output()
            .script_ref()
            .and_then(|script| match script.get().kind() {
                ScriptKind::PlutusScriptV1 => Some(BlockfrostScript {
                    script_hash: script
                        .get()
                        .as_plutus_v1()
                        .unwrap()
                        .hash(ScriptHashNamespace::PlutusV1)
                        .to_hex(),
                    type_: std::string::String::from_str("plutusV1").unwrap(),
                    serialised_size: script.to_bytes().len() as u64,
                }),
                ScriptKind::PlutusScriptV2 => Some(BlockfrostScript {
                    script_hash: script
                        .get()
                        .as_plutus_v2()
                        .unwrap()
                        .hash(ScriptHashNamespace::PlutusV2)
                        .to_hex(),
                    type_: std::string::String::from_str("plutusV2").unwrap(),
                    serialised_size: script.to_bytes().len() as u64,
                }),
                ScriptKind::PlutusScriptV3 => todo!("PlutusV3 not yet implemented."),
                ScriptKind::NativeScript => Some(BlockfrostScript {
                    script_hash: script
                        .get()
                        .as_native()
                        .unwrap()
                        .hash(ScriptHashNamespace::NativeScript)
                        .to_hex(),
                    type_: std::string::String::from_str("timelock").unwrap(),
                    serialised_size: script.to_bytes().len() as u64,
                }),
            }),
    };
    vec![(tx_in, tx_out)]
}


#[cfg(all(target_arch = "wasm32", not(target_os = "emscripten")))]
pub async fn get_ex_units_blockfrost(
    tx: Transaction,
    bf: &Blockfrost,
    utxos: Option<TransactionUnspentOutputs>,
) -> Result<Redeemers, JsError> {
    if bf.url.is_empty() || bf.project_id.is_empty() {
        return Err(JsError::from_str(
            "Blockfrost not set. Can't calculate ex units",
        ));
    }

    let mut opts = RequestInit::new();
    opts.method("POST");
    let tx_hex = hex::encode(tx.to_bytes());
    let (body, bodystr): (Option<JsValue>, String) = match utxos {
        Some(ref utxosSet) => {
            let bodyUtxos = utxosSet.0
                .iter()
                .map(|u| to_blockfrost_utxo(u.clone())).flatten().collect::<Vec<(TxIn, TxOut)>>();
            let body = serde_json::json!({
                "cbor": tx_hex,
                "additional_utxo_set": bodyUtxos
            })
            .to_string();
            (Some(JsValue::from_str(&body)), body)
        }
        None => (Some(JsValue::from(tx_hex)), "".to_string()),
    };
    opts.body(Some(&body.unwrap()));

    let url = match utxos {
        Some(_) => &format!("{}/utxos", bf.url),
        None => &bf.url,
    };
//    Err(JsError::from_str(&format!("{}/{}", bodystr, url)))

    let request = Request::new_with_str_and_init(&url, &opts)?;
    request.headers().set("Content-Type", "application/json")?;
    request.headers().set("project_id", &bf.project_id)?;

    let window = js_sys::global().unchecked_into::<globalThis>();
    let resp_value = JsFuture::from(window.fetch_with_request(&request)).await?;

    // `resp_value` is a `Response` object.
    assert!(resp_value.is_instance_of::<Response>());
    let resp: Response = resp_value.dyn_into().unwrap();

    // Convert this other `Promise` into a rust `Future`.
    let json = JsFuture::from(resp.json()?).await?;
    //Err(JsError::from_str(&format!("{:?}", json)))

    // Use serde to parse the JSON into a struct.
    let redeemer_result: RedeemerResult = json.into_serde().unwrap();

    match redeemer_result.result {
        Some(res) => {
            if let Some(e) = &res.EvaluationFailure {
                return Err(JsError::from_str(
                    &serde_json::to_string_pretty(&e).unwrap(),
                ));
            }
            let mut redeemers: BTreeMap<RedeemerWitnessKey, Redeemer> = BTreeMap::new();
            for (pointer, eu) in &res.EvaluationResult.unwrap() {
                let r: Vec<&str> = pointer.split(":").collect();
                let tag = match r[0] {
                    "spend" => RedeemerTag::new_spend(),
                    "mint" => RedeemerTag::new_mint(),
                    "certificate" => RedeemerTag::new_cert(),
                    "withdrawal" => RedeemerTag::new_reward(),
                    _ => return Err(JsValue::NULL),
                };
                let index = &to_bignum(r[1].parse::<u64>().unwrap());
                let ex_units = ExUnits::new(&to_bignum(eu.memory), &to_bignum(eu.steps));

                for tx_redeemer in &tx.witness_set.redeemers.clone().unwrap().0 {
                    if tx_redeemer.tag() == tag && tx_redeemer.index() == *index {
                        let updated_redeemer = Redeemer::new(
                            &tx_redeemer.tag(),
                            &tx_redeemer.index(),
                            &tx_redeemer.data(),
                            &ex_units,
                        );
                        redeemers.insert(
                            RedeemerWitnessKey::new(
                                &updated_redeemer.tag(),
                                &updated_redeemer.index(),
                            ),
                            updated_redeemer.clone(),
                        );
                    }
                }
            }

            Ok(Redeemers(redeemers.values().cloned().collect()))
        }

        None => Err(JsValue::NULL),
    }
}

#[wasm_bindgen]
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ScriptWitnessKind {
    NativeWitness,
    PlutusWitness,
}

#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub enum ScriptWitnessEnum {
    NativeWitness(NativeScript),
    PlutusWitness(PlutusWitness),
}

#[wasm_bindgen]
#[derive(
    Clone, Debug, Eq, PartialEq, Ord, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub struct PlutusWitness {
    redeemer: PlutusData,
    plutus_data: Option<PlutusData>,
    script: Option<PlutusScript>,
    version: LanguageKind,
}

#[wasm_bindgen]
impl PlutusWitness {
    /// Plutus V1 witness or witness where no script is attached and so version doesn't matter
    pub fn new(
        redeemer: &PlutusData,
        plutus_data: Option<PlutusData>,
        script: Option<PlutusScript>,
    ) -> Self {
        Self {
            redeemer: redeemer.clone(),
            plutus_data: plutus_data.clone(),
            script: script.clone(),
            version: LanguageKind::PlutusV1,
        }
    }

    pub fn new_plutus_v2(
        redeemer: &PlutusData,
        plutus_data: Option<PlutusData>,
        script: Option<PlutusScript>,
    ) -> Self {
        Self {
            redeemer: redeemer.clone(),
            plutus_data: plutus_data.clone(),
            script: script.clone(),
            version: LanguageKind::PlutusV2,
        }
    }

    pub fn plutus_data(&self) -> Option<PlutusData> {
        self.plutus_data.clone()
    }
    pub fn redeemer(&self) -> PlutusData {
        self.redeemer.clone()
    }
    pub fn script(&self) -> Option<PlutusScript> {
        self.script.clone()
    }
    pub fn version(&self) -> LanguageKind {
        self.version.clone()
    }
}

#[wasm_bindgen]
#[derive(
    Clone, Debug, Eq, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize, JsonSchema,
)]
pub struct ScriptWitness(ScriptWitnessEnum);

to_from_json!(ScriptWitness);

#[wasm_bindgen]
impl ScriptWitness {
    pub fn new_native_witness(native_script: &NativeScript) -> Self {
        Self(ScriptWitnessEnum::NativeWitness(native_script.clone()))
    }
    pub fn new_plutus_witness(plutus_witness: &PlutusWitness) -> Self {
        Self(ScriptWitnessEnum::PlutusWitness(plutus_witness.clone()))
    }

    pub fn kind(&self) -> ScriptWitnessKind {
        match &self.0 {
            ScriptWitnessEnum::NativeWitness(_) => ScriptWitnessKind::NativeWitness,
            ScriptWitnessEnum::PlutusWitness(_) => ScriptWitnessKind::PlutusWitness,
        }
    }

    pub fn as_native_witness(&self) -> Option<NativeScript> {
        match &self.0 {
            ScriptWitnessEnum::NativeWitness(native_script) => Some(native_script.clone()),
            _ => None,
        }
    }

    pub fn as_plutus_witness(&self) -> Option<PlutusWitness> {
        match &self.0 {
            ScriptWitnessEnum::PlutusWitness(plutus_witness) => Some(plutus_witness.clone()),
            _ => None,
        }
    }
}
