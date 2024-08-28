import { C } from "../core/mod.ts";
import { Data } from "../mod.ts";
import {
  Address,
  Assets,
  CertificateValidator,
  Datum,
  Json,
  Label,
  Lovelace,
  MintingPolicy,
  OutputData,
  OutRef,
  PaymentKeyHash,
  PoolId,
  PoolParams,
  Redeemer,
  RewardAddress,
  SpendingValidator,
  StakeKeyHash,
  UnixTime,
  UTxO,
  WithdrawalValidator,
} from "../types/mod.ts";
import {
  assetsToValue,
  fromHex,
  networkToId,
  toHex,
  toScriptRef,
  utxoToCore,
} from "../utils/mod.ts";
import { applyDoubleCborEncoding, valueToAssets } from "../utils/utils.ts";
import { Lucid } from "./lucid.ts";
import { TxComplete } from "./tx_complete.ts";

export class Tx {
  txBuilder: C.TransactionBuilder;
  /** Stores the tx instructions, which get executed after calling .complete() */
  private tasks: ((that: Tx) => unknown)[];
  private lucid: Lucid;

  constructor(lucid: Lucid, tx?: C.Transaction) {
    this.lucid = lucid;
    this.txBuilder = C.TransactionBuilder.new(this.lucid.txBuilderConfig);
    this.tasks = [];
    if (tx) {
      this.addPlutusData(tx);
      this.setValidityRange(tx);
      this.addSigners(tx);
      this.addOutputs(tx);
      this.addMetadata(tx);
      this.addMint(tx);
      this.addScripts(tx);
      this.addInputs(tx);
      this.addReferenceInputs(tx);
      this.addCollateral(tx);
    }
  }

  private setValidityRange(tx: C.Transaction) {
    const txBody = tx.body();
    const slotFrom = txBody.validity_start_interval();
    const slotUntil = txBody.ttl();

    if (slotFrom) {
      const from: number = this.lucid.utils.slotToUnixTime(
        Number(slotFrom!.to_str())
      );
      this.validFrom(from);
    }

    if (slotUntil) {
      const until: number = this.lucid.utils.slotToUnixTime(
        Number(slotUntil!.to_str())
      );
      this.validTo(until);
    }

    return this;
  }

  private addSigners(tx: C.Transaction) {
    const txBody = tx.body();
    const requiredSigners = txBody.required_signers();

    if (requiredSigners) {
      for (let i = 0; i < requiredSigners?.len(); i++) {
        const reqSigner = requiredSigners?.get(i);
        const key = reqSigner.to_hex();
        this.addSignerKey(key);
      }
    }
    return this;
  }

  private getOutputData(
    tx: C.Transaction,
    output: C.TransactionOutput
  ): OutputData | undefined {
    const datumHash = output.datum()?.as_data_hash()?.to_hex();
    const inlineDatum = output.datum()?.as_data()?.to_js_value().original_bytes;
    const scriptRef = output.script_ref()?.to_js_value();
    let outputData = {};
    if (scriptRef) {
      if (scriptRef.PlutusScriptV2) {
        outputData = {
          scriptRef: {
            type: "PlutusV2",
            script: scriptRef.PlutusScriptV2,
          },
        };
      }
      if (scriptRef.PlutusScriptV1) {
        outputData = {
          scriptRef: {
            type: "PlutusV1",
            script: scriptRef.PlutusScriptV1,
          },
        };
      }
    }
    if (datumHash) {
      const datum = findDatumFromHash(datumHash, tx);
      if (datum) {
        const datumCBOR = toHex(datum.to_bytes());
        return { ...outputData, asHash: datumCBOR };
      }
      return { ...outputData, hash: datumHash }; //o datumCBOR?
    }

    if (inlineDatum) {
      return { ...outputData, inline: toHex(inlineDatum) };
    }
  }

  private addOutputs(tx: C.Transaction) {
    const outputs = tx.body().outputs();
    if (outputs) {
      for (let i = 0; i < outputs.len(); i++) {
        const output = outputs.get(i);
        this.tasks.push((that) => {
          that.txBuilder.add_output(output);
        });
      }
    }
    return this;
  }

  private addMetadata(tx: C.Transaction): Tx {
    const metadata = tx.auxiliary_data()?.metadata();

    if (metadata) {
      for (let i = 0; i < metadata.keys().len()!; i++) {
        const key = metadata.keys().get(i);
        if (key) {
          this.tasks.push((that) => {
            that.txBuilder.add_metadatum(key, metadata.get(key)!);
          });
        }
      }
    }
    return this;
  }

  private addMint(tx: C.Transaction): Tx {
    const redeemers = tx.witness_set().redeemers();
    const mintField = tx.body().mint();
    if (redeemers && mintField) {
      for (let i = 0; i < redeemers?.len()!; i++) {
        const redeemer = redeemers?.get(i);
        if (redeemer.tag().kind() == 1) {
          const index = Number(redeemer.index().to_str());
          const policy = mintField.keys().get(index);
          const assets = mintField.get(policy);
          if (assets) {
            this.tasks.push((that) => {
              that.txBuilder.add_mint(
                policy,
                assets,
                C.ScriptWitness.new_plutus_witness(
                  C.PlutusWitness.new(redeemer.data(), undefined, undefined)
                )
              );
            });
          }
        }
      }
    }
    return this;
  }

  private addScripts(tx: C.Transaction): Tx {
    const witness = tx.witness_set();
    const native_scripts = witness.native_scripts();
    const plutus_scripts = witness.plutus_scripts();
    const plutus_v2_scripts = witness.plutus_v2_scripts();
    if (native_scripts) {
      for (let i = 0; i < native_scripts.len(); i++) {
        this.tasks.push((that) => {
          that.txBuilder.add_native_script(native_scripts.get(i));
        });
      }
    }
    if (plutus_scripts) {
      for (let i = 0; i < plutus_scripts.len(); i++) {
        this.tasks.push((that) => {
          that.txBuilder.add_plutus_script(plutus_scripts.get(i));
        });
      }
    }
    if (plutus_v2_scripts) {
      for (let i = 0; i < plutus_v2_scripts.len(); i++) {
        this.tasks.push((that) => {
          that.txBuilder.add_plutus_v2_script(plutus_v2_scripts.get(i));
        });
      }
    }
    return this;
  }

  private addInputs(tx: C.Transaction): Tx {
    this.tasks.push(async (that) => {
      const inputs: OutRef[] = tx
        .body()
        .inputs()
        .to_js_value()
        .map(inputOutRef);
      const utxos = (await this.lucid.utxosByOutRef(inputs)).sort(outRefCmp);
      const redeemers = tx.witness_set().redeemers();
      const redeemersData : {[id: number]: C.PlutusData} = {};
      if (redeemers) {
        for (let j = 0; j < redeemers.len(); j++) {
          const redeemer = redeemers.get(j);
          if (redeemer.tag().kind() == 0) {
            const index = Number(redeemer.index().to_str());
            redeemersData[index] = redeemer.data();
          }
        }
      }
      utxos.forEach((utxo, index) => {
        const redeemerData: undefined | C.PlutusData = redeemersData[index];
        that.txBuilder.add_input(
          utxoToCore(utxo),
          redeemerData
            ? C.ScriptWitness.new_plutus_witness(
                C.PlutusWitness.new(redeemerData, undefined, undefined)
              )
            : undefined
        );
      });
    });
    return this;
  }

  private addReferenceInputs(tx: C.Transaction): Tx {
    this.tasks.push(async (that) => {
      const reference_inputs = tx
        .body()
        .reference_inputs()
        ?.to_js_value()
        ?.map(inputOutRef);
      const utxos = reference_inputs
        ? await this.lucid.utxosByOutRef(reference_inputs)
        : undefined;
      if (utxos) {
        for (let i = 0; i < utxos.length; i++) {
          that.txBuilder.add_reference_input(utxoToCore(utxos[i]));
        }
      }
    });
    return this;
  }

  private addPlutusData(tx: C.Transaction): Tx {
    const plutus_data = tx.witness_set().plutus_data();
    if (plutus_data) {
      for (let i = 0; i < plutus_data.len(); i++) {
        const data = plutus_data.get(i);
        this.tasks.push((that) => {
          that.txBuilder.add_plutus_data(data);
        });
      }
    }
    return this;
  }

  private addCollateral(tx: C.Transaction): Tx {
    const collaterals = tx.body().collateral()
      ?.to_js_value()
      ?.map(inputOutRef);
    this.tasks.push(async (that) => {
      const utxos = collaterals
      ? await this.lucid.utxosByOutRef(collaterals)
      : undefined;
      if (utxos) {
        utxos.forEach((outref) => {
          that.txBuilder.add_collateral(utxoToCore(outref));
        })
      }
    });
    return this;
  }

  /** Read data from utxos. These utxos are only referenced and not spent. */
  readFrom(utxos: UTxO[]): Tx {
    this.tasks.push(async (that) => {
      for (const utxo of utxos) {
        if (utxo.datumHash) {
          utxo.datum = Data.to(await that.lucid.datumOf(utxo));
          // Add datum to witness set, so it can be read from validators
          const plutusData = C.PlutusData.from_bytes(fromHex(utxo.datum!));
          that.txBuilder.add_plutus_data(plutusData);
        }
        const coreUtxo = utxoToCore(utxo);
        that.txBuilder.add_reference_input(coreUtxo);
      }
    });
    return this;
  }

  /**
   * A public key or native script input.
   * With redeemer it's a plutus script input.
   */
  collectFrom(utxos: UTxO[], redeemer?: Redeemer): Tx {
    this.tasks.push(async (that) => {
      for (const utxo of utxos) {
        if (utxo.datumHash && !utxo.datum) {
          utxo.datum = Data.to(await that.lucid.datumOf(utxo));
        }
        const coreUtxo = utxoToCore(utxo);
        that.txBuilder.add_input(
          coreUtxo,
          (redeemer as undefined) &&
            C.ScriptWitness.new_plutus_witness(
              C.PlutusWitness.new(
                C.PlutusData.from_bytes(fromHex(redeemer!)),
                utxo.datumHash && utxo.datum
                  ? C.PlutusData.from_bytes(fromHex(utxo.datum!))
                  : undefined,
                undefined
              )
            )
        );
      }
    });
    return this;
  }

  /**
   * All assets should be of the same policy id.
   * You can chain mintAssets functions together if you need to mint assets with different policy ids.
   * If the plutus script doesn't need a redeemer, you still need to specifiy the void redeemer.
   */
  mintAssets(assets: Assets, redeemer?: Redeemer): Tx {
    this.tasks.push((that) => {
      const units = Object.keys(assets);
      const policyId = units[0].slice(0, 56);
      const mintAssets = C.MintAssets.new();
      units.forEach((unit) => {
        if (unit.slice(0, 56) !== policyId) {
          throw new Error(
            "Only one policy id allowed. You can chain multiple mintAssets functions together if you need to mint assets with different policy ids."
          );
        }
        mintAssets.insert(
          C.AssetName.new(fromHex(unit.slice(56))),
          C.Int.from_str(assets[unit].toString())
        );
      });
      const scriptHash = C.ScriptHash.from_bytes(fromHex(policyId));
      that.txBuilder.add_mint(
        scriptHash,
        mintAssets,
        redeemer
          ? C.ScriptWitness.new_plutus_witness(
              C.PlutusWitness.new(
                C.PlutusData.from_bytes(fromHex(redeemer!)),
                undefined,
                undefined
              )
            )
          : undefined
      );
    });
    return this;
  }

  /** Pay to a public key or native script address. */
  payToAddress(address: Address, assets: Assets): Tx {
    this.tasks.push((that) => {
      const output = C.TransactionOutput.new(
        addressFromWithNetworkCheck(address, that.lucid),
        assetsToValue(assets)
      );
      that.txBuilder.add_output(output);
    });
    return this;
  }

  /** Pay to a public key or native script address with datum or scriptRef. */
  payToAddressWithData(
    address: Address,
    outputData: Datum | OutputData,
    assets: Assets
  ): Tx {
    this.tasks.push((that) => {
      if (typeof outputData === "string") {
        outputData = { asHash: outputData };
      }

      if (
        [outputData.hash, outputData.asHash, outputData.inline].filter((b) => b)
          .length > 1
      ) {
        throw new Error(
          "Not allowed to set hash, asHash and inline at the same time."
        );
      }

      const output = C.TransactionOutput.new(
        addressFromWithNetworkCheck(address, that.lucid),
        assetsToValue(assets)
      );

      if (outputData.hash) {
        output.set_datum(
          C.Datum.new_data_hash(C.DataHash.from_hex(outputData.hash))
        );
      } else if (outputData.asHash) {
        const plutusData = C.PlutusData.from_bytes(fromHex(outputData.asHash));
        output.set_datum(C.Datum.new_data_hash(C.hash_plutus_data(plutusData)));
        that.txBuilder.add_plutus_data(plutusData);
      } else if (outputData.inline) {
        const plutusData = C.PlutusData.from_bytes(fromHex(outputData.inline));
        output.set_datum(C.Datum.new_data(C.Data.new(plutusData)));
      }

      const script = outputData.scriptRef;
      if (script) {
        output.set_script_ref(toScriptRef(script));
      }
      that.txBuilder.add_output(output);
    });
    return this;
  }

  /** Pay to a plutus script address with datum or scriptRef. */
  payToContract(
    address: Address,
    outputData: Datum | OutputData,
    assets: Assets
  ): Tx {
    if (typeof outputData === "string") {
      outputData = { asHash: outputData };
    }

    if (!(outputData.hash || outputData.asHash || outputData.inline)) {
      throw new Error(
        "No datum set. Script output becomes unspendable without datum."
      );
    }
    return this.payToAddressWithData(address, outputData, assets);
  }

  /** Delegate to a stake pool. */
  delegateTo(
    rewardAddress: RewardAddress,
    poolId: PoolId,
    redeemer?: Redeemer
  ): Tx {
    this.tasks.push((that) => {
      const addressDetails = that.lucid.utils.getAddressDetails(rewardAddress);

      if (addressDetails.type !== "Reward" || !addressDetails.stakeCredential) {
        throw new Error("Not a reward address provided.");
      }
      const credential =
        addressDetails.stakeCredential.type === "Key"
          ? C.StakeCredential.from_keyhash(
              C.Ed25519KeyHash.from_bytes(
                fromHex(addressDetails.stakeCredential.hash)
              )
            )
          : C.StakeCredential.from_scripthash(
              C.ScriptHash.from_bytes(
                fromHex(addressDetails.stakeCredential.hash)
              )
            );

      that.txBuilder.add_certificate(
        C.Certificate.new_stake_delegation(
          C.StakeDelegation.new(
            credential,
            C.Ed25519KeyHash.from_bech32(poolId)
          )
        ),
        redeemer
          ? C.ScriptWitness.new_plutus_witness(
              C.PlutusWitness.new(
                C.PlutusData.from_bytes(fromHex(redeemer!)),
                undefined,
                undefined
              )
            )
          : undefined
      );
    });
    return this;
  }

  /** Register a reward address in order to delegate to a pool and receive rewards. */
  registerStake(rewardAddress: RewardAddress): Tx {
    this.tasks.push((that) => {
      const addressDetails = that.lucid.utils.getAddressDetails(rewardAddress);

      if (addressDetails.type !== "Reward" || !addressDetails.stakeCredential) {
        throw new Error("Not a reward address provided.");
      }
      const credential =
        addressDetails.stakeCredential.type === "Key"
          ? C.StakeCredential.from_keyhash(
              C.Ed25519KeyHash.from_bytes(
                fromHex(addressDetails.stakeCredential.hash)
              )
            )
          : C.StakeCredential.from_scripthash(
              C.ScriptHash.from_bytes(
                fromHex(addressDetails.stakeCredential.hash)
              )
            );

      that.txBuilder.add_certificate(
        C.Certificate.new_stake_registration(
          C.StakeRegistration.new(credential)
        ),
        undefined
      );
    });
    return this;
  }

  /** Deregister a reward address. */
  deregisterStake(rewardAddress: RewardAddress, redeemer?: Redeemer): Tx {
    this.tasks.push((that) => {
      const addressDetails = that.lucid.utils.getAddressDetails(rewardAddress);

      if (addressDetails.type !== "Reward" || !addressDetails.stakeCredential) {
        throw new Error("Not a reward address provided.");
      }
      const credential =
        addressDetails.stakeCredential.type === "Key"
          ? C.StakeCredential.from_keyhash(
              C.Ed25519KeyHash.from_bytes(
                fromHex(addressDetails.stakeCredential.hash)
              )
            )
          : C.StakeCredential.from_scripthash(
              C.ScriptHash.from_bytes(
                fromHex(addressDetails.stakeCredential.hash)
              )
            );

      that.txBuilder.add_certificate(
        C.Certificate.new_stake_deregistration(
          C.StakeDeregistration.new(credential)
        ),
        redeemer
          ? C.ScriptWitness.new_plutus_witness(
              C.PlutusWitness.new(
                C.PlutusData.from_bytes(fromHex(redeemer!)),
                undefined,
                undefined
              )
            )
          : undefined
      );
    });
    return this;
  }

  /** Register a stake pool. A pool deposit is required. The metadataUrl needs to be hosted already before making the registration. */
  registerPool(poolParams: PoolParams): Tx {
    this.tasks.push(async (that) => {
      const poolRegistration = await createPoolRegistration(
        poolParams,
        that.lucid
      );

      const certificate = C.Certificate.new_pool_registration(poolRegistration);

      that.txBuilder.add_certificate(certificate, undefined);
    });
    return this;
  }

  /** Update a stake pool. No pool deposit is required. The metadataUrl needs to be hosted already before making the update. */
  updatePool(poolParams: PoolParams): Tx {
    this.tasks.push(async (that) => {
      const poolRegistration = await createPoolRegistration(
        poolParams,
        that.lucid
      );

      // This flag makes sure a pool deposit is not required
      poolRegistration.set_is_update(true);

      const certificate = C.Certificate.new_pool_registration(poolRegistration);

      that.txBuilder.add_certificate(certificate, undefined);
    });
    return this;
  }
  /**
   * Retire a stake pool. The epoch needs to be the greater than the current epoch + 1 and less than current epoch + eMax.
   * The pool deposit will be sent to reward address as reward after full retirement of the pool.
   */
  retirePool(poolId: PoolId, epoch: number): Tx {
    this.tasks.push((that) => {
      const certificate = C.Certificate.new_pool_retirement(
        C.PoolRetirement.new(C.Ed25519KeyHash.from_bech32(poolId), epoch)
      );
      that.txBuilder.add_certificate(certificate, undefined);
    });
    return this;
  }

  withdraw(
    rewardAddress: RewardAddress,
    amount: Lovelace,
    redeemer?: Redeemer
  ): Tx {
    this.tasks.push((that) => {
      that.txBuilder.add_withdrawal(
        C.RewardAddress.from_address(
          addressFromWithNetworkCheck(rewardAddress, that.lucid)
        )!,
        C.BigNum.from_str(amount.toString()),
        redeemer
          ? C.ScriptWitness.new_plutus_witness(
              C.PlutusWitness.new(
                C.PlutusData.from_bytes(fromHex(redeemer!)),
                undefined,
                undefined
              )
            )
          : undefined
      );
    });
    return this;
  }

  /**
   * Needs to be a public key address.
   * The PaymentKeyHash is taken when providing a Base, Enterprise or Pointer address.
   * The StakeKeyHash is taken when providing a Reward address.
   */
  addSigner(address: Address | RewardAddress): Tx {
    const addressDetails = this.lucid.utils.getAddressDetails(address);

    if (!addressDetails.paymentCredential && !addressDetails.stakeCredential) {
      throw new Error("Not a valid address.");
    }

    const credential =
      addressDetails.type === "Reward"
        ? addressDetails.stakeCredential!
        : addressDetails.paymentCredential!;

    if (credential.type === "Script") {
      throw new Error("Only key hashes are allowed as signers.");
    }
    return this.addSignerKey(credential.hash);
  }

  /** Add a payment or stake key hash as a required signer of the transaction. */
  addSignerKey(keyHash: PaymentKeyHash | StakeKeyHash): Tx {
    this.tasks.push((that) => {
      that.txBuilder.add_required_signer(
        C.Ed25519KeyHash.from_bytes(fromHex(keyHash))
      );
    });
    return this;
  }

  validFrom(unixTime: UnixTime): Tx {
    this.tasks.push((that) => {
      const slot = that.lucid.utils.unixTimeToSlot(unixTime);
      that.txBuilder.set_validity_start_interval(
        C.BigNum.from_str(slot.toString())
      );
    });
    return this;
  }

  validTo(unixTime: UnixTime): Tx {
    this.tasks.push((that) => {
      const slot = that.lucid.utils.unixTimeToSlot(unixTime);
      that.txBuilder.set_ttl(C.BigNum.from_str(slot.toString()));
    });
    return this;
  }

  attachMetadata(label: Label, metadata: Json): Tx {
    this.tasks.push((that) => {
      that.txBuilder.add_json_metadatum(
        C.BigNum.from_str(label.toString()),
        JSON.stringify(metadata)
      );
    });
    return this;
  }

  /** Converts strings to bytes if prefixed with **'0x'**. */
  attachMetadataWithConversion(label: Label, metadata: Json): Tx {
    this.tasks.push((that) => {
      that.txBuilder.add_json_metadatum_with_schema(
        C.BigNum.from_str(label.toString()),
        JSON.stringify(metadata),
        C.MetadataJsonSchema.BasicConversions
      );
    });
    return this;
  }

  /** Explicitely set the network id in the transaction body. */
  addNetworkId(id: number): Tx {
    this.tasks.push((that) => {
      that.txBuilder.set_network_id(
        C.NetworkId.from_bytes(fromHex(id.toString(16).padStart(2, "0")))
      );
    });
    return this;
  }

  attachSpendingValidator(spendingValidator: SpendingValidator): Tx {
    this.tasks.push((that) => {
      attachScript(that, spendingValidator);
    });
    return this;
  }

  attachMintingPolicy(mintingPolicy: MintingPolicy): Tx {
    this.tasks.push((that) => {
      attachScript(that, mintingPolicy);
    });
    return this;
  }

  attachCertificateValidator(certValidator: CertificateValidator): Tx {
    this.tasks.push((that) => {
      attachScript(that, certValidator);
    });
    return this;
  }

  attachWithdrawalValidator(withdrawalValidator: WithdrawalValidator): Tx {
    this.tasks.push((that) => {
      attachScript(that, withdrawalValidator);
    });
    return this;
  }

  /** Compose transactions. */
  compose(tx: Tx | null): Tx {
    if (tx) this.tasks = this.tasks.concat(tx.tasks);
    return this;
  }

  async complete(options?: {
    change?: { address?: Address; outputData?: OutputData };
    coinSelection?: boolean;
    nativeUplc?: boolean;
  }): Promise<TxComplete> {
    if (
      [
        options?.change?.outputData?.hash,
        options?.change?.outputData?.asHash,
        options?.change?.outputData?.inline,
      ].filter((b) => b).length > 1
    ) {
      throw new Error(
        "Not allowed to set hash, asHash and inline at the same time."
      );
    }

    let task = this.tasks.shift();
    while (task) {
      await task(this);
      task = this.tasks.shift();
    }

    const utxos = await this.lucid.wallet.getUtxosCore();

    const changeAddress: C.Address = addressFromWithNetworkCheck(
      options?.change?.address || (await this.lucid.wallet.address()),
      this.lucid
    );

    if (options?.coinSelection || options?.coinSelection === undefined) {
      this.txBuilder.add_inputs_from(
        utxos,
        changeAddress,
        Uint32Array.from([
          200, // weight ideal > 100 inputs
          1000, // weight ideal < 100 inputs
          1500, // weight assets if plutus
          800, // weight assets if not plutus
          800, // weight distance if not plutus
          5000, // weight utxos
        ])
      );
    }

    this.txBuilder.balance(
      changeAddress,
      (() => {
        if (options?.change?.outputData?.hash) {
          return C.Datum.new_data_hash(
            C.DataHash.from_hex(options.change.outputData.hash)
          );
        } else if (options?.change?.outputData?.asHash) {
          this.txBuilder.add_plutus_data(
            C.PlutusData.from_bytes(fromHex(options.change.outputData.asHash))
          );
          return C.Datum.new_data_hash(
            C.hash_plutus_data(
              C.PlutusData.from_bytes(fromHex(options.change.outputData.asHash))
            )
          );
        } else if (options?.change?.outputData?.inline) {
          return C.Datum.new_data(
            C.Data.new(
              C.PlutusData.from_bytes(fromHex(options.change.outputData.inline))
            )
          );
        } else {
          return undefined;
        }
      })()
    );

    return new TxComplete(
      this.lucid,
      await this.txBuilder.construct(
        utxos,
        changeAddress,
        options?.nativeUplc === undefined ? true : options?.nativeUplc
      )
    );
  }

  /** Return the current transaction body in Hex encoded Cbor. */
  async toString(): Promise<string> {
    let task = this.tasks.shift();
    while (task) {
      await task(this);
      task = this.tasks.shift();
    }

    return toHex(this.txBuilder.to_bytes());
  }
}

function attachScript(
  tx: Tx,
  {
    type,
    script,
  }:
    | SpendingValidator
    | MintingPolicy
    | CertificateValidator
    | WithdrawalValidator
) {
  if (type === "Native") {
    return tx.txBuilder.add_native_script(
      C.NativeScript.from_bytes(fromHex(script))
    );
  } else if (type === "PlutusV1") {
    return tx.txBuilder.add_plutus_script(
      C.PlutusScript.from_bytes(fromHex(applyDoubleCborEncoding(script)))
    );
  } else if (type === "PlutusV2") {
    return tx.txBuilder.add_plutus_v2_script(
      C.PlutusScript.from_bytes(fromHex(applyDoubleCborEncoding(script)))
    );
  }
  throw new Error("No variant matched.");
}

async function createPoolRegistration(
  poolParams: PoolParams,
  lucid: Lucid
): Promise<C.PoolRegistration> {
  const poolOwners = C.Ed25519KeyHashes.new();
  poolParams.owners.forEach((owner) => {
    const { stakeCredential } = lucid.utils.getAddressDetails(owner);
    if (stakeCredential?.type === "Key") {
      poolOwners.add(C.Ed25519KeyHash.from_hex(stakeCredential.hash));
    } else throw new Error("Only key hashes allowed for pool owners.");
  });

  const metadata = poolParams.metadataUrl
    ? await fetch(poolParams.metadataUrl).then((res) => res.arrayBuffer())
    : null;

  const metadataHash = metadata
    ? C.PoolMetadataHash.from_bytes(C.hash_blake2b256(new Uint8Array(metadata)))
    : null;

  const relays = C.Relays.new();
  poolParams.relays.forEach((relay) => {
    switch (relay.type) {
      case "SingleHostIp": {
        const ipV4 = relay.ipV4
          ? C.Ipv4.new(
              new Uint8Array(relay.ipV4.split(".").map((b) => parseInt(b)))
            )
          : undefined;
        const ipV6 = relay.ipV6
          ? C.Ipv6.new(fromHex(relay.ipV6.replaceAll(":", "")))
          : undefined;
        relays.add(
          C.Relay.new_single_host_addr(
            C.SingleHostAddr.new(relay.port, ipV4, ipV6)
          )
        );
        break;
      }
      case "SingleHostDomainName": {
        relays.add(
          C.Relay.new_single_host_name(
            C.SingleHostName.new(
              relay.port,
              C.DNSRecordAorAAAA.new(relay.domainName!)
            )
          )
        );
        break;
      }
      case "MultiHost": {
        relays.add(
          C.Relay.new_multi_host_name(
            C.MultiHostName.new(C.DNSRecordSRV.new(relay.domainName!))
          )
        );
        break;
      }
    }
  });

  return C.PoolRegistration.new(
    C.PoolParams.new(
      C.Ed25519KeyHash.from_bech32(poolParams.poolId),
      C.VRFKeyHash.from_hex(poolParams.vrfKeyHash),
      C.BigNum.from_str(poolParams.pledge.toString()),
      C.BigNum.from_str(poolParams.cost.toString()),
      C.UnitInterval.from_float(poolParams.margin),
      C.RewardAddress.from_address(
        addressFromWithNetworkCheck(poolParams.rewardAddress, lucid)
      )!,
      poolOwners,
      relays,
      metadataHash
        ? C.PoolMetadata.new(C.Url.new(poolParams.metadataUrl!), metadataHash)
        : undefined
    )
  );
}

function addressFromWithNetworkCheck(
  address: Address | RewardAddress,
  lucid: Lucid
): C.Address {
  const { type, networkId } = lucid.utils.getAddressDetails(address);

  const actualNetworkId = networkToId(lucid.network);
  if (networkId !== actualNetworkId) {
    throw new Error(
      `Invalid address: Expected address with network id ${actualNetworkId}, but got ${networkId}`
    );
  }
  return type === "Byron"
    ? C.ByronAddress.from_base58(address).to_address()
    : C.Address.from_bech32(address);
}

function inputOutRef(input: { transaction_id: string; index: string }): OutRef {
  const ref: OutRef = {
    txHash: input.transaction_id,
    outputIndex: Number(input.index),
  };
  return ref;
}

function outRefCmp(a: OutRef, b: OutRef): number {
  const aTxHash = a.txHash;
  const bTxHash = b.txHash;
  const aIndex = a.outputIndex;
  const bIndex = b.outputIndex;
  if (aTxHash < bTxHash) return -1;
  if (aTxHash > bTxHash) return 1;
  if (aIndex < bIndex) return -1;
  if (aIndex > bIndex) return 1;
  return 0;
}

/**
 * Finds a datum inside a transaction that corresponds with the given hash
 * @param hash hash to look for
 * @param transaction transaction where to look for the datum
 * @returns The Datum whose hash is the same as the given hash
 * @throws NoDatumsInTx
 * @throws NoDatumMatchesHash
 */
function findDatumFromHash(
  hash: string,
  transaction: C.Transaction
): C.PlutusData | undefined {
  const allDatums = transaction.witness_set().plutus_data();
  if (allDatums) {
    for (let i = 0; i < allDatums.len(); i++) {
      const datum = allDatums.get(i);
      if (C.hash_plutus_data(datum).to_hex() === hash) {
        return datum;
      }
    }
  }
}
