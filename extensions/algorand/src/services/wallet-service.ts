import { LocalStorage, showToast, Toast } from "@raycast/api";
import algosdk from "algosdk";
import * as crypto from "crypto";
import { PeraSwap } from "@perawallet/swap";

export interface WalletData {
  address: string;
  mnemonic: string;
  createdAt: string;
}

export interface StoredWallet {
  address: string;
  encryptedMnemonic: string;
  iv: string;
  createdAt: string;
}

export class WalletService {
  private static instance: WalletService;
  private cachedWallet: WalletData | null = null;
  private readonly WALLET_KEY = "default_algorand_wallet";
  private readonly DEFAULT_PASSWORD = "raycast_algorand_default_2024";

  static getInstance(): WalletService {
    if (!WalletService.instance) {
      WalletService.instance = new WalletService();
    }
    return WalletService.instance;
  }

  private encryptMnemonic(mnemonic: string, password: string): { encrypted: string; iv: string } {
    const algorithm = "aes-256-cbc";
    const key = crypto.scryptSync(password, "algorand-salt", 32);
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, key, iv);

    let encrypted = cipher.update(mnemonic, "utf8", "hex");
    encrypted += cipher.final("hex");

    return {
      encrypted,
      iv: iv.toString("hex"),
    };
  }

  private decryptMnemonic(encrypted: string, iv: string, password: string): string {
    const algorithm = "aes-256-cbc";
    const key = crypto.scryptSync(password, "algorand-salt", 32);
    const ivBuffer = Buffer.from(iv, "hex");
    const decipher = crypto.createDecipheriv(algorithm, key, ivBuffer);

    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");

    return decrypted;
  }

  async generateWallet(): Promise<WalletData> {
    const account = algosdk.generateAccount();
    const mnemonic = algosdk.secretKeyToMnemonic(account.sk);

    const wallet: WalletData = {
      address: account.addr,
      mnemonic: mnemonic,
      createdAt: new Date().toISOString(),
    };

    return wallet;
  }

  async saveWallet(wallet: WalletData): Promise<void> {
    const { encrypted, iv } = this.encryptMnemonic(wallet.mnemonic, this.DEFAULT_PASSWORD);

    const storedWallet: StoredWallet = {
      address: wallet.address,
      encryptedMnemonic: encrypted,
      iv,
      createdAt: wallet.createdAt,
    };

    await LocalStorage.setItem(this.WALLET_KEY, JSON.stringify(storedWallet));
    this.cachedWallet = wallet;
  }

  async loadWallet(): Promise<WalletData | null> {
    if (this.cachedWallet) {
      return this.cachedWallet;
    }

    try {
      const stored = await LocalStorage.getItem(this.WALLET_KEY);
      if (!stored) {
        return null;
      }

      const storedWallet: StoredWallet = JSON.parse(stored as string);
      const mnemonic = this.decryptMnemonic(storedWallet.encryptedMnemonic, storedWallet.iv, this.DEFAULT_PASSWORD);

      const wallet: WalletData = {
        address: storedWallet.address,
        mnemonic,
        createdAt: storedWallet.createdAt,
      };

      this.cachedWallet = wallet;
      return wallet;
    } catch (error) {
      console.error("Error loading wallet:", error);
      return null;
    }
  }

  async getOrCreateWallet(): Promise<WalletData> {
    let wallet = await this.loadWallet();

    if (!wallet) {
      await showToast({
        style: Toast.Style.Animated,
        title: "Creating Wallet...",
        message: "Generating your Algorand wallet",
      });

      wallet = await this.generateWallet();
      await this.saveWallet(wallet);

      await showToast({
        style: Toast.Style.Success,
        title: "Wallet Created!",
        message: "Your Algorand wallet is ready",
      });
    }

    return wallet;
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getAccountInfo(address: string): Promise<any> {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.algonode.cloud", "");
    try {
      return await algodClient.accountInformation(address).do();
    } catch {
      throw new Error("Account not found on testnet. Try funding it first.");
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getDetailedAccountAssets(address: string): Promise<any[]> {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.algonode.cloud", "");

    try {
      const accountInfo = await algodClient.accountInformation(address).do();

      if (!accountInfo.assets || accountInfo.assets.length === 0) {
        return [];
      }

      // Fetch detailed information for each asset
      const detailedAssets = await Promise.all(
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        accountInfo.assets.map(async (asset: any) => {
          try {
            const assetInfo = await algodClient.getAssetByID(asset["asset-id"]).do();
            return {
              id: asset["asset-id"],
              amount: asset.amount,
              isFrozen: asset["is-frozen"] || false,
              // Asset details from the blockchain
              name: assetInfo.params.name || `Asset ${asset["asset-id"]}`,
              unitName: assetInfo.params["unit-name"] || `ASA${asset["asset-id"]}`,
              decimals: assetInfo.params.decimals || 0,
              total: assetInfo.params.total,
              creator: assetInfo.params.creator,
              manager: assetInfo.params.manager,
              reserve: assetInfo.params.reserve,
              freeze: assetInfo.params.freeze,
              clawback: assetInfo.params.clawback,
              url: assetInfo.params.url,
              metadataHash: assetInfo.params["metadata-hash"],
              defaultFrozen: assetInfo.params["default-frozen"],
              // Formatted amount considering decimals
              formattedAmount: (asset.amount / Math.pow(10, assetInfo.params.decimals || 0)).toFixed(
                assetInfo.params.decimals || 0,
              ),
            };
          } catch (error) {
            console.error(`Error fetching details for asset ${asset["asset-id"]}:`, error);
            return {
              id: asset["asset-id"],
              amount: asset.amount,
              isFrozen: asset["is-frozen"] || false,
              name: `Asset ${asset["asset-id"]}`,
              unitName: `ASA${asset["asset-id"]}`,
              decimals: 0,
              formattedAmount: asset.amount.toString(),
            };
          }
        }),
      );

      return detailedAssets;
    } catch (error) {
      console.error("Error fetching detailed account assets:", error);
      return [];
    }
  }

  async sendPayment(
    fromMnemonic: string,
    toAddress: string,
    amountInAlgo: number,
    note?: string,
  ): Promise<{ txId: string; confirmedRound: number }> {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.algonode.cloud", "");

    // Get account from mnemonic
    const account = algosdk.mnemonicToSecretKey(fromMnemonic);

    // Get suggested parameters
    const suggestedParams = await algodClient.getTransactionParams().do();

    // Convert ALGO to microAlgos
    const amountInMicroAlgos = Math.round(amountInAlgo * 1000000);

    // Create transaction
    const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
      from: account.addr,
      to: toAddress,
      amount: amountInMicroAlgos,
      note: note ? new Uint8Array(Buffer.from(note)) : undefined,
      suggestedParams,
    });

    // Sign transaction
    const signedTxn = txn.signTxn(account.sk);

    // Submit transaction
    const { txId } = await algodClient.sendRawTransaction(signedTxn).do();

    // Wait for confirmation
    const confirmedTxn = await algosdk.waitForConfirmation(algodClient, txId, 4);

    return {
      txId,
      confirmedRound: confirmedTxn["confirmed-round"],
    };
  }

  async createAsset(
    creatorMnemonic: string,
    assetName: string,
    unitName: string,
    totalSupply: number,
    decimals: number = 0,
    defaultFrozen: boolean = false,
    url?: string,
    metadataHash?: string,
  ): Promise<{ assetId: number; txId: string }> {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.algonode.cloud", "");

    // Get account from mnemonic
    const account = algosdk.mnemonicToSecretKey(creatorMnemonic);

    // Get suggested parameters
    const suggestedParams = await algodClient.getTransactionParams().do();

    // Create asset creation transaction
    const txn = algosdk.makeAssetCreateTxnWithSuggestedParamsFromObject({
      from: account.addr,
      assetName,
      unitName,
      total: totalSupply,
      decimals,
      defaultFrozen,
      manager: account.addr,
      reserve: account.addr,
      freeze: account.addr,
      clawback: account.addr,
      assetURL: url,
      assetMetadataHash: metadataHash ? new Uint8Array(Buffer.from(metadataHash, "hex")) : undefined,
      suggestedParams,
    });

    // Sign transaction
    const signedTxn = txn.signTxn(account.sk);

    // Submit transaction
    const { txId } = await algodClient.sendRawTransaction(signedTxn).do();

    // Wait for confirmation
    const confirmedTxn = await algosdk.waitForConfirmation(algodClient, txId, 4);

    // Extract asset ID from transaction
    const assetId = confirmedTxn["asset-index"];

    return {
      assetId,
      txId,
    };
  }

  async optInToAsset(accountMnemonic: string, assetId: number): Promise<{ txId: string }> {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.algonode.cloud", "");

    // Get account from mnemonic
    const account = algosdk.mnemonicToSecretKey(accountMnemonic);

    // Get suggested parameters
    const suggestedParams = await algodClient.getTransactionParams().do();

    // Create asset opt-in transaction (transfer 0 assets to self)
    const txn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      from: account.addr,
      to: account.addr,
      assetIndex: assetId,
      amount: 0,
      suggestedParams,
    });

    // Sign transaction
    const signedTxn = txn.signTxn(account.sk);

    // Submit transaction
    const { txId } = await algodClient.sendRawTransaction(signedTxn).do();

    // Wait for confirmation
    await algosdk.waitForConfirmation(algodClient, txId, 4);

    return { txId };
  }

  async transferAsset(
    fromMnemonic: string,
    toAddress: string,
    assetId: number,
    amount: number,
    note?: string,
  ): Promise<{ txId: string }> {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.algonode.cloud", "");

    // Get account from mnemonic
    const account = algosdk.mnemonicToSecretKey(fromMnemonic);

    // Get suggested parameters
    const suggestedParams = await algodClient.getTransactionParams().do();

    // Create asset transfer transaction
    const txn = algosdk.makeAssetTransferTxnWithSuggestedParamsFromObject({
      from: account.addr,
      to: toAddress,
      assetIndex: assetId,
      amount,
      note: note ? new Uint8Array(Buffer.from(note)) : undefined,
      suggestedParams,
    });

    // Sign transaction
    const signedTxn = txn.signTxn(account.sk);

    // Submit transaction
    const { txId } = await algodClient.sendRawTransaction(signedTxn).do();

    // Wait for confirmation
    await algosdk.waitForConfirmation(algodClient, txId, 4);

    return { txId };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async fundTestnet(address: string): Promise<any> {
    const faucetUrl = `https://bank.testnet.algorand.network/api/v2/accounts/${address}`;
    const response = await fetch(faucetUrl, { method: "POST" });

    if (!response.ok) {
      throw new Error(`Faucet request failed: ${response.statusText}`);
    }

    return await response.json();
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getTransactionHistory(address: string, limit: number = 50): Promise<any> {
    const indexerClient = new algosdk.Indexer("", "https://testnet-idx.algonode.cloud", "");

    try {
      const response = await indexerClient.searchForTransactions().address(address).limit(limit).do();

      return response;
    } catch {
      throw new Error("Failed to fetch transaction history");
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getAssetInfo(assetId: number): Promise<any> {
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.algonode.cloud", "");

    try {
      const assetInfo = await algodClient.getAssetByID(assetId).do();
      return {
        id: assetInfo.index || assetId,
        params: {
          name: assetInfo.params?.name || "",
          unitName: assetInfo.params?.["unit-name"] || assetInfo.params?.unitName || "",
          total: assetInfo.params?.total || 0,
          decimals: assetInfo.params?.decimals || 0,
          defaultFrozen: assetInfo.params?.["default-frozen"] || assetInfo.params?.defaultFrozen || false,
          url: assetInfo.params?.url || "",
          metadataHash: assetInfo.params?.["metadata-hash"] || assetInfo.params?.metadataHash || "",
          manager: assetInfo.params?.manager || "",
          reserve: assetInfo.params?.reserve || "",
          freeze: assetInfo.params?.freeze || "",
          clawback: assetInfo.params?.clawback || "",
          creator: assetInfo.params?.creator || "",
        },
        createdAtRound: assetInfo["created-at-round"] || null,
        deleted: assetInfo.deleted || false,
      };
    } catch {
      throw new Error(`Failed to get asset info: Asset ${assetId} not found or invalid`);
    }
  }

  getPrivateKeyFromMnemonic(mnemonic: string): string {
    const account = algosdk.mnemonicToSecretKey(mnemonic);
    return Buffer.from(account.sk).toString("hex");
  }

  getPublicKeyFromMnemonic(mnemonic: string): string {
    const account = algosdk.mnemonicToSecretKey(mnemonic);
    return Buffer.from(account.sk.slice(32)).toString("hex");
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  formatTransactionType(txn: any): string {
    if (txn["tx-type"] === "pay") {
      return "Payment";
    } else if (txn["tx-type"] === "axfer") {
      return "Asset Transfer";
    } else if (txn["tx-type"] === "acfg") {
      if (txn["asset-config-transaction"]["asset-id"] === 0) {
        return "Asset Creation";
      } else {
        return "Asset Configuration";
      }
    } else if (txn["tx-type"] === "afrz") {
      return "Asset Freeze";
    } else if (txn["tx-type"] === "appl") {
      return "Application Call";
    } else if (txn["tx-type"] === "keyreg") {
      return "Key Registration";
    }
    return txn["tx-type"].toUpperCase();
  }

  formatAmount(amount: number, decimals: number = 6): string {
    return (amount / Math.pow(10, decimals)).toFixed(decimals);
  }

  // Swap-related methods using Pera Swap
  getPeraSwapClient(): PeraSwap {
    return new PeraSwap("testnet"); // Using testnet for development
  }

  async getSwapQuote(
    fromAssetId: number,
    toAssetId: number,
    amount: string,
    walletAddress: string,
    slippage: string = "0.005", // 0.5% default slippage
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
  ): Promise<any> {
    const peraSwap = this.getPeraSwapClient();

    try {
      const response = await peraSwap.createQuote({
        providers: ["tinyman", "vestige-v4"],
        swapper_address: walletAddress,
        swap_type: "fixed-input",
        asset_in_id: fromAssetId,
        asset_out_id: toAssetId,
        amount: amount,
        slippage: slippage,
      });

      return response.results[0]; // Return the best quote
    } catch (error) {
      throw new Error(`Failed to get swap quote: ${error}`);
    }
  }

  async executeSwap(quoteId: string, mnemonic: string): Promise<{ txId: string; confirmedRound: number }> {
    const peraSwap = this.getPeraSwapClient();
    const account = algosdk.mnemonicToSecretKey(mnemonic);
    const algodClient = new algosdk.Algodv2("", "https://testnet-api.algonode.cloud", "");

    try {
      // Get prepared transactions from Pera
      const preparedTxns = await peraSwap.prepareTransactions(quoteId);

      if (!preparedTxns.transaction_groups || preparedTxns.transaction_groups.length === 0) {
        throw new Error("No transaction groups received from Pera Swap");
      }

      console.log(`Processing ${preparedTxns.transaction_groups.length} transaction groups`);

      // Process each transaction group separately and submit them individually
      let finalTxId = "";
      let finalConfirmedRound = 0;

      for (const group of preparedTxns.transaction_groups) {
        console.log(`Processing group: ${group.purpose}`);

        if (!group.transactions || group.transactions.length === 0) {
          console.log("No transactions in this group, skipping");
          continue;
        }

        const txnGroup: algosdk.Transaction[] = [];

        // Decode all transactions in this group
        for (let i = 0; i < group.transactions.length; i++) {
          const txnB64 = group.transactions[i];
          if (!txnB64) {
            console.log(`Skipping null transaction at index ${i}`);
            continue;
          }

          try {
            const txnBytes = new Uint8Array(Buffer.from(txnB64, "base64"));
            const txn = algosdk.decodeUnsignedTransaction(txnBytes);
            txnGroup.push(txn);

            const txnFromAddress = algosdk.encodeAddress(txn.from.publicKey);
            console.log(`Transaction ${i + 1}: from ${txnFromAddress}, type: ${txn.type}`);
          } catch (error) {
            console.error(`Error decoding transaction ${i}:`, error);
          }
        }

        if (txnGroup.length === 0) {
          console.log("No valid transactions to process in this group");
          continue;
        }

        // DON'T assign new group IDs - Pera has already set them correctly
        // The transactions already have the proper group IDs from Pera
        console.log(`Keeping original group IDs for ${txnGroup.length} transactions`);

        // Sign only the transactions that are from our address
        const signedTxns: Uint8Array[] = [];

        for (let i = 0; i < txnGroup.length; i++) {
          const txn = txnGroup[i];
          const txnFromAddress = algosdk.encodeAddress(txn.from.publicKey);

          if (txnFromAddress === account.addr) {
            // This transaction is from our address - we sign it
            const signedTxn = txn.signTxn(account.sk);
            signedTxns.push(signedTxn);
            console.log(`Signed transaction ${i + 1} from our address`);
          } else {
            // This transaction is from another address - check if Pera provided a signed version
            if (group.signed_transactions && group.signed_transactions[i]) {
              const signedTxnB64 = group.signed_transactions[i];
              const signedTxnBytes = new Uint8Array(Buffer.from(signedTxnB64, "base64"));
              signedTxns.push(signedTxnBytes);
              console.log(`Using pre-signed transaction ${i + 1} from ${txnFromAddress}`);
            } else {
              // This is likely a logic signature transaction - include it unsigned
              const encodedTxn = algosdk.encodeUnsignedTransaction(txn);
              signedTxns.push(encodedTxn);
              console.log(`Including unsigned transaction ${i + 1} from ${txnFromAddress} (likely LogicSig)`);
            }
          }
        }

        if (signedTxns.length === 0) {
          console.log("No transactions to submit in this group");
          continue;
        }

        console.log(`Submitting ${signedTxns.length} transactions for group: ${group.purpose}`);

        // Submit this group of transactions
        const { txId } = await algodClient.sendRawTransaction(signedTxns).do();
        console.log(`Group ${group.purpose} submitted with txId: ${txId}`);

        // Wait for confirmation
        const confirmedTxn = await algosdk.waitForConfirmation(algodClient, txId, 4);

        finalTxId = txId;
        finalConfirmedRound = confirmedTxn["confirmed-round"];

        console.log(`Group ${group.purpose} confirmed in round: ${finalConfirmedRound}`);
      }

      if (!finalTxId) {
        throw new Error("No transactions were submitted");
      }

      return {
        txId: finalTxId,
        confirmedRound: finalConfirmedRound,
      };
    } catch (error) {
      console.error("Detailed swap error:", error);
      throw new Error(`Swap execution failed: ${error}`);
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async searchSwapAssets(query: string): Promise<any[]> {
    const peraSwap = this.getPeraSwapClient();

    try {
      return await peraSwap.searchAssets(query);
    } catch (error) {
      console.error("Error searching assets:", error);
      return [];
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getAvailableSwapAssets(assetInId: number): Promise<any[]> {
    const peraSwap = this.getPeraSwapClient();

    try {
      const response = await peraSwap.getAvailableAssets({ asset_in_id: assetInId });
      return response.results;
    } catch (error) {
      console.error("Error getting available assets:", error);
      return [];
    }
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getSwapAsset(assetId: number): Promise<any | null> {
    const peraSwap = this.getPeraSwapClient();

    try {
      return await peraSwap.getAsset(assetId);
    } catch (error) {
      console.error("Error getting swap asset:", error);
      return null;
    }
  }

  clearCache(): void {
    this.cachedWallet = null;
  }
}
