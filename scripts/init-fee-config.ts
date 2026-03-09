#!/usr/bin/env npx ts-node
/**
 * Initialize Fee Config PDA
 * 
 * One-time setup to create the fee config on-chain.
 * 
 * Usage:
 *   npx ts-node scripts/init-fee-config.ts --authority <PUBKEY> --recipient <PUBKEY>
 * 
 * If no args provided, uses payer pubkey for both authority and recipient.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  TransactionInstruction,
  Transaction,
  SystemProgram,
} from '@solana/web3.js';
import * as fs from 'fs';
import * as path from 'path';

const LAZORKIT_PROGRAM_ID = new PublicKey(
  process.env.LAZORKIT_PROGRAM_ID || 'GkgBgRSHgBuMTUDhcVbnQGjBQyVyEaC8qDznzNNizfxk'
);

const RPC_URL = process.env.RPC_URL || 'https://api.devnet.solana.com';

function deriveFeeConfigPda(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from('fee_config')],
    LAZORKIT_PROGRAM_ID
  );
}

function loadPayer(): Keypair {
  // Try PAYER_KEYPAIR as JSON object with base64 secretKey
  if (process.env.PAYER_KEYPAIR) {
    try {
      const parsed = JSON.parse(process.env.PAYER_KEYPAIR);
      if (parsed.secretKey) {
        const secretKey = Buffer.from(parsed.secretKey, 'base64');
        return Keypair.fromSecretKey(secretKey);
      }
    } catch {
      // Not JSON, treat as path
      if (fs.existsSync(process.env.PAYER_KEYPAIR)) {
        const secretKey = JSON.parse(fs.readFileSync(process.env.PAYER_KEYPAIR, 'utf-8'));
        return Keypair.fromSecretKey(Uint8Array.from(secretKey));
      }
    }
  }
  
  // Try PAYER_SECRET_KEY as JSON array
  if (process.env.PAYER_SECRET_KEY) {
    const secretKey = JSON.parse(process.env.PAYER_SECRET_KEY);
    return Keypair.fromSecretKey(Uint8Array.from(secretKey));
  }
  
  // Try default keypair path
  const keypairPath = path.join(process.env.HOME || '', '.config/solana/id.json');
  if (fs.existsSync(keypairPath)) {
    const secretKey = JSON.parse(fs.readFileSync(keypairPath, 'utf-8'));
    return Keypair.fromSecretKey(Uint8Array.from(secretKey));
  }
  
  throw new Error('No payer keypair found. Set PAYER_KEYPAIR or PAYER_SECRET_KEY');
}

function parseArgs(): { authority?: string; recipient?: string } {
  const args = process.argv.slice(2);
  const result: { authority?: string; recipient?: string } = {};
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--authority' && args[i + 1]) {
      result.authority = args[++i];
    } else if (args[i] === '--recipient' && args[i + 1]) {
      result.recipient = args[++i];
    }
  }
  
  return result;
}

async function main() {
  console.log('🚀 Initializing Fee Config PDA...\n');
  
  const connection = new Connection(RPC_URL, 'confirmed');
  const payer = loadPayer();
  const args = parseArgs();
  
  console.log('Program ID:', LAZORKIT_PROGRAM_ID.toBase58());
  console.log('RPC URL:', RPC_URL);
  console.log('Payer:', payer.publicKey.toBase58());
  
  // Derive fee config PDA
  const [feeConfigPda, bump] = deriveFeeConfigPda();
  console.log('Fee Config PDA:', feeConfigPda.toBase58());
  console.log('Bump:', bump);
  
  // Check if already initialized
  const existingAccount = await connection.getAccountInfo(feeConfigPda);
  if (existingAccount) {
    console.log('\n⚠️  Fee config already initialized!');
    console.log('Account size:', existingAccount.data.length, 'bytes');
    console.log('Owner:', existingAccount.owner.toBase58());
    
    // Parse existing config
    const data = existingAccount.data;
    const authority = new PublicKey(data.slice(1, 33));
    const recipient = new PublicKey(data.slice(33, 65));
    console.log('Authority:', authority.toBase58());
    console.log('Recipient:', recipient.toBase58());
    return;
  }
  
  // Determine authority and recipient
  const authority = args.authority 
    ? new PublicKey(args.authority)
    : payer.publicKey;
    
  const recipient = args.recipient 
    ? new PublicKey(args.recipient)
    : payer.publicKey;
  
  console.log('\nConfig to create:');
  console.log('  Authority:', authority.toBase58());
  console.log('  Recipient:', recipient.toBase58());
  
  // Build instruction
  // Tag: 6 (InitFeeConfig)
  // Data: [tag (1 byte)] + [authority pubkey (32 bytes)] + [recipient pubkey (32 bytes)]
  const data = Buffer.alloc(1 + 32 + 32);
  data.writeUint8(6, 0);  // Tag 6 = InitFeeConfig
  authority.toBuffer().copy(data, 1);
  recipient.toBuffer().copy(data, 33);
  
  const initIx = new TransactionInstruction({
    programId: LAZORKIT_PROGRAM_ID,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: feeConfigPda, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
  
  // Send transaction
  const { blockhash, lastValidBlockHeight } = await connection.getLatestBlockhash();
  const tx = new Transaction().add(initIx);
  tx.recentBlockhash = blockhash;
  tx.feePayer = payer.publicKey;
  tx.sign(payer);
  
  console.log('\n📤 Sending transaction...');
  const sig = await connection.sendRawTransaction(tx.serialize());
  console.log('Signature:', sig);
  
  await connection.confirmTransaction({ signature: sig, blockhash, lastValidBlockHeight });
  console.log('✅ Confirmed!');
  
  // Verify
  const newAccount = await connection.getAccountInfo(feeConfigPda);
  if (newAccount) {
    console.log('\n📋 Fee Config Created:');
    console.log('  Size:', newAccount.data.length, 'bytes');
    const parsedData = newAccount.data;
    console.log('  Authority:', new PublicKey(parsedData.slice(1, 33)).toBase58());
    console.log('  Recipient:', new PublicKey(parsedData.slice(33, 65)).toBase58());
  }
  
  console.log('\n🎉 Done! Fee system is ready.');
  console.log('\nExplorer:', `https://explorer.solana.com/tx/${sig}?cluster=devnet`);
}

main().catch(console.error);
