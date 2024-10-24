---
sidebar_position: 3
---

# Usage of the Service Kit

In this document we are showing how to use the service kit to interact with the
 Network. We will be showing code snippets in Scala.

## Creating a Vault and a Wallet Database

The first step is to create a vault, which securely stores the master key. The vault is encrypted with a password you provide. Along with the vault, we also create a wallet state database to track the wallet's state.

```scala
// You can run this code using scala-cli. Save it in a file called `create-vault.sc` and run it with `scala-cli create-vault.sc`
//> using scala 2.13
//> using repository "sonatype-s01:releases"
//> using dep "co.topl::service-kit:2.0.0-beta2"
//> using dep "org.typelevel::cats-core:2.10.0"

import cats.effect.IO
import co.topl.brambl.wallet.WalletApi
import co.topl.brambl.servicekit.{WalletKeyApi, WalletStateApi, WalletStateResource}
import co.topl.brambl.constants.NetworkConstants

import cats.effect.std
import io.circe.syntax._
import co.topl.crypto.encryption.VaultStore.Codecs._
import cats.effect.unsafe.implicits.global

import java.io.File

case class CreateWallet(file: String, password: String) {
  val walletKeyApi = WalletKeyApi.make[IO]()
  val walletApi = WalletApi.make(walletKeyApi)
  val walletStateApi = WalletStateApi.make[IO](WalletStateResource.walletResource(file), walletApi)

  val createWallet = for {
    wallet <- walletApi
      .createNewWallet(
        password.getBytes(),
        Some("passphrase")
      )
      .map(_.fold(throw _, identity))
    keyPair <- walletApi
      .extractMainKey(
        wallet.mainKeyVaultStore,
        password.getBytes()
      )
      .flatMap(
        _.fold(
          _ =>
            IO.raiseError(
              new Throwable("No input file (should not happen)")
            ),
          IO(_)
        )
      )
    _ <- std.Console[IO].println("Wallet: " + new String(wallet.mainKeyVaultStore.asJson.noSpaces))
    _ <- std.Console[IO].println("Mnemonic: "+ wallet.mnemonic.mkString(","))
    _ <- walletStateApi.initWalletState(
      NetworkConstants.PRIVATE_NETWORK_ID,
      NetworkConstants.MAIN_LEDGER_ID,
      keyPair
    )
  } yield ()

}

val file = "myWallet.db"
val password = "password"
// we delete the wallet before creating it
new File(file).delete()

val wallet = CreateWallet(file, password)
// Create the wallet using:
wallet.createWallet.unsafeRunSync()
```

### Code Breakdown:
1. **Vault Creation**: The `walletApi.createNewWallet` function creates a new wallet in memory.
2. **Key Extraction**: The `walletApi.extractMainKey` function retrieves the main key, which is essential for initializing the wallet state.
3. **Wallet Initialization**: The `walletStateApi.initWalletState` function sets up the wallet's state on the specified network. This includes storing the key pair in the database for future transactions.

### Troubleshooting:
- If the `walletApi.createNewWallet` or `walletApi.extractMainKey` step fails, ensure that the password is correct and the file paths are valid.
- You may also want to verify the permissions of the database file (`myWallet.db`) to ensure it’s accessible.

This will create an encrypted vault and print it to the console. It will also create a wallet state database file called `myWallet.db` and print the mnemonic to recover the wallet.

## Updating the Wallet Database

Whenever a child key from the wallet is used to create a transaction, the wallet state must be updated. This section builds on the previous one and shows how to update the wallet state.

```scala
// You can run this code using scala-cli. Save it in a file called `create-vault.sc` and run it with `scala-cli create-vault.sc`
//> using scala 2.13
//> using repository "sonatype-s01:releases"
//> using dep "co.topl::service-kit:2.0.0-beta2"
//> using dep "org.typelevel::cats-core:2.10.0"

import cats.effect.IO
import co.topl.brambl.wallet.WalletApi
import co.topl.brambl.servicekit.{WalletKeyApi, WalletStateApi, WalletStateResource}
import co.topl.brambl.constants.NetworkConstants
import cats.effect.std
import io.circe.syntax._
import co.topl.crypto.encryption.VaultStore.Codecs._
import cats.effect.unsafe.implicits.global
import cats.implicits.toTraverseOps
import co.topl.brambl.builders.TransactionBuilderApi
import co.topl.brambl.builders.TransactionBuilderApi.implicits.lockAddressOps
import co.topl.brambl.constants.NetworkConstants.{MAIN_LEDGER_ID, PRIVATE_NETWORK_ID}
import co.topl.brambl.models.Indices
import co.topl.brambl.utils.Encoding
import quivr.models.VerificationKey

import java.io.File

case class CreateWallet(file: String, password: String) {
  val walletKeyApi = WalletKeyApi.make[IO]()
  val walletApi = WalletApi.make(walletKeyApi)
  val walletStateApi = WalletStateApi.make[IO](WalletStateResource.walletResource(file), walletApi)

  val createWallet = for {
    wallet <- walletApi
      .createNewWallet(
        password.getBytes(),
        Some("passphrase")
      )
      .map(_.fold(throw _, identity))
    keyPair <- walletApi
      .extractMainKey(
        wallet.mainKeyVaultStore,
        password.getBytes()
      )
      .flatMap(
        _.fold(
          _ =>
            IO.raiseError(
              new Throwable("No input file (should not happen)")
            ),
          IO(_)
        )
      )
    _ <- std.Console[IO].println("Wallet: " + new String(wallet.mainKeyVaultStore.asJson.noSpaces))
    _ <- std.Console[IO].println("Mnemonic: "+ wallet.mnemonic.mkString(","))
    // Initialize the wallet state:
    _ <- walletStateApi.initWalletState(
      NetworkConstants.PRIVATE_NETWORK_ID,
      NetworkConstants.MAIN_LEDGER_ID,
      keyPair
    )
  } yield ()

  // highlight-start
  val updateWallet = for {
    indices <- IO.pure(Indices(1, 1, 2))
    lock <- walletStateApi.getLock("self", "default", indices.z).map(_.get)
    lockAddress <- TransactionBuilderApi.make[IO](PRIVATE_NETWORK_ID, MAIN_LEDGER_ID).lockAddress(lock).map(_.toBase58())
    lockPredicate = Encoding.encodeToBase58Check(lock.getPredicate.toByteArray)
    parentVk <- walletStateApi.getEntityVks("self", "default")
      .map(_.sequence.head.map(pVk => VerificationKey.parseFrom(Encoding.decodeFromBase58(pVk).toOption.get)))
    vk <- parentVk.map(pVk => walletApi.deriveChildVerificationKey(pVk, indices.z)
      .map(cVk => Encoding.encodeToBase58(cVk.toByteArray))).sequence
    _ <- walletStateApi.updateWalletState(lockPredicate, lockAddress, Some("ExtendedEd25519"), vk, indices)
  } yield ()
  // highlight-end
}

val file = "myWallet.db"
val password = "password"
// we delete the wallet before creating it
new File(file).delete()

val wallet = CreateWallet(file, password)
wallet.createWallet.unsafeRunSync()

// Update the wallet using:
// highlight-next-line
wallet.updateWallet.unsafeRunSync()
```

### Key Concepts:
- **Lock**: A lock is associated with specific indices in the wallet. It acts as a security mechanism to control access to funds.
- **Predicate**: This is a condition encoded in the lock that must be fulfilled for the lock to be opened.
- **Verification Key**: The verification key is derived from a parent key and is used to authenticate transactions.

### Steps:
1. Set the indices to `(x=1, y=1, z=2)` to represent the "self" fellowship and "default" template.
2. Retrieve the lock using the `getLock` function for the chosen indices.
3. Generate a lock address from the lock using the `TransactionBuilder`.
4. Encode the lock's predicate using Base58 encoding.
5. Retrieve the parent verification key for "self" and "default" using `getEntityVks`.
6. Derive a child verification key from the parent key using the new index (z=2).
7. Update the wallet state using the `updateWalletState` function to reflect the changes.

### Troubleshooting:
- If you encounter issues retrieving the lock or verification key, ensure that the indices match the initialized state from the previous section.
- Verify that the encoded predicate and lock address are correctly generated before updating the wallet state.
