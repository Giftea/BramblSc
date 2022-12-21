package co.topl.crypto.generation

import co.topl.crypto.generation.mnemonic.Entropy
import co.topl.models.Bytes
import co.topl.models.utility.HasLength.instances._
import co.topl.models.utility.{Length, Sized}
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.KeyParameter
import scodec.bits.ByteVector

import java.nio.charset.StandardCharsets

trait EntropyToSeed[SeedLength <: Length] {
  def toSeed(entropy: Entropy, password: Option[String]): ByteVector
}

object EntropyToSeed {

  trait Instances {

    implicit def pbkdf2Sha512[SeedLength <: Length](implicit seedLength: SeedLength): EntropyToSeed[SeedLength] =
      (entropy: Entropy, password: Option[String]) => {
        val kdf = new Pbkdf2Sha512()
        ByteVector(
          kdf.generateKey(
            password.getOrElse("").getBytes(StandardCharsets.UTF_8),
            entropy.value.toArray,
            seedLength.value,
            4096
          )
        )
      }
  }

  object instances extends Instances
}

/**
 * PBKDF-SHA512 defines a function for creating a public key from a password and salt.
 *
 * It repeats the HMAC-SHA512 hashing function a given number of iterations and then slices a number of bytes off the
 * result.
 *
 * NOTE: This is a class wrapper on the Java impl to help with thread safety issues that were occurring during testing
 */
class Pbkdf2Sha512 {

  /**
   * Generates a public key from the given message and salt.
   *
   * Runs HMAC-SHA512 a given number of iterations and creates a key of given size.
   *
   * @param password the password to create a public key for
   * @param salt the salt to apply
   * @param keySizeBytes the resulting key size in bytes
   * @param iterations the number of iterations to run
   * @return the bytes of the key result
   */
  def generateKey(password: Array[Byte], salt: Array[Byte], keySizeBytes: Int, iterations: Int): Array[Byte] = {
    val generator = new PKCS5S2ParametersGenerator(new SHA512Digest)
    generator.init(password, salt, iterations)
    generator.generateDerivedParameters(keySizeBytes * 8).asInstanceOf[KeyParameter].getKey
  }
}
