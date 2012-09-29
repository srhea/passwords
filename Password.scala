import java.io.{ DataInputStream, DataOutputStream, FileInputStream, FileOutputStream }
import java.security.SecureRandom
import javax.crypto.{ Cipher, SecretKeyFactory }
import javax.crypto.spec.{ IvParameterSpec, PBEKeySpec, SecretKeySpec }

class Vault(password: Array[Char], salt: Array[Byte]) {
  val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1")
  val spec = new PBEKeySpec(password, salt, 65536 /* iterations */, 256 /* key length */)
  val secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded, "AES")

  def encrypt(plaintext: Array[Byte]) = {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.ENCRYPT_MODE, secret)
    val iv = cipher.getParameters.getParameterSpec(classOf[IvParameterSpec]).getIV
    val ciphertext = cipher.doFinal(plaintext)
    (iv, ciphertext)
  }

  def decrypt(iv: Array[Byte], ciphertext: Array[Byte]) = {
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv))
    cipher.doFinal(ciphertext)
  }
}

class VaultFile(filename: String, password: Array[Char]) {
  val FileVersion = 1

  // Cribbed from Beginning Scala by David Pollack, pp. 109-112.
  def using[A <: {def close(): Unit}, B](a: A)(f: A => B): B = try { f(a) } finally { a.close() }

  def read: Array[Byte] = {
    using(new DataInputStream(new FileInputStream(filename))) { is =>
      def readBytes() = {
        val length = is.readInt()
        val result = new Array[Byte](length)
        is.readFully(result, 0, length)
        result
      }
      val version = is.readInt()
      if (version != FileVersion)
        throw new Exception("unknown file version: " + version)
      val salt = readBytes()
      val iv = readBytes()
      val ciphertext = readBytes()
      val vault = new Vault(password, salt)
      vault.decrypt(iv, ciphertext)
    }
  }

  def write(plaintext: Array[Byte]) {
    using(new DataOutputStream(new FileOutputStream(filename))) { os =>
      def writeBytes(bytes: Array[Byte]) {
        os.writeInt(bytes.length)
        os.write(bytes, 0, bytes.length)
      }
      val rand = new SecureRandom
      val salt = new Array[Byte](16)
      rand.nextBytes(salt)
      val vault = new Vault(password, salt)
      val (iv, ciphertext) = vault.encrypt(plaintext)
      os.writeInt(FileVersion)
      writeBytes(salt)
      writeBytes(iv)
      writeBytes(ciphertext)
    }
  }
}

object Password {
  def generate(length: Int): String = {
    val Lowers = "abcdefghijklmnopqrstuvwxyz"
    val Uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    val Digits = "0123456789"
    val Symbols = """`-=[]\;',./~!@#$%^&*()_+{}|:"<>?"""
    val Groups = Array(Lowers, Uppers, Digits, Symbols)
    val All = Groups.mkString("")

    val rand = new SecureRandom
    (1 to 100).foreach { attempt =>
      val result = (1 to length).map { i => All(rand.nextInt(All.length)) }.mkString("")
      val missing = Groups.filter { group => result.filter { c => group.contains(c) }.isEmpty }
      if (missing.isEmpty)
        return result
    }
    throw new Exception("failed to find a good password")
  }

  def main(args: Array[String]) {
    var length = 8
    if (args.length > 0) {
      length = Integer.parseInt(args(0))
      if (args.length > 1 || length < 4) {
        println("usage: password <length>")
        sys.exit(1)
      }
    }
    println(generate(length))
  }
}
