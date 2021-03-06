// Copyright (c) 2012 Sean C. Rhea <sean.c.rhea@gmail.com>
// See LICENSE file for details.

import java.io.{ ByteArrayInputStream, ByteArrayOutputStream }
import java.io.{ DataInputStream, DataOutputStream, File, FileInputStream, FileOutputStream }
import java.security.SecureRandom
import javax.crypto.{ Cipher, SecretKeyFactory }
import javax.crypto.spec.{ IvParameterSpec, PBEKeySpec, SecretKeySpec }
import scala.collection.immutable.SortedMap
import scala.collection.mutable.ArrayBuffer

// http://docs.oracle.com/javase/6/docs/technotes/guides/security/crypto/CryptoSpec.html#PBEEx
// http://stackoverflow.com/questions/992019/java-256-bit-aes-password-based-encryption
// http://en.wikipedia.org/wiki/Key_stretching
class PBE(password: Array[Char], salt: Array[Byte]) {
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

case class Login(url: String, user: String) extends Ordered[Login] {
  def compare(that: Login) = {
    val r = url.compare(that.url)
    if (r == 0) user.compare(that.url) else r
  }
}

case class Password(pw: String, mtime: Long) // milliseconds since the epoch

class Vault(file: File, val password: Array[Char]) {
  val Version = "1.1"
  val InfoString = "Passwords Version %s, https://github.com/srhea/passwords".format(Version)
  val Terminator = '\0'.toByte

  // Cribbed from Beginning Scala by David Pollack, pp. 109-112.
  def using[A <: {def close(): Unit}, B](a: A)(f: A => B): B = try { f(a) } finally { a.close() }

  def readBytes(is: DataInputStream) = {
    val length = is.readInt()
    val result = new Array[Byte](length)
    is.readFully(result, 0, length)
    result
  }

  def writeBytes(os: DataOutputStream, bytes: Array[Byte]) {
    os.writeInt(bytes.length)
    os.write(bytes)
  }

  def readPlaintext: Pair[Array[Byte], String] = {
    using(new DataInputStream(new FileInputStream(file))) { is =>
      def readLine(): String = {
        val buffer = new ArrayBuffer[Byte]
        while (true) {
          val byte = is.readByte()
          if (byte == Terminator)
            return new String(buffer.toArray, "UTF-8")
          buffer += byte
        }
        "" // unreachable
      }
      val infoString = readLine()
      val regex = """Passwords Version (\d+\.\d+)""".r
      val version = regex.findFirstMatchIn(infoString) match {
        case None =>
          println("Can't find version number in " + file.getPath)
          sys.exit(1)
          ""
        case Some(m) =>
          val version = m.group(1)
          if (version != Version && version != "1.0") {
            println("Unknown file version " + version + " in " + file.getPath)
            sys.exit(1)
          }
          version
      }
      val salt = readBytes(is)
      val iv = readBytes(is)
      val ciphertext = readBytes(is)
      val cipher = new PBE(password, salt)
      (cipher.decrypt(iv, ciphertext), version)
    }
  }

  def writeCiphertext(plaintext: Array[Byte]) {
    val tmp = File.createTempFile(".passwords.", ".tmp", file.getParentFile)
    using(new DataOutputStream(new FileOutputStream(tmp))) { os =>
      val rand = new SecureRandom
      val salt = new Array[Byte](16)
      rand.nextBytes(salt)
      val cipher = new PBE(password, salt)
      val (iv, ciphertext) = cipher.encrypt(plaintext)
      os.write(InfoString.getBytes("UTF-8"))
      os.write(Terminator)
      writeBytes(os, salt)
      writeBytes(os, iv)
      writeBytes(os, ciphertext)
    }
    // Java 1.6 has no atomic, overwriting rename, and Java 1.7 isn't widely installed.
    // Instead use a pair of renames. Also see recovery code in init(), below.
    val bak = new File(file.getAbsolutePath + ".bak")
    bak.delete // In case there's one from a previous crash.
    file.renameTo(bak)
    tmp.renameTo(file)
    bak.delete
  }

  def read: Map[Login, Password] = {
    val (plaintext, version) = readPlaintext
    using(new DataInputStream(new ByteArrayInputStream(plaintext))) { is =>
      def readString() = new String(readBytes(is), "UTF-8")
      val entryCount = is.readInt()
      (1 to entryCount).map { i =>
        val url = readString
        val user = readString
        val password = readString
        val mtime = if (version == "1.1") is.readLong() else 0
        Login(url, user) -> Password(password, mtime)
      }.toMap
    }
  }

  def write(db: Map[Login, Password]) {
    val bs = new ByteArrayOutputStream
    using(new DataOutputStream(bs)) { os =>
      def writeString(s: String) = writeBytes(os, s.getBytes("UTF-8"))
      os.writeInt(db.size)
      for ((login, password) <- db) {
        writeString(login.url)
        writeString(login.user)
        writeString(password.pw)
        os.writeLong(password.mtime)
      }
    }
    writeCiphertext(bs.toByteArray)
  }
}

object Passwords {

  val file = new File(System.getProperty("user.home"), ".passwords")
  lazy val masterPassword = System.console.readPassword("Master password: ")

  val Lowers = "abcdefghijklmnopqrstuvwxyz"
  val Uppers = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
  val Digits = "0123456789"
  val Symbols = "_"
  val Groups = Array(Lowers, Uppers, Digits, Symbols)
  val All = Groups.mkString("")

  def possiblePasswords(length: Int): Double = {
    val all = math.pow(All.length, length)
    val noU = math.pow(All.length - Uppers.length, length)
    val noL = math.pow(All.length - Lowers.length, length)
    val noD = math.pow(All.length - Digits.length, length)
    val noS = math.pow(All.length - Symbols.length, length)
    val noUnoL = math.pow(Digits.length + Symbols.length, length)
    val noUnoD = math.pow(Lowers.length + Symbols.length, length)
    val noUnoS = math.pow(Lowers.length + Digits.length, length)
    val noLnoD = math.pow(Uppers.length + Symbols.length, length)
    val noLnoS = math.pow(Uppers.length + Digits.length, length)
    val noDnoS = math.pow(Uppers.length + Lowers.length, length)
    val U = math.pow(Uppers.length, length)
    val L = math.pow(Uppers.length, length)
    val D = math.pow(Uppers.length, length)
    val S = math.pow(Uppers.length, length)
    all - (noU + noL + noD + noS
           - noUnoL - noUnoD - noUnoS - noLnoD - noLnoS - noDnoS
           + U + L + D + S)
  }

  def generate(length: Int): String = {
    val rand = new SecureRandom
    for (attempt <- (1 to 100)) {
      val result = (1 to length).map { i => All(rand.nextInt(All.length)) }.mkString("")
      val missing = Groups.filter { group => result.filter { c => group.contains(c) }.isEmpty }
      if (missing.isEmpty)
        return result
    }
    println("Failed to find a good password.")
    sys.exit(1)
  }

  var oneShot = false
  def usage() {
    if (oneShot) {
      println("""|Usage:
                 |  passwords <command> [<args>]""".stripMargin)
    }
    println("""|Commands:
               |  strength [length]
               |  generate [length]
               |  add <url> <username>
               |  addgen <url> <username> [length]
               |  remove <url> <username>
               |  list
               |  search <search string>
               |  merge <other file>""".stripMargin)
    if (oneShot)
      sys.exit(1)
  }

  def confirm(msg: String) {
    val yesno = System.console.readLine(msg)
    if (!Array("y", "yes").contains(yesno.toLowerCase))
      sys.exit(1)
  }

  def init(file: File, exitIfMissing: Boolean): Pair[Vault, Map[Login, Password]] = {
    val bak = new File(file.getAbsolutePath + ".bak")
    if (!file.exists && bak.exists) {
      // Recover from previous crash.
      bak.renameTo(file)
    }
    if (file.exists) {
      val vault = new Vault(file, masterPassword)
      val db = try { vault.read } catch {
        case e: Exception => println("Password incorrect."); sys.exit(1)
      }
      (vault, db)
    } else {
      println("No existing passwords database.")
      if (exitIfMissing)
        sys.exit(1)
      val first = System.console.readPassword("Enter a master password: ")
      val second = System.console.readPassword("Confirm master password: ")
      if (!first.sameElements(second)) {
        println("Passwords do not match.")
        sys.exit(1)
      }
      val vault = new Vault(file, first)
      val db = Map[Login, Password]()
      vault.write(db)
      (vault, db)
    }
  }

  def runOneCommand(args: Array[String]) {
    val defaultLength = 10
    if (args.length == 0) {
      usage()
      return
    }
    args.head match {
      case "exit" | "quit" =>
        sys.exit(0)
      case "generate" | "strength" =>
        val length = if (args.length > 1) Integer.parseInt(args(1)) else defaultLength
        if (length < 4) {
          println("Length must be at least 4.")
          return
        }
        if (args.head == "generate") {
          println(generate(length))
        } else {
          val choices = possiblePasswords(length)
          val bits = (Math.log(choices) / Math.log(2)).floor.toInt
          println(bits + " bits of entropy")
        }
      case "list" =>
        val (vault, db) = init(file, true)
        for ((login, password) <- SortedMap(db.toSeq: _*)) {
          println(login.url + " " + login.user)
        }
      case "search" =>
        if (args.length < 2) {
          usage()
          return
        }
        val search = args(1)
        val (vault, db) = init(file, true)
        val matches = db.filter { case (login, password) => login.url.contains(search) }
        if (matches.isEmpty)
          println("No passwords for urls matching \"%s\".".format(search))
        for ((login, password) <- matches) {
          println(login.url + " " + login.user + " " + password.pw)
        }
      case "add" | "addgen" =>
        if (args.length < 3) {
          usage()
          return
        }
        val login = Login(args(1), args(2))
        val (vault, db) = init(file, false)
        if (db.contains(login))
          confirm("Overwrite existing entry? (Y/N): ")
        val password = if (args.head == "addgen") {
          val length = if (args.length > 3) Integer.parseInt(args(3)) else defaultLength
          val pw = generate(length)
          println("Pasword is " + pw)
          pw
        } else {
          val pw = new String(System.console.readPassword("Password: "))
          val again = new String(System.console.readPassword("Confirm password: "))
          if (pw != again) {
            println("Passwords do not match.")
            return
          }
          pw
        }
        vault.write(db + (login -> Password(password, System.currentTimeMillis)))
      case "remove" =>
        if (args.length < 3) {
          usage()
          return
        }
        val login = Login(args(1), args(2))
        val (vault, db) = init(file, true)
        if (!db.contains(login)) {
          println("No matching url and username. Try \"passwords search " + login.url + "\".")
          return
        }
        confirm("Really remove this entry? (Y/N): ")
        vault.write(db - login)
      case "merge" =>
        if (args.length < 2) {
          usage()
          return
        }
        val otherFile = new File(args(1))
        val (vault, db) = init(file, true)
        val otherVault = new Vault(otherFile, vault.password)
        val otherDb = try { otherVault.read } catch {
          case e: Exception => println("Master password in " + args(1) + " differs."); return
        }
        val onlyInDb = db.filterKeys { k => !otherDb.contains(k) }
        val onlyInOtherDb = otherDb.filterKeys { k => !db.contains(k) }
        val inBoth = for {
          (login, password) <- db
          otherPassword <- otherDb.get(login)
        } yield {
          (login, (if (password.mtime > otherPassword.mtime) password else otherPassword))
        }
        vault.write(onlyInDb ++ onlyInOtherDb ++ inBoth)
      case _ => usage()
    }
  }

  def main(args: Array[String]) {
    if (!args.isEmpty) {
      oneShot = true
      runOneCommand(args)
    } else {
      while (true) {
        runOneCommand(System.console.readLine("> ").split("""\s+"""))
      }
    }
  }
}
