import java.security.SecureRandom

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
