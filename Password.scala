val LOWERS = "abcdefghijklmnopqrstuvwxyz"
val UPPERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
val NUMS = "0123456789"
val SYMS = """`-=[]\;',./~!@#$%^&*()_+{}|:"<>?"""
val ALLCHARS = LOWERS + UPPERS + NUMS + SYMS

var len = 8
if (args.length > 0) {
  len = Integer.parseInt(args(0))
  if (args.length > 1 || len < 4) {
    println("usage: password <length>")
    sys.exit(1)
  }
}

val rand = new java.security.SecureRandom
(1 to 10).foreach { attempt =>
  val pw = (1 to len).map { i => ALLCHARS(rand.nextInt(ALLCHARS.length)) }.mkString("")
  val missing = Array(LOWERS, UPPERS, NUMS, SYMS).filter { group =>
    pw.filter { char => group.contains(char) }.isEmpty
  }
  if (missing.isEmpty) {
    println(pw)
    sys.exit(0)
  }
}

println("failed to find a good password")
sys.exit(1)
