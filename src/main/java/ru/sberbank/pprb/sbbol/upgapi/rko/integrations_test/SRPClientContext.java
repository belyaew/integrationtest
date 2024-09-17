package ru.sberbank.pprb.sbbol.upgapi.rko.integrations_test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;


/**
 * @author P. Belyaev
 */
public final class SRPClientContext {
  private SRPParams srpParams = SRPParams.getInstance();

  // prefix v for variables used in srp algorithm
  private byte[] vUserPasswordHash; // SHA(U | ":" | p) (where p=<raw password>)
  private BigInteger va; // random()
  private BigInteger vA; // g^a % N
  private byte[] vKbytes;
  private byte[] clientData; // request to the server
  private String user;

  public SRPClientContext(String user, String password) {
    MessageDigest digest = SRPParams.newDigest();
    //по требованию банка пароль нужно тримить перед вычислением хэша
      vUserPasswordHash = digest.digest((user + ":" + (password == null? "" : password.trim()) ).getBytes());
    // a = random()
    va = srpParams.generateRandom(srpParams.pabBitsLen);
    // A = g^a % N
    vA = srpParams.pg.modPow(va, srpParams.pN);
    this.user = user;
  }

  /**
   * Generates password verifier: v = g^x % N. <br>
   * This method used for generation new password.
   * Verifier need send to the server
   * @param salt from the server
   * @return password verifier
   */
  public byte[] calculateVerifier(byte[] salt) {
    SRPParams srpParams = SRPParams.getInstance();
    BigInteger vx = xCalculate(salt);
    BigInteger vv = srpParams.pg.modPow(vx, srpParams.pN);
    return SRPParams.bigIntToBytes(vv);
  }

  /**
   *
   * @param salt server salt
   * @param vBbytes B bytes from server calculated by B = kv + g^b % N
   */
  public byte[] makeAuthorizationData(byte[] salt, byte[] vBbytes) {
    BigInteger vB = new BigInteger(1, vBbytes);

    // calculate x = SHA(s | SHA(U | ":" | p))
    BigInteger vx = xCalculate(salt);

    // calculate u = SHA-1(A || B)
    BigInteger vu = srpParams.u(getAbytes(), vBbytes);

    // Check correct server data
    // The user will abort if he receives B == 0 (mod N) or u == 0.
    if (vB.mod(srpParams.pN).signum() == 0 || vu.signum() == 0)
      throw new IllegalArgumentException("Bad SRP server data");

    // calculate S = (B - kg^x) ^ (a + ux) % N
    BigInteger kgN = srpParams.pg.modPow(vx, srpParams.pN);
    BigInteger base = vB.subtract(srpParams.pk.multiply(kgN));
    if (base.signum() < 0)
      base = base.add(srpParams.pN.multiply(srpParams.pk));
    BigInteger exp = va.add(vx.multiply(vu)); // a + ux
    BigInteger vS = base.modPow(exp, srpParams.pN);
    vKbytes = srpParams.calculateK(vS);
    clientData = vKbytes;
    if (srpParams.requiredMCalculating) {
      clientData = srpParams.calculateM1(user, vA, vB, salt, vKbytes);
    }
    return clientData;
  }

  public void verifyServerReply(byte[] serverData) {
    boolean valid;
    if (srpParams.requiredMCalculating) {
      byte[] vM2 = srpParams.calculateM2(vA, clientData, vKbytes);
      valid = Arrays.equals(serverData, vM2);
    } else {
      valid = serverData != null && serverData.length >=0;
    }
    if (!valid)
      throw new IllegalStateException("Bad SRP server data");
  }

  public byte[] getAbytes() {
    return SRPParams.bigIntToBytes(vA);
  }

  /**
   * calculate x = SHA(s | SHA(U | ":" | p))
   * @param vs salt from server
   * @return x
   */
  private BigInteger xCalculate(byte[] vs) {
    MessageDigest digest = SRPParams.newDigest();
    digest.update(vs);
    digest.update(vUserPasswordHash);
    BigInteger vx = new BigInteger(1, digest.digest());
    if (vx.compareTo(srpParams.pN) > 0)
      vx = vx.mod(srpParams.pN);
    return vx;
  }
}
