package ru.sberbank.pprb.sbbol.upgapi.rko.integrations_test;


import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * @author P. Belyaev
 */
public class SRPParams {

    /**
     * Modulus (N)
     */
    public final BigInteger pN = new BigInteger(1, pnBytes);

    //256 bit N
    private static final String pNHex256 =
            "115b8b692e0e045692cf280b436735c77a5a9e8a9e7ed56c965f87db5b2a2ece3";

    // parameter N
    private static final String pNHex = pNHex256;
    private static final byte[] pnBytes = StringUtil.hexToBytes(pNHex);

    private static final byte[] pgBytes = StringUtil.hexToBytes("02");

    /**
     * Generator (g)
     */
    public final BigInteger pg = new BigInteger(1, pgBytes);


    /**
     * Multiplier (k)
     */
    public final BigInteger pk;

    /**
     * Длина генерируемых параметров a и b (в битах)
     */
    public final int pabBitsLen = 256;

    /**
     * Длина генерируемых параметров a и b (в битах)
     */
    private final int pNBitsLen = pnBytes.length * 8;

    /**
     * Кодировка строк в хэше
     */
    public final String stringEncoding = "UTF8";

    /**
     * Нужно ли вычислять interleave хэш при вычислении сессионного ключа K, как описано в rfc2945 или необязательно.
     * Из описания srp-6a не следует, что это нужно делать. Хотя в rfc2945 (srp-3) используется именно этот способ.
     */
    public final boolean requiredInterleaveHashForK = false;

    /**
     * Нужно ли вычислять M1 и M2 для проверки авторизации или достаточно только K.
     * Так как сессионный ключ K не нужен, то, наверное, можно выкинуть вычисление M1 и M2,
     * т.к. можем позволить его скомпрометировать.
     */
    public final boolean requiredMCalculating = false;


    /**
     * Salt length in bits
     */
    public final int saltLen = 80;


    private static SRPParams instance = new SRPParams();
    private static Random secureRandom = new SecureRandom();


    private SRPParams() {
        // k = SHA1(N | PAD(g))
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
        digest.update(pnBytes);
        // 6a requires left-padding
        for (int i = (pNBitsLen >>> 3) - pgBytes.length; i > 0; i--)
            digest.update((byte) 0);
        digest.update(pgBytes);

        byte[] kBytes = digest.digest();
        //parameter K - 7556AA045AEF2CDD07ABAF0F665C3E818913186F for 1024 bit, dbe5dfe0704fee4c85ff106ecd38117d33bcfe50 for 256 bit
        pk = new BigInteger(1, kBytes);
    }

    public static SRPParams getInstance() {
        return instance;
    }

    private byte[] generateRandomBytes(int bitLen) {
        return bigIntToBytes(generateRandom(bitLen));
    }

    public byte[] generateRandomBytes() {
        return bigIntToBytes(generateRandom(pabBitsLen));
    }

    public byte[] generateRandomSalt() {
        return generateRandomBytes(saltLen);
    }

    /**
     * Генерация случайного числа
     * @param bitLen количество бит
     */
    public BigInteger generateRandom(int bitLen) {
        BigInteger r;
        do {
            r = new BigInteger(bitLen, secureRandom);
        } while(r.mod(pN).signum() == 0);
        return r;
    }

    public static MessageDigest newDigest() {
        try {
            return MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e.getMessage(), e);
        }
    }

    /*
     * calculate u
     * SRP-6(a): u = SHA(A || B)
     */
    public BigInteger u(byte[] vAbytes, byte[] vBbytes) {
        MessageDigest digest = newDigest();
        int nlen = pNBitsLen >>> 3;
        // 6a requires left-padding
        for (int i = nlen - vAbytes.length; i > 0; i--)
            digest.update((byte) 0);
        digest.update(vAbytes);
        // 6a requires left-padding
        for (int i = nlen - vBbytes.length; i > 0; i--)
            digest.update((byte) 0);
        digest.update(vBbytes);
        BigInteger u = new BigInteger(1, digest.digest());
        if (u.compareTo(pN) > 0)
            u = u.mod(pN);

  /*
    u for srp-3
    // calculate u is a 32-bit unsigned integer which takes its value
    // from the first 32 bits of the SHA1 hash of B, MSB first
    byte[] uhash = Util.newDigest().digest(vBbytes);
    byte[] fourbytes = {uhash[0], uhash[1], uhash[2], uhash[3]};
    BigInteger vu = new BigInteger(1, fourbytes);
  */

        return u;
    }


    public static byte[] xor(byte[] b1, byte[] b2) {
        int length = Math.max(b1.length, b2.length);
        byte[] result = new byte[length];
        for(int i = 0; i < length; ++i) {
            byte bb1 = i < b1.length ? b1[i] : 0;
            byte bb2 = i < b2.length ? b2[i] : 0;
            result[i] = (byte) (bb1 ^ bb2);
        }
        return result;
    }

    /**
     * Calculates K H(S) or SHA_Interleave(S) depends from requiredInterleaveHashForK
     * @param vS S
     * @return K bytes
     */
    public byte[] calculateK(BigInteger vS) {
        byte[] vSbytes = bigIntToBytes(vS);
        byte[] vk;
        if (!requiredInterleaveHashForK)
            vk = newDigest().digest(vSbytes);
        else
            vk = interleaveHash(vSbytes); // like in rfc2945. Is it required???
        return vk;
    }

    /**
     * calculates M1 = H(H(N) xor H(g), H(I), s, A, B, K)
     * @return
     */
    public byte[] calculateM1(String user, BigInteger vA, BigInteger vB, byte[] salt, byte[] vKbytes) {
        MessageDigest digest = newDigest();
        byte[] hnXORhg = xor(newDigest().digest(pN.toByteArray()),
                newDigest().digest(pg.toByteArray()));
        digest.update(hnXORhg);
        try {
            digest.update(user.getBytes(stringEncoding));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        digest.update(salt);
        digest.update(vA.toByteArray());
        digest.update(vB.toByteArray());
        digest.update(vKbytes);
        return digest.digest();
    }

    /**
     * calculates M2 = H(A, M, K)
     * @return
     */
    public byte[] calculateM2(BigInteger vA, byte[] vM1, byte[] vKbytes) {
        MessageDigest digest = newDigest();
        digest.update(vA.toByteArray());
        digest.update(vM1);
        digest.update(vKbytes);
        return digest.digest();
    }

    /**
     * Perform an interleaved even-odd hash on the byte string
     *
     * From rfc 2495:
     *
     * The SHA_Interleave function used in SRP-SHA1 is used to generate a
     * session key that is twice as long as the 160-bit output of SHA1.  To
     * compute this function, remove all leading zero bytes from the input.
     * If the length of the resulting string is odd, also remove the first
     * byte.  Call the resulting string T.  Extract the even-numbered bytes
     * into a string E and the odd-numbered bytes into a string F, i.e.
     * E = T[0] | T[2] | T[4] | ...
     * F = T[1] | T[3] | T[5] | ...
     * Both E and F should be exactly half the length of T.  Hash each one
     * with regular SHA1, i.e.
     *  G = SHA(E)
     *  H = SHA(F)
     * Interleave the two hashes back together to form the output, i.e.
     * result = G[0] | H[0] | G[1] | H[1] | ... | G[19] | H[19]
     * The result will be 40 bytes (320 bits) long.
     */
    public byte[] interleaveHash(byte[] number) {
        int offset;
        for(offset = 0; offset < number.length && number[offset] == 0; ++offset)
            ;

        byte[] hout;

        int klen = (number.length - offset) / 2;
        byte[] hbuf = new byte[klen];

        for(int i = 0; i < klen; ++i)
            hbuf[i] = number[number.length - 2 * i - 1];
        hout = newDigest().digest(hbuf);
        byte[] key = new byte[2 * hout.length];
        for(int i = 0; i < hout.length; ++i)
            key[2 * i] = hout[i];

        for(int i = 0; i < klen; ++i)
            hbuf[i] = number[number.length - 2 * i - 2];
        hout = newDigest().digest(hbuf);
        for(int i = 0; i < hout.length; ++i)
            key[2 * i + 1] = hout[i];

        return key;
    }

    /**
     * Do BigInteger.toByteArray() and trims leading zeros
     * @param v
     * @return
     */
    public static byte[] bigIntToBytes(BigInteger v) {
        byte[] b = v.toByteArray();
        int k;
        for (k = 0; k < b.length && b[k] == 0; k++)
            ;
        if (k > 0) {
            byte[] b2 = new byte[b.length - k];
            System.arraycopy(b, 1, b2, 0, b2.length);
            b = b2;
        }
        return b;
    }

}
