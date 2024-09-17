package ru.sberbank.pprb.sbbol.upgapi.rko.integrations_test;



public class StringUtil {

    public static final String UTF8 = "UTF-8";

    public static String bytesToHex(byte[] data) {
        if (data == null) {
            return "";
        }
        StringBuffer sb = new StringBuffer(2 * data.length);
        for (int i = 0; i < data.length; i++) {
            int b1 = (data[i] >> 4) & 0x0F;
            int b2 = data[i] & 0x0F;
            int ch1 = ((b1 >= 0xA) ? 'A' + b1 - 0xA : '0' + b1);
            int ch2 = ((b2 >= 0xA) ? 'A' + b2 - 0xA : '0' + b2);
            sb.append((char) ch1);
            sb.append((char) ch2);
        }
        return sb.toString();
    }

    public static byte[] hexToBytes(String str) {
        if (str == null) {
            return null;
        }
        int len = str.length(), blen = (len + 1) / 2;
        //if (blen*2 != len)
        // throw new IllegalArgumentException();
        byte[] buf = new byte[blen];

        for (--len, --blen; len > 0; len -= 2, --blen) {
            buf[blen] = (byte) (asciiToHex(str.charAt(len - 1)) << 4 |
                    asciiToHex(str.charAt(len)));
        }
        if (len == 0) {
            // если len нечетное, то к первому символу неявно добавляется 0
            buf[0] = (byte) asciiToHex(str.charAt(0));
        }
        return buf;
    }

    private static final int asciiToHex(char c) {
        if ((c >= 'A') && (c <= 'F')) {
            return (c - 'A' + 10);
        }
        if ((c >= '0') && (c <= '9')) {
            return (c - '0');
        }
        if ((c >= 'a') && (c <= 'f')) {
            return (c - 'a' + 10);
        }
        throw new IllegalArgumentException();
    }


}
