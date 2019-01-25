package org.aion.offline;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import org.aion.api.IAionAPI;
import org.aion.api.type.ApiMsg;
import org.aion.api.type.MsgRsp;
import org.aion.base.type.AionAddress;
import org.aion.base.type.Hash256;
import org.aion.base.util.ByteArrayWrapper;
import org.aion.rlp.RLP;

public class TxTool {

    private static byte[] addSkPrefix(String skString) {
        String skEncoded = "302e020100300506032b657004220420" + skString;
        return hexToBytes(skEncoded);
    }

    private static byte[] blake2b(byte[] msg) {
        Blake2b digest = Blake2b.Digest.newInstance(32);
        digest.update(msg);
        return digest.digest();
    }

    private static byte[] hexToBytes(String s) {
        byte[] biBytes = new BigInteger("10" + s.replaceAll("\\s", ""), 16).toByteArray();
        return Arrays.copyOfRange(biBytes, 1, biBytes.length);
    }

    private static byte hexToByte(String s) {
        return hexToBytes(s)[0];
    }

    private static String bytesToHex(byte[] bytes) {
        BigInteger bigInteger = new BigInteger(1, bytes);
        return bigInteger.toString(16);
    }

    private static byte[] sign(EdDSAPrivateKey privateKey, byte[] data) throws Throwable {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        EdDSAEngine edDSAEngine = new EdDSAEngine(
            MessageDigest.getInstance(spec.getHashAlgorithm()));

        edDSAEngine.initSign(privateKey);

        return edDSAEngine.signOneShot(data);
    }

    public static void main(String[] args) throws Throwable {

        if (6 == args.length) {

            IAionAPI api = IAionAPI.init();
            // We need the user to specify:

            // Api URL
            api.connect(args[0]);


            // PRIVATE KEY
            EdDSAPrivateKey privateKey = new EdDSAPrivateKey(
                new PKCS8EncodedKeySpec(addSkPrefix(args[1])));

            byte[] publicKey = privateKey.getAbyte();

            byte[] addrBytes = blake2b(publicKey);
            addrBytes [0] = hexToByte("a0");

            // -TO
            byte[] to = hexToBytes(args[2]);

            // -VALUE
            byte[] value = hexToBytes(args[3]);

            // -DATA
            byte[] data = hexToBytes(args[4]);

            // -TYPE
            byte type = hexToByte(args[5]);

            // Things we calculate:

            // -NONCE
            AionAddress acc = new AionAddress(addrBytes);
            BigInteger nonceBI = api.getChain().getNonce(acc).getObject();
            byte[] nonce = nonceBI.toByteArray();

            // -TIMESTAMP
            // (nanos)
            byte[] timestamp = BigInteger.valueOf(System.currentTimeMillis() * 1000).toByteArray();

            // Things we hard-code:
            // -ENERGY
            long energy = 350_000L;
            // -ENERGY PRICE
            long energyPrice = 10_000_000_000L;

            // Notes for serialization.
            // 1) NONCE (byte[])
            // 2) TO (byte[])
            // 3) VALUE (byte[])
            // 4) DATA (byte[])
            // 5) TIMESTAMP (byte[])
            // 6) NRG (long)
            // 7) NRG PRICE (long)
            // 8) TYPE (byte)
            // (optional 9) SIGNATURE (byte[]) (HashUtil.h256(encodeList(1-8))
            // FINAL: encode either (1-8) or (1-9) as list

            byte[] nonce_1 = RLP.encodeElement(nonce);
//            System.out.println(" - NONCE: " + bytesToHex(nonce_1));
            byte[] to_2 = RLP.encodeElement(to);
//            System.out.println(" - TO: " + bytesToHex(to_2));
            byte[] value_3 = RLP.encodeElement(value);
//            System.out.println(" - VALUE: " + bytesToHex(value_3));
            byte[] data_4 = RLP.encodeElement(data);
//            System.out.println(" - DATA: " + bytesToHex(data_4));
            byte[] timestamp_5 = RLP.encodeElement(timestamp);
//            System.out.println(" - TIMESTAMP: " + bytesToHex(timestamp_5));
            byte[] energy_6 = RLP.encodeLong(energy);
//            System.out.println(" - NRG: " + bytesToHex(energy_6));
            byte[] energyPrice_7 = RLP.encodeLong(energyPrice);
//            System.out.println(" - NRGP: " + bytesToHex(energyPrice_7));
            byte[] type_8 = RLP.encodeByte(type);
//            System.out.println(" - TYPE: " + bytesToHex(type_8));

            byte[] encodedData = RLP
                .encodeList(nonce_1, to_2, value_3, data_4, timestamp_5, energy_6, energyPrice_7,
                    type_8);

            byte[] rawHash = blake2b(encodedData);

            byte[] signatureOnly = sign(privateKey, rawHash);
            byte[] preEncodeSignature = new byte[publicKey.length + signatureOnly.length];
            System.arraycopy(publicKey, 0, preEncodeSignature, 0, publicKey.length);
            System.arraycopy(signatureOnly, 0, preEncodeSignature, publicKey.length,
                signatureOnly.length);
            byte[] signature_9 = RLP.encodeElement(preEncodeSignature);
            byte[] encodedWithPayload = RLP
                .encodeList(nonce_1, to_2, value_3, data_4, timestamp_5, energy_6, energyPrice_7,
                    type_8, signature_9);

//            System.out.println("DATA: " + bytesToHex(encodedData));
//            System.out.println("RAW: " + bytesToHex(rawHash));
//            System.out.println("----- " + bytesToHex(preEncodeSignature));
//            System.out.println("SIG: " + bytesToHex(signature_9));
//            System.out.println("ENCODED: " + bytesToHex(encodedWithPayload));

            ApiMsg apiMsg = api.getTx().sendRawTransaction(ByteArrayWrapper.wrap(encodedWithPayload));

            assertFalse(apiMsg.isError());

            MsgRsp msgRsp = apiMsg.getObject();
            assertNotNull(msgRsp);

            Hash256 hash = msgRsp.getTxHash();
            assertNotNull(hash);
            System.out.println(hash);
        } else {
            System.err.println("Usage: Calling ApiUrl privateKey toAddress value data type");
            System.exit(1);
        }
    }
}