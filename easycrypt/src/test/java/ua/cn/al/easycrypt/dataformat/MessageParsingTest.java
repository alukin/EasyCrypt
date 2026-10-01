package ua.cn.al.easycrypt.dataformat;

import java.nio.ByteBuffer;
import org.junit.jupiter.api.Test;
import ua.cn.al.easycrypt.CryptoConfig;
import ua.cn.al.easycrypt.CryptoNotValidException;
import ua.cn.al.easycrypt.CryptoParams;
import static org.junit.jupiter.api.Assertions.assertThrows;

class MessageParsingTest {
    private final CryptoParams params = CryptoConfig.createDefaultParams();

    @Test
    void rejectsTruncatedAeadHeaders() {
        assertThrows(CryptoNotValidException.class,
                () -> AEADCiphered.fromBytes(new byte[params.getAesIvLen() + 7], params));
    }

    @Test
    void rejectsNegativeAndOversizedAeadLengths() {
        byte[] negative = ByteBuffer.allocate(params.getAesIvLen() + 8).put(new byte[params.getAesIvLen()])
                .putInt(-1).putInt(16).array();
        assertThrows(CryptoNotValidException.class, () -> AEADCiphered.fromBytes(negative, params));

        byte[] oversized = ByteBuffer.allocate(params.getAesIvLen() + 8).put(new byte[params.getAesIvLen()])
                .putInt(AEADCiphered.MAX_MSG_SIZE).putInt(16).array();
        assertThrows(CryptoNotValidException.class, () -> AEADCiphered.fromBytes(oversized, params));
    }

    @Test
    void rejectsMismatchedLengthsAndShortAuthenticationTags() {
        byte[] mismatch = ByteBuffer.allocate(params.getAesIvLen() + 8 + 16)
                .put(new byte[params.getAesIvLen()]).putInt(0).putInt(17).put(new byte[16]).array();
        assertThrows(CryptoNotValidException.class, () -> AEADCiphered.fromBytes(mismatch, params));

        byte[] tagShort = ByteBuffer.allocate(params.getAesIvLen() + 8 + 15)
                .put(new byte[params.getAesIvLen()]).putInt(0).putInt(15).put(new byte[15]).array();
        assertThrows(CryptoNotValidException.class, () -> AEADCiphered.fromBytes(tagShort, params));
    }

    @Test
    void rejectsTruncatedLegacyGcmMessages() {
        assertThrows(CryptoNotValidException.class, () -> Ciphered.fromBytes(new byte[27]));
    }
}
