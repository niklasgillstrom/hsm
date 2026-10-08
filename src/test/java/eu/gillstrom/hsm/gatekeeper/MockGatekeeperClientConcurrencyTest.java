package eu.gillstrom.hsm.gatekeeper;

import eu.gillstrom.hsm.testsupport.TestPki;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The mock mirrors gatekeeper's Step-7 rule that a confirmation nonce is spent
 * by the confirm that uses it, also when confirms race.
 */
class MockGatekeeperClientConcurrencyTest {

    private static MockGatekeeperClient mock() throws Exception {
        MockGatekeeperClient mock = new MockGatekeeperClient(new GatekeeperKeyRegistry(""));
        mock.init();
        return mock;
    }

    private static VerifyRequest request() throws Exception {
        KeyPair kp = TestPki.newRsaKeyPair(2048);
        return VerifyRequest.builder()
                .publicKey("-----BEGIN PUBLIC KEY-----\n"
                        + Base64.getMimeEncoder().encodeToString(kp.getPublic().getEncoded())
                        + "\n-----END PUBLIC KEY-----")
                .hsmVendor("YUBICO").countryCode("SE").build();
    }

    private static IssuanceConfirmRequest notIssued(VerifyResponse receipt) {
        return IssuanceConfirmRequest.builder()
                .verificationId(receipt.getVerificationId())
                .confirmationNonce(receipt.getConfirmationNonce())
                .issued(false)
                .build();
    }

    @Test
    void aNonceIsSpentByItsConfirm() throws Exception {
        MockGatekeeperClient mock = mock();
        VerifyResponse receipt = mock.verify(request());

        assertThat(mock.confirm(notIssued(receipt)).isLoopClosed()).isTrue();
        assertThatThrownBy(() -> mock.confirm(notIssued(receipt)))
                .isInstanceOf(GatekeeperException.class)
                .hasMessageContaining("does not match");
    }

    @Test
    void racingConfirmsWithOneNonceSucceedOnce() throws Exception {
        MockGatekeeperClient mock = mock();
        ExecutorService pool = Executors.newFixedThreadPool(16);
        try {
            for (int round = 0; round < 20; round++) {
                VerifyResponse receipt = mock.verify(request());
                List<Callable<Boolean>> confirms = new ArrayList<>();
                for (int i = 0; i < 16; i++) {
                    confirms.add(() -> {
                        try {
                            return mock.confirm(notIssued(receipt)).isLoopClosed();
                        } catch (GatekeeperException e) {
                            return false;
                        }
                    });
                }
                int closed = 0;
                for (Future<Boolean> f : pool.invokeAll(confirms)) {
                    closed += f.get() ? 1 : 0;
                }
                assertThat(closed).as("round %d", round).isEqualTo(1);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void concurrentVerifiesAreAllConfirmable() throws Exception {
        MockGatekeeperClient mock = mock();
        ExecutorService pool = Executors.newFixedThreadPool(16);
        try {
            List<Callable<VerifyResponse>> verifies = new ArrayList<>();
            VerifyRequest request = request();
            for (int i = 0; i < 400; i++) {
                verifies.add(() -> mock.verify(request));
            }
            List<VerifyResponse> receipts = new ArrayList<>();
            for (Future<VerifyResponse> f : pool.invokeAll(verifies)) {
                receipts.add(f.get());
            }
            for (VerifyResponse r : receipts) {
                assertThat(mock.confirm(notIssued(r)).isLoopClosed()).isTrue();
            }
        } finally {
            pool.shutdownNow();
        }
    }
}
