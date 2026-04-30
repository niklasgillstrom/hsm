package eu.gillstrom.hsm.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.core.io.DefaultResourceLoader;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The mock registry loads (personalNumber, organisationNumber) pairs from a
 * JSON file; a listed pair must AUTHORISE, an unlisted pair must UNAUTHORISE.
 */
class MockAgreementRegistrySignatoryRightsVerifierTest {

    @Test
    void listedPairIsAuthorisedUnlistedIsUnauthorised(@TempDir Path tmp) throws Exception {
        Path registryFile = tmp.resolve("signatory-rights.json");
        String json = """
                {
                  "entries": [
                    {
                      "organisationNumber": "5566778899",
                      "organisationName": "Acme AB",
                      "authorisedPersonalNumbers": ["198001011234", "199002023456"]
                    }
                  ]
                }
                """;
        Files.writeString(registryFile, json);

        // Use Spring's DefaultResourceLoader so the "file:" URI resolves
        // against the real filesystem — no classpath resource required.
        MockAgreementRegistrySignatoryRightsVerifier verifier =
                new MockAgreementRegistrySignatoryRightsVerifier(
                        new DefaultResourceLoader(),
                        "file:" + registryFile.toAbsolutePath());
        verifier.load();

        SignatoryRightsVerifier.Result listed =
                verifier.check("198001011234", "5566778899", null);
        assertThat(listed.status())
                .isEqualTo(SignatoryRightsVerifier.Result.Status.AUTHORISED);
        assertThat(listed.isAuthorised()).isTrue();

        SignatoryRightsVerifier.Result unlistedPnr =
                verifier.check("197001019999", "5566778899", null);
        assertThat(unlistedPnr.status())
                .isEqualTo(SignatoryRightsVerifier.Result.Status.UNAUTHORISED);

        SignatoryRightsVerifier.Result unlistedOrg =
                verifier.check("198001011234", "0000000000", null);
        assertThat(unlistedOrg.status())
                .isEqualTo(SignatoryRightsVerifier.Result.Status.UNAUTHORISED);
    }

    @Test
    void missingFileYieldsUnauthorised(@TempDir Path tmp) {
        Path notThere = tmp.resolve("does-not-exist.json");
        MockAgreementRegistrySignatoryRightsVerifier verifier =
                new MockAgreementRegistrySignatoryRightsVerifier(
                        new DefaultResourceLoader(),
                        "file:" + notThere.toAbsolutePath());
        verifier.load();

        SignatoryRightsVerifier.Result r =
                verifier.check("198001011234", "5566778899", null);
        assertThat(r.status())
                .isEqualTo(SignatoryRightsVerifier.Result.Status.UNAUTHORISED);
    }
}
