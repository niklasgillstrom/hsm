package eu.gillstrom.hsm.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * Demonstration {@link SignatoryRightsVerifier} that loads authorised
 * (personalNumber, organisationNumber) pairs from a JSON configuration file
 * and treats the union as authoritative. Active when
 * {@code swish.signatory-rights.mode=mock-registry}.
 *
 * <p>Expected JSON shape (one of):</p>
 *
 * <pre>
 * {
 *   "entries": [
 *     {
 *       "organisationNumber": "5566778899",
 *       "authorisedPersonalNumbers": ["198001011234", "199002023456"],
 *       "organisationName": "Acme AB"
 *     }
 *   ]
 * }
 * </pre>
 *
 * <p>The file path is read from {@code swish.signatory-rights.mock-registry.path}
 * (Spring resource notation: {@code classpath:} or {@code file:}). Default is
 * {@code classpath:signatory-rights.json}.</p>
 *
 * <p>This is a demonstration of the integration shape only — it is NOT a
 * substitute for Bolagsverket / Swish agreement-registry integration. The
 * JSON file is not authoritative, is not audit-logged, and is trivially
 * modifiable. The WARN log at startup surfaces this.</p>
 */
@Component
@ConditionalOnProperty(name = "swish.signatory-rights.mode", havingValue = "mock-registry")
public class MockAgreementRegistrySignatoryRightsVerifier implements SignatoryRightsVerifier {

    private static final Logger log =
            LoggerFactory.getLogger(MockAgreementRegistrySignatoryRightsVerifier.class);

    private final ResourceLoader resourceLoader;
    private final String registryPath;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // organisationNumber → set of authorised personalNumbers
    private Map<String, Set<String>> registry = Collections.emptyMap();

    public MockAgreementRegistrySignatoryRightsVerifier(
            ResourceLoader resourceLoader,
            @Value("${swish.signatory-rights.mock-registry.path:classpath:signatory-rights.json}") String path) {
        this.resourceLoader = resourceLoader;
        this.registryPath = path;
    }

    @PostConstruct
    public void load() {
        try {
            Resource resource = resourceLoader.getResource(registryPath);
            if (!resource.exists()) {
                log.warn("MockAgreementRegistrySignatoryRightsVerifier: registry file '{}' does not exist. "
                        + "All queries will return UNAUTHORISED.", registryPath);
                registry = Collections.emptyMap();
                return;
            }
            try (InputStream in = resource.getInputStream()) {
                JsonNode root = objectMapper.readTree(in);
                JsonNode entries = root.get("entries");
                if (entries == null || !entries.isArray()) {
                    log.warn("MockAgreementRegistrySignatoryRightsVerifier: registry file '{}' has no "
                            + "'entries' array. All queries will return UNAUTHORISED.", registryPath);
                    registry = Collections.emptyMap();
                    return;
                }
                Map<String, Set<String>> parsed = new HashMap<>();
                for (JsonNode entry : entries) {
                    String orgNr = text(entry.get("organisationNumber"));
                    if (orgNr == null) continue;
                    Set<String> pnrs = new HashSet<>();
                    JsonNode arr = entry.get("authorisedPersonalNumbers");
                    if (arr != null && arr.isArray()) {
                        Iterator<JsonNode> it = arr.elements();
                        while (it.hasNext()) {
                            String pnr = text(it.next());
                            if (pnr != null) pnrs.add(pnr);
                        }
                    }
                    parsed.put(orgNr, pnrs);
                }
                registry = parsed;
                log.warn("MockAgreementRegistrySignatoryRightsVerifier loaded {} organisation(s) from '{}'. "
                        + "This is a DEMONSTRATION registry — not a substitute for Bolagsverket or the "
                        + "Swish agreement registry, and MUST NOT be treated as authoritative in production.",
                        registry.size(), registryPath);
            }
        } catch (Exception e) {
            log.error("Failed to load mock signatory-rights registry from '{}'. "
                    + "Falling back to empty registry (all queries UNAUTHORISED).", registryPath, e);
            registry = Collections.emptyMap();
        }
    }

    @Override
    public Result check(String personalNumber, String organisationNumber, String swishNumber) {
        if (personalNumber == null || organisationNumber == null) {
            return Result.unauthorised("Missing personalNumber or organisationNumber");
        }
        Set<String> authorised = registry.get(organisationNumber);
        if (authorised == null) {
            return Result.unauthorised(
                    "organisationNumber=" + organisationNumber + " not present in mock registry");
        }
        if (!authorised.contains(personalNumber)) {
            return Result.unauthorised(
                    "personalNumber not listed as authorised signatory for organisationNumber="
                            + organisationNumber);
        }
        return Result.authorised("mock-registry:" + registryPath);
    }

    private static String text(JsonNode node) {
        return node == null || node.isNull() ? null : node.asText();
    }
}
