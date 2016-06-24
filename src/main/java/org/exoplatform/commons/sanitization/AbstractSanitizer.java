package org.exoplatform.commons.sanitization;

import org.owasp.validator.html.*;
import org.exoplatform.services.log.ExoLogger;
import org.exoplatform.services.log.Log;


/**
 * Created by kmenzli on 02/02/16.
 */
public abstract class AbstractSanitizer {
    private static final Log LOG = ExoLogger.getLogger(AbstractSanitizer.class);
    private static final String RULES = "social-rules-1.0.0-SNAPSHOT";

    private static Policy policy;
    private static AntiSamy antiSamy;

    protected static AntiSamy getAntiSamy() throws PolicyException  {
        if (antiSamy == null) {
            policy = getPolicy(RULES);
            antiSamy = new AntiSamy();
        }
        return antiSamy;

    }

    protected static String sanitize(String input) {
        CleanResults cr;
        try {
            cr = getAntiSamy().scan(input, policy);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        return cr.getCleanHTML();
    }

    private static Policy getPolicy(String name) throws PolicyException {
        Policy policy = Policy.getInstance(Policy.class.getResourceAsStream("/META-INF/antisamy/" + name + ".xml"));
        return policy;
    }
    private static void squatch (String branche) throws Exception {
        System.out.println("The branch name to squatch is "+branche);
    }
}
