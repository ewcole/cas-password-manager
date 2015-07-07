package edu.sunyjcc.cas.passwordmanager.flow;

import net.unicon.cas.passwordmanager.flow.SecurityQuestion;

/** A factory class that produces new security questions.  This moves 
 *  encryption setup outside of the LDAP Server implementation.
 *  @Author Ed Cole
 */
public class SecurityQuestionFactory {

    /** Create a new SecurityQuestion with no values  */
    public SecurityQuestion newSecurityQuestion() {
        return new EncryptedSecurityQuestion();
    }

    public SecurityQuestion createFromPlainText(String questionText, 
                                                String responseText) {
        EncryptedSecurityQuestion q = new EncryptedSecurityQuestion();
        q.setQuestionText(questionText);
        q.setResponseText(responseText);
        return q;
    }

    public SecurityQuestionFactory() {
    }
}
