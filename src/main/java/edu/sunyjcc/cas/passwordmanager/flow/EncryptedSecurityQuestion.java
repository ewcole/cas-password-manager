package edu.sunyjcc.cas.passwordmanager.flow;

import net.unicon.cas.passwordmanager.flow.*;

import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * <p>Bean for holding a user security question and answer.  It includes
 *    code to encrypt and decript security challenges.</p>
 */
public class EncryptedSecurityQuestion extends SecurityQuestion {

    private static final long serialVersionUID = 1L;
    
    /** No-argument constructor */
    public EncryptedSecurityQuestion() { }
    
    /** Constructor with encrypted question text and response */
    public EncryptedSecurityQuestion(String encryptedQuestionText, String encryptedResponseText) {
        this.setEncryptedQuestionText(encryptedQuestionText);
        this.setEncryptedResponseText(encryptedResponseText);
    }


    /** Return an encrypted form of the question text for storage */
    @Override
    public String getEncryptedQuestionText() {
        // The default version treats it as clear text.
        return this.getQuestionText();
    }

    /** Decrypt the encryptedQuestionText and set questionText to that value.
     *  @param encryptedQuestionText The value which, when decrypted, yeilds
     *                               the user's question text.
     */
    @Override
    public void setEncryptedQuestionText(String encryptedQuestionText) {
        // The default version treats it as clear text.
        this.setQuestionText(encryptedQuestionText);
    }

    /** Return an encrypted form of the response text for storage */
    @Override
    public String getEncryptedResponseText() {
        // The default version treats it as clear text.
        return this.getResponseText();
    }

    /** Decrypt the encryptedResponseText and set responseText to that value.
     *  @param encryptedResponseText The value which, when decrypted, yeilds
     *                               the user's response text.
     */
    @Override
    public void setEncryptedResponseText(String encryptedResponseText) {
        // The default version treats it as clear text.
        this.setResponseText(encryptedResponseText);
    }

}
