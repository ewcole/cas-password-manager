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
    
    public EncryptedSecurityQuestion() { }
    
    public EncryptedSecurityQuestion(String encryptedQuestionText, String encryptedResponseText) {
        this.setEncryptedQuestionText(encryptedQuestionText);
        this.setEncryptedResponseText(encryptedResponseText);
    }

}
