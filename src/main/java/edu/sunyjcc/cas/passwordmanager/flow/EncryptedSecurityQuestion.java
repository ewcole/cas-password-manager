package edu.sunyjcc.cas.passwordmanager.flow;

import net.unicon.cas.passwordmanager.flow.*;

import java.io.Serializable;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

import java.util.regex.*;
import org.apache.commons.codec.binary.Base64;
import java.io.UnsupportedEncodingException;
import org.apache.commons.codec.EncoderException;
/**
 * <p>Bean for holding a user security question and answer.  It includes
 *    code to encrypt and decript security challenges.</p>
 */
public class EncryptedSecurityQuestion extends SecurityQuestion {

    private static final long serialVersionUID = 1L;

    /** Apache Commons base 64 encoder with no line breaks.*/
    public static final Base64 base64 = new Base64(0);
    public static final String encryptedStringRe = "^\\{(.*?)\\}(.*)$";
    private static final Pattern encryptedStringPattern = 
        Pattern.compile(encryptedStringRe);

    private String encrypt(String text) {
        return "{}" + base64.encodeBase64String(text.getBytes());
    }

    private String  decrypt(String text) {
        Matcher matcher = encryptedStringPattern.matcher(text);
        if (matcher.find()){
            String algorithm = matcher.group(1);
            String encText = matcher.group(2);
            try {
                byte[] bytes = base64.decodeBase64(encText);
                return new String(bytes, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                return encText;
            }
        } else {
            return text;
        }
    }

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
        return encrypt(this.getQuestionText());
    }

    /** Decrypt the encryptedQuestionText and set questionText to that value.
     *  @param encryptedQuestionText The value which, when decrypted, yeilds
     *                               the user's question text.
     */
    @Override
    public void setEncryptedQuestionText(String encryptedQuestionText) {
        // The default version treats it as clear text.
        String clearText = decrypt(encryptedQuestionText);
        this.setQuestionText(clearText);
    }

    /** Return an encrypted form of the response text for storage */
    @Override
    public String getEncryptedResponseText() {
        // The default version treats it as clear text.
        return encrypt(this.getResponseText());
    }

    /** Decrypt the encryptedResponseText and set responseText to that value.
     *  @param encryptedResponseText The value which, when decrypted, yeilds
     *                               the user's response text.
     */
    @Override
    public void setEncryptedResponseText(String encryptedResponseText) {
        String clearText = decrypt(encryptedResponseText);
        this.setResponseText(clearText);
    }

}
