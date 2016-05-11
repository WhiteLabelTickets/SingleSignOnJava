import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class SingleSignOnBuilder {

    private String firstname;
    private String lastname;
    private String email;

    public String getFirstname() {
        return firstname;
    }
    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }
    public String getLastname() {
        return lastname;
    }
    public void setLastname(String lastname) {
        this.lastname = lastname;
    }
    public String getEmail() {
        return email;
    }
    public void setEmail(String email) {
        this.email = email;
    }

    public String getToken(byte[] secret) throws UnsupportedEncodingException {
        final String message = Base64.encodeBase64URLSafeString(buildJson().getBytes());
        return message + "." + Base64.encodeBase64URLSafeString(signature(message, secret));
    }

    public String buildJson() {
        StringBuilder sb = new StringBuilder();
        if (firstname != null && !firstname.equals("")) {
            sb.append("\"fn\":\"" + firstname + "\"");
        }
        if (lastname != null && !lastname.equals("")) {
            if (sb.length() != 0) {
                sb.append(",");
            }
            sb.append("\"ln\":\"" + lastname + "\"");
        }
        if (email != null && !email.equals("")) {
            if (sb.length() != 0) {
                sb.append(",");
            }
            sb.append("\"em\":\"" + email + "\"");
        }

        return "{" + sb.toString() + "}";
    }

    private byte[] signature(String message, byte[] secret) throws IllegalStateException, UnsupportedEncodingException {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(secret, "HS256"));
            byte[] sig = hmac.doFinal(message.getBytes());
            return sig;
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}
