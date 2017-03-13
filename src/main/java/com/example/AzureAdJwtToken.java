package com.example;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;

/**
 * 
 * @author Yu-Hua Chang
 * 
 */
public class AzureAdJwtToken {

    private static final Logger log = LoggerFactory.getLogger(AzureAdJwtToken.class);

    protected final String token;

    // Header
    protected final String x5t;
    protected final String kid;

    // Payload
    protected final String issuer;
    protected final String ipAddr;
    protected final String name;
    protected final String uniqueName;
    
    public AzureAdJwtToken(String token) {
        this.token = token;

        String[] parts = token.split("\\.");
        
        // Header
        String headerStr = new String(Base64.getUrlDecoder().decode((parts[0])));
        if (log.isDebugEnabled()) {
            log.debug("JWT Header: {}", headerStr);
        }

        JSONObject header = new JSONObject(headerStr);
        x5t = header.getString("x5t");
        kid = header.getString("kid");
        if (log.isDebugEnabled()) {
            log.debug("JWT Header x5t: {}", x5t);
            log.debug("JWT Header kid: {}", kid);
        }
        
        // Payload
        // reserved, public, and private claims.
        String payloadStr = new String(Base64.getUrlDecoder().decode((parts[1])));
        if (log.isDebugEnabled()) {
            log.debug("JWT Payload: {}", payloadStr);
        }

        JSONObject payload = new JSONObject(payloadStr);
        issuer = payload.getString("iss");
        ipAddr = payload.getString("ipaddr");
        name = payload.getString("name");
        uniqueName = payload.getString("unique_name");
        if (log.isDebugEnabled()) {
            log.debug("JWT Payload issuer: {}", issuer);
            log.debug("JWT Payload ipAddr: {}", ipAddr);
            log.debug("JWT Payload name: {}", name);
            log.debug("JWT Payload uniqueName: {}", uniqueName);
        }
    }
    
    /**
     *     1. go to here: https://login.microsoftonline.com/common/.well-known/openid-configuration
     *     2. check the value of "jwks_uri", which is "https://login.microsoftonline.com/common/discovery/keys"
     *     3. go to https://login.microsoftonline.com/common/discovery/keys
     *     4. get "kid" value from header, which is "Y4ueK2oaINQiQb5YEBSYVyDcpAU"
     *     5. search Y4ueK2oaINQiQb5YEBSYVyDcpAU in key file to get the key.
     *     
     *     (We can manually decode JWT token at https://jwt.io/ by copy'n'paste)
     *     to select the public key used to sign this token.
     *     (There are about three keys which are rotated about everyday.)
     *     
     * @throws IOException
     * @throws CertificateException 
     */
    protected PublicKey loadPublicKey() throws IOException, CertificateException {

        // Key Info (RSA PublicKey)
        String openidConfigStr = readUrl("https://login.microsoftonline.com/common/.well-known/openid-configuration");
        if (log.isDebugEnabled()) {
            log.debug("AAD OpenID Config: {}", openidConfigStr);
        }

        JSONObject openidConfig = new JSONObject(openidConfigStr);
        String jwksUri = openidConfig.getString("jwks_uri");
        if (log.isDebugEnabled()) {
            log.debug("AAD OpenID Config jwksUri: {}", jwksUri);
        }

        String jwkConfigStr = readUrl(jwksUri);
        if (log.isDebugEnabled()) {
            log.debug("AAD OpenID JWK Config: {}", jwkConfigStr);
        }

        JSONObject jwkConfig = new JSONObject(jwkConfigStr);
        JSONArray keys = jwkConfig.getJSONArray("keys");
        for (int i = 0; i < keys.length(); i++) {
            JSONObject key = keys.getJSONObject(i);

            String kid = key.getString("kid");
            if (!this.kid.equals(kid)) {
                continue;
            }

            String x5c = key.getJSONArray("x5c").getString(0);
            String keyStr = "-----BEGIN CERTIFICATE-----\r\n";
            String tmp = x5c;
            while (tmp.length() > 0) {
                if (tmp.length() > 64) {
                    String x = tmp.substring(0, 64);
                    keyStr += x + "\r\n";
                    tmp = tmp.substring(64);
                } else {
                    keyStr += tmp + "\r\n";
                    tmp = "";
                }
            }
            keyStr += "-----END CERTIFICATE-----\r\n";
            if (log.isDebugEnabled()) {
                log.debug("AAD OpenID Key:\n{}", keyStr);
            }

            /*
             * go to https://jwt.io/ and copy'n'paste the jwt token to the left side, it will be decoded on the right side,
             * copy'n'past the public key (from ----BEGIN... to END CERT...) to the verify signature, it will show signature verified.
             */

            // read certification
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            InputStream stream = new ByteArrayInputStream(keyStr.getBytes(StandardCharsets.US_ASCII));
            X509Certificate cer = (X509Certificate) fact.generateCertificate(stream);
            if (log.isTraceEnabled()) {
                log.trace("AAD OpenID X509Certificate: {}", cer);
            }
            
            // get public key from certification
            PublicKey publicKey = cer.getPublicKey();
            if (log.isDebugEnabled()) {
                log.debug("AAD OpenID X509Certificate publicKey: {}", publicKey);
            }

            return publicKey;
        }
        return null;
    }
    
    //TODO: cache content to file to prevent access internet everytime.
    protected String readUrl(String url) throws IOException {
        URL addr = new URL(url);
        StringBuilder sb = new StringBuilder();
        try (BufferedReader in = new BufferedReader(new InputStreamReader(addr.openStream()))) {
            String inputLine = null;
            while ((inputLine = in.readLine()) != null) {
                sb.append(inputLine);
            }
        }
        return sb.toString();
    }
    
    public void verify() throws IOException, CertificateException {
        PublicKey publicKey = loadPublicKey();
        try {
            JWTVerifier verifier = JWT.require(Algorithm.RSA256((RSAKey) publicKey)).withIssuer(issuer).build();
            DecodedJWT jwt = verifier.verify(token);
            if (log.isDebugEnabled()) {
                log.debug("AAD jwt issuer: {}", jwt.getIssuer());
                log.debug("AAD jwt issued at: {}", jwt.getIssuedAt());
                log.debug("AAD jwt expires at: {}", jwt.getExpiresAt());
            }
        } catch (JWTVerificationException exception) {
            throw new RuntimeException("JWT Token verification failed!");
        }
    }

    public String getIpAddr() {
        return ipAddr;
    }

    public String getName() {
        return name;
    }

    public String getUniqueName() {
        return uniqueName;
    }

    @Override
    public String toString() {
        return "AzureAdJwtToken [issuer=" + issuer + ", ipAddr=" + ipAddr + ", name=" + name + ", uniqueName=" + uniqueName + "]";
    }
}
