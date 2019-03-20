package fr.paris.lutece.util.jwt.service;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.junit.Assert;
import org.junit.Test;



/*
 * Copyright (c) 2002-2018, Mairie de Paris
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice
 *     and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice
 *     and the following disclaimer in the documentation and/or other materials
 *     provided with the distribution.
 *
 *  3. Neither the name of 'Mairie de Paris' nor 'Lutece' nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * License 1.0
 */

public class JWTUtilTest 
{
    private static final String HEADER = "{\n" +
    "  \"typ\": \"JWT\",\n" +
    "  \"alg\": \"RS256\",\n" +
    "  \"x5t\": \"NmJmOGUxMzZlYjM2ZDRhNTZlYTA1YzdhZTRiOWE0NWI2M2JmOTc1ZA==\"\n" +
    "}";
    private static final String PAYLOAD = "{\n" +
    "  \"iss\": \"wso2.org/products/am\",\n" +
    "  \"exp\": 1552984468352,\n" +
    "  \"http://wso2.org/claims/subscriber\": \"admin\",\n" +
    "  \"http://wso2.org/claims/applicationid\": \"2\",\n" +
    "  \"http://wso2.org/claims/applicationname\": \"MyDashboard\",\n" +
    "  \"http://wso2.org/claims/applicationtier\": \"Unlimited\",\n" +
    "  \"http://wso2.org/claims/apicontext\": \"/identity/v2\",\n" +
    "  \"http://wso2.org/claims/version\": \"v2\",\n" +
    "  \"http://wso2.org/claims/tier\": \"Unlimited\",\n" +
    "  \"http://wso2.org/claims/keytype\": \"SANDBOX\",\n" +
    "  \"http://wso2.org/claims/usertype\": \"APPLICATION\",\n" +
    "  \"http://wso2.org/claims/enduser\": \"admin@carbon.super\",\n" +
    "  \"http://wso2.org/claims/enduserTenantId\": \"-1234\"\n" +
    "}";
    private static final String PUB_KEY = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCUp/oV1vWc8/TkQSiAvTousMzOM4asB2iltr2QKozni5aVFu818MpOLZIr8LMnTzWllJvvaA5RAAdpbECb+48FjbBe0hseUdN5HpwvnH/DW8ZccGvk53I6Orq7hLCv1ZHtuOCokghz/ATrhyPq+QktMfXnRS4HrKGJTzxaCcU7OQIDAQAB";
    private static final String PRIV_KEY = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAJSn+hXW9Zzz9ORBKIC9Oi6wzM4zhqwHaKW2vZAqjOeLlpUW7zXwyk4tkivwsydPNaWUm+9oDlEAB2lsQJv7jwWNsF7SGx5R03kenC+cf8Nbxlxwa+Tncjo6uruEsK/Vke244KiSCHP8BOuHI+r5CS0x9edFLgesoYlPPFoJxTs5AgMBAAECgYBL/6iiO7hr2mjrvMgZMSSqtCawkLUcA9mjRs6ZArfwtHNymzwGZqj22ONu5WqiASPbGCO0fI09KfegFQDe/fe6wnpirBWtawLoXCZmGrwC+x/3iqbiGJMd7UB3FaZkZOzV5Jhzomc8inSJWMcR+ywiUY37stfVDqR1sJ/jzZ1OdQJBAO8vCa2OVQBJbzjMvk8Sc0KiuVwnyqMYqVty6vYuufe9ILJfhwhYzE82wIa9LYg7UK2bPvKyyehuFfqI5oU5lU8CQQCfG5LA3gp3D1mS7xxztqJ+cm4SPO4R6YzVybAZKqKUvTFSKNV57Kp/LL7WjtUUNr+dY+aYRlKo81Hq61y8tBT3AkAjJyak+2ZCxIg0MONHe8603HWhtbdygQ1jA2DFDdkHMCS+EowmDeb5PXLOWr92ZkFVQpvdz6kdIBDa4YP/0JbBAkBVHLjqd1z9x7ZRBZwgwkg2gBwloXZxGpB+JMARFl+WVYa2vqVD7bhfA56qxAl0IL1sAm7ucl/xhQgDNRiM0YCNAkEAqySTBx2HO9VyzuWWbf7BYTNsxfO80GaRkZGENfqO1QgnhT1FMeK+ox7Kbi+nSaCBoPjNzyrMbU08M6nSnkDEGA==";
    private static final String SHA256_WITH_RSA = "SHA256withRSA";
    
    /**
     * Check a JWT building step by step and verify the RSA-built signature with JJWT lib
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     * @throws SignatureException 
     */
    @Test
    public void checkRSA256SignatureTest( ) throws InvalidKeyException, InvalidKeySpecException, NoSuchAlgorithmException, UnsupportedEncodingException, SignatureException
    {
        //Build a JWT encoded with a RSA private key
        KeyFactory kf = KeyFactory.getInstance("RSA");

        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(PRIV_KEY));
        PrivateKey privKey = kf.generatePrivate(keySpecPKCS8);

        X509EncodedKeySpec keySpecX509 = new X509EncodedKeySpec(Base64.getDecoder().decode(PUB_KEY));
        RSAPublicKey pubKey = (RSAPublicKey) kf.generatePublic(keySpecX509);
        
        String strBase64UrlEncodeHeader = Base64.getUrlEncoder( ).encodeToString( HEADER.getBytes( "UTF-8" ) );
        String strBase64UrlEncodePayload= Base64.getUrlEncoder( ).encodeToString( PAYLOAD.getBytes( "UTF-8" ) );
        String strAssertion = strBase64UrlEncodeHeader + "." + strBase64UrlEncodePayload;

        
        Signature signature = Signature.getInstance( SHA256_WITH_RSA );
        signature.initSign( privKey);
        
        byte[] dataInBytes = strAssertion.getBytes( "UTF-8");
        signature.update( dataInBytes );
        byte[] signatureBytes = signature.sign( );
        
        String strBase64UrlEncodeSignature = Base64.getUrlEncoder( ).encodeToString( signatureBytes );
        
        String computedJWT = strAssertion+"."+strBase64UrlEncodeSignature;
        
        //Verify the JWT with the RSA corresponding private Key
        Assert.assertTrue(  JWTUtil.checkSignature( computedJWT, pubKey ) );
    }
}
