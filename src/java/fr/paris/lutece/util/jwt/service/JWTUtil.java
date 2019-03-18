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
package fr.paris.lutece.util.jwt.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.impl.TextCodec;
import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.Enumeration;
import java.util.Map;
import java.util.Map.Entry;
import javax.servlet.http.HttpServletRequest;
import org.apache.log4j.Logger;
import org.apache.log4j.Priority;

/**
 * Utils class for JWT
 */
public class JWTUtil
{
    protected static final Logger LOGGER = Logger.getLogger( "lutece.security.jwt" );

    /**
     * Check if provided request contains a JWT
     * 
     * @param request
     * @param strHeaderName
     * @return true if the request contains a JWT, false othewise
     */
    public static boolean containsValidUnsafeJWT( HttpServletRequest request, String strHeaderName )
    {
        String strBase64JWT = request.getHeader( strHeaderName );

        // If no specific Header is provided, use spec JWT : try to fetch in Authorization: Bearer HTTP Header
        if ( strBase64JWT == null )
        {
            strBase64JWT = getAuthozirationBearerValue( request );
        }

        if ( strBase64JWT != null )
        {
            strBase64JWT = removeSignature( strBase64JWT );
            try
            {
                Jwts.parser( ).parseClaimsJwt( strBase64JWT );
                return true;
            }
            catch( JwtException e )
            {
                LOGGER.log( Priority.ERROR, "Provided request doesn't contains any JWT in HTTP headers ", e );
            }
        }
        return false;
    }

    /**
     * Checks claims key/value inside the JWT payload
     * 
     * @param request
     * @param strHeaderName
     * @param claimsToCheck
     * @return true if the key/values are present, false otherwise
     */
    public static boolean checkPayloadValues( HttpServletRequest request, String strHeaderName, Map<String, String> claimsToCheck )
    {
        String strBase64JWT = request.getHeader( strHeaderName );

        // If no specific Header is provided, use spec JWT : try to fetch in Authorization: Bearer HTTP Header
        if ( strBase64JWT == null )
        {
            strBase64JWT = getAuthozirationBearerValue( request );
        }

        if ( strBase64JWT != null )
        {
            strBase64JWT = removeSignature( strBase64JWT );
            try
            {
                Claims claims = Jwts.parser( ).parseClaimsJwt( strBase64JWT ).getBody( );

                for ( Entry<String, String> entry : claimsToCheck.entrySet( ) )
                {
                    if ( !claims.get( entry.getKey( ), String.class ).equals( entry.getValue( ) ) )
                    {
                        return false;
                    }
                }
            }
            catch( Exception e )
            {
                LOGGER.log( Priority.ERROR, "Unable to check JWT payload for checking claims", e );
                return false;
            }
        }
        return true;
    }
    
    /**
     * Get a payload value with given claimName;
     * 
     * @param request
     * @param strHeaderName
     * @param strClaimName
     * @return true if the key/values are present, false otherwise
     */
    public static String getPayloadValue( HttpServletRequest request, String strHeaderName, String strClaimName )
    {
        String strBase64JWT = request.getHeader( strHeaderName );

        // If no specific Header is provided, use spec JWT : try to fetch in Authorization: Bearer HTTP Header
        if ( strBase64JWT == null )
        {
            strBase64JWT = getAuthozirationBearerValue( request );
        }

        getPayloadValue( strBase64JWT, strClaimName );
        return null;
    }
    
    /**
     * Get a payload value with given claimName;
     * 
     * @param strBase64JWT
     * @param strClaimName
     * @return true if the key/values are present, false otherwise
     */
    public static String getPayloadValue( String strBase64JWT, String strClaimName )
    {
        if ( strBase64JWT != null && !strBase64JWT.isEmpty( ) )
        {
            strBase64JWT = removeSignature( strBase64JWT );
            try
            {
                Claims claims = Jwts.parser( ).parseClaimsJwt( strBase64JWT ).getBody( );

                return (String) claims.get( strClaimName );
            }
            catch( Exception e )
            {
                LOGGER.log( Priority.ERROR, "Unable to get JWT Payload value", e );
            }
        }
        return null;
    }

    /**
     * Check the JWT signature with provided java security Key: this can be a RSA Public Key
     * 
     * @param request
     *            The request
     * @param strHeaderName
     *            The header name
     * @param key
     *            The key
     * @return true if the signature of the JWT is checked; false otherwise
     */
    public static boolean checkSignature( HttpServletRequest request, String strHeaderName, Key key )
    {
        String strBase64JWT = request.getHeader( strHeaderName );

        // If no specific Header is provided, use spec JWT : try to fetch in Authorization: Bearer HTTP Header
        if ( strBase64JWT == null )
        {
            strBase64JWT = getAuthozirationBearerValue( request );
        }

        return checkSignature( strBase64JWT, key );
    }

    /**
     * Check the signature of the JWT with a secret key
     * 
     * @param request
     * @param strHeaderName
     * @param strSecreyKey
     * @return true if the signature is checked, false otherwise
     */
    public static boolean checkSignature( HttpServletRequest request, String strHeaderName, String strSecreyKey )
    {
        String strBase64JWT = request.getHeader( strHeaderName );

        // If no specific Header is provided, use spec JWT : try to fetch in Authorization: Bearer HTTP Header
        if ( strBase64JWT == null )
        {
            strBase64JWT = getAuthozirationBearerValue( request );
        }

        return checkSignature( strBase64JWT, strSecreyKey );
    }
    
    /**
     * Check the signature of the JWT with a secret key
     * 
     * @param mapClaims
     *              The map of claims
     * @param expirationDate
     *              The expiration date
     * @param strAlgoName
     * @param strSecreyKey
     * @return true if the signature is checked, false otherwise
     */
    public static String buildBase64JWT( Map<String,String> mapClaims, Date expirationDate, String strAlgoName, String strSecreyKey )
    {
            JwtBuilder builder = Jwts.builder();
            
            builder.setIssuedAt( Date.from(Instant.now( ) ) );
            
            //Set claims
            for ( Entry<String,String> entry : mapClaims.entrySet( ) )
            {
                builder.claim( entry.getKey( ), entry.getValue( ) );
            }
            
            if ( expirationDate != null )
            {
                builder.setExpiration( expirationDate );
            }
            
            
            if ( strSecreyKey != null )
            {
                SignatureAlgorithm signatureAlgo = SignatureAlgorithm.HS256;
                if ( strAlgoName != null && !strAlgoName.isEmpty( ) )
                {
                    SignatureAlgorithm signatureAlgoFromName = signatureAlgo.valueOf( strAlgoName );
                    if ( signatureAlgoFromName != null )
                    {
                        signatureAlgo = signatureAlgoFromName;
                    }
                }
                
                builder.signWith( signatureAlgo, TextCodec.BASE64.encode( strSecreyKey ) );
            }
                
            return builder.compact();
    }

    /*
     * PRIVATE METHODS
     */
    /**
     * Get the Authorization Bearer value : "Authorization: Bearer XXXXXX" => exract XXXXX
     * 
     * @param request
     *            The request
     * @return the Authorization Bearer value in the request
     */
    private static String getAuthozirationBearerValue( HttpServletRequest request )
    {
        Enumeration<String> headers = request.getHeaders( "Authorization" );
        while ( headers.hasMoreElements( ) )
        {
            String value = headers.nextElement( );
            if ( value.toLowerCase( ).startsWith( "bearer" ) )
            {
                return value.substring( "bearer".length( ) ).trim( );
            }
        }
        return null;
    }

    /**
     * Check a JWT signature with a Java security Key
     * 
     * @param strBase64JWT
     * @param key
     * @return true if the JWT is checked, false otherwise
     */
    private static boolean checkSignature( String strBase64JWT, Key key )
    {
        try
        {
            Jwts.parser( ).setSigningKey( key ).parseClaimsJws( strBase64JWT );
        }

        catch( JwtException e )
        {
            return false;
        }
        return true;
    }

    /**
     * Check a JWT signature with a Secrey Key
     * 
     * @param strBase64JWT
     * @param strSecretKey
     * @return true if the signature is checked, false otherwise
     */
    private static boolean checkSignature( String strBase64JWT, String strSecretKey )
    {
        try
        {
            Jwts.parser( ).setSigningKey( TextCodec.BASE64.encode( strSecretKey ) )
                    .parseClaimsJws( strBase64JWT );
        }

        catch( JwtException e )
        {
            return false;
        }
        return true;
    }

    /**
     * Remove a signature from a base64 JWT string
     * 
     * @param strBase64JWT
     * @return the JWT without signature
     */
    private static String removeSignature( String strBase64JWT )
    {
        int i = strBase64JWT.lastIndexOf( "." );
        return strBase64JWT.substring( 0, i + 1 );
    }
}
