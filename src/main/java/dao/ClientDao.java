package dao;

import java.security.Key;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.util.Base64;

import javax.crypto.spec.SecretKeySpec;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class ClientDao 
{
	//Validate the token with respect to signature,Algorithm used,claims value
	 public static String validateToken(String IDToken) throws Exception
		{
			try
			{
		     //Secret key which will issued during client registration
			 String secret = "ojsoiwmrwhaoctfmighrdbuucksmzufvobvksdtvkjstmfytdj";
			    Key hmacKey = new SecretKeySpec(Base64.getDecoder().decode(secret), 
			                                    SignatureAlgorithm.HS256.getJcaName());

			    Jws<Claims> jwt = Jwts.parser()
			            .setSigningKey(hmacKey)
			            .parseClaimsJws(IDToken);
			    
			    if(claimsVerifications(jwt))
			    {
			    	return (String) jwt.getBody().get("sub");
			    }
			    else
			    {
			    	//Invalid Token when claims value is invalid
			         return "";
			    }
			}
			catch(Exception e)
			{
				//Invalid Token when expired or signature not matched
				return "";
			}
		}
	 
	 //Save ID Token for future access or used for SSO(Single Sign On)
	 public static void saveIDToken(String IDToken) throws ClassNotFoundException, SQLException
	 {
	 Connection conn=DatabaseConnect.connect();
   	 PreparedStatement st=conn.prepareStatement("insert into storeIDToken(idToken) values(?)");
   	 st.setString(1,IDToken);
   	 st.executeUpdate();
   	 st.close();
   	 conn.close();
	 }
	  
	 //Verified the claims present in the IDtoken
	 public static boolean claimsVerifications(Jws<Claims> jwt)
	 {
		 //Verified the token issued server name in issuer and check the client id gn during client registration with audience
		 if((jwt.getBody().get("iss").equals("http://localhost:8080/OpenIdConnect/msaccounts.com")&&(jwt.getBody().get("aud").equals("mano.empojplqqo"))))
		 {
			 return true;
		 }
		 else
		 {
			 return false;
		 }
	 }
}
