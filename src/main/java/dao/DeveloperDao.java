package dao;

import java.security.Key;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import model.DeveloperModel;

public class DeveloperDao 
{
	    //New Developer clients are inserted here
		public static void InsertDeveloper(DeveloperModel dev) throws ClassNotFoundException, SQLException
	    {
	 	      Connection conn=DatabaseConnect.connect();
	 	      PreparedStatement st=conn.prepareStatement("insert into developerdb(clientid,clientsecret,appname,redirecturi,secretkey) values(?,?,?,?,?)");
	 	      st.setString(1,dev.getClientId());
	 	      st.setString(2,dev.getClientSecret());
	 	      st.setString(3,dev.getAppName());
	 	      st.setString(4, dev.getRedirectUri());
	 	      st.setString(5, dev.getSecretKey());
	 	      st.executeUpdate();
	 	      st.close();
	          conn.close();
	    }
		
		//Verify the client id and redirecturi
	    public static boolean verifyDeveloper(String clientid,String redirecturi) throws ClassNotFoundException, SQLException
	    {
	     int uri_found=0;
	   	 Connection conn=DatabaseConnect.connect();
	   	 PreparedStatement st=conn.prepareStatement("select * from developerdb where clientid=?");
	   	 st.setString(1, clientid);
	   	 ResultSet rs=st.executeQuery();
	   	 if(rs.next()==true)
	   	 {
	   		 String redirecturis=rs.getString("redirecturi");
	 
	   		//Split the list of uris for verifications
	   		String[] listOfUris=redirecturis.split(",");
	   		for(int i=0;i<listOfUris.length;i++)
	   		{
	   			//Check whether the mentioned redirected uri in query param will gets matched with any of these in developer table
	   			if(listOfUris[i].contains(redirecturi)==true)
	   			{
	   				uri_found=1;
	   				break;
	   			}
	   		}
	   		rs.close();
	   		st.close();
	   		conn.close();
	   		if(uri_found==1)
	   		{
	   			return true;
	   		}
	   		else
	   		{
	   			return false;
	   		}
	   	 }
	   	 else
	   	 {
	   		 rs.close();
	   		 st.close();
	   		 conn.close();
	   		 return false;
	   	 }
	    }
	    
	    //Returns secret key used to signed the JWT Token
	    public static String getSecretKey(String clientid) throws SQLException, ClassNotFoundException
	    {
	    	 Connection conn=DatabaseConnect.connect();
		   	 PreparedStatement st=conn.prepareStatement("select * from developerdb where clientid=?");
		   	 st.setString(1, clientid);
		   	 ResultSet rs=st.executeQuery();
		   	 rs.next();
		   	 String secret_key=rs.getString("secretkey");
		   	 rs.close();
		   	 return secret_key;
	    }
}
