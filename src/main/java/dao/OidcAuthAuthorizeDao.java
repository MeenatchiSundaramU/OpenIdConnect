package dao;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Locale;

import model.AccessTokenModel;
import model.CreateAccModel;
import model.RefreshTokenModel;
import model.grantCodeModel;

public class OidcAuthAuthorizeDao 
{
	    //Insert new users
		public static void InsertUser(CreateAccModel creuser,String refreshTokens) throws ClassNotFoundException, SQLException, NoSuchAlgorithmException
	    {
			//Database connect
	   	 Connection conn=DatabaseConnect.connect();
	   	 PreparedStatement st=conn.prepareStatement("insert into users(name,email,mobile,password,location) values(?,?,?,?,?)");
	   	 st.setString(1,creuser.getName());
	   	 st.setString(2,creuser.getEmail());
	   	 st.setString(3,creuser.getPhone());
	   	 st.setString(4,hashPass(creuser.getPassword()));
	   	 st.setString(5, creuser.getLocation());
	   	 
	   	 //Insertion made into database
	   	 st.executeUpdate();
	   	 
	   	 //Find the UID of the user to save the refresh token to that uid in refToken Holder
	     java.sql.Statement stm=(java.sql.Statement)conn.createStatement();
	     ResultSet rst=stm.executeQuery("select max(uid) as UID from users");
	     int uids=rst.getInt("UID");
	     stm.close();
	     rst.close();
	    
	     //Insert uids into UsersAPIindex table to acknowledge,which of the user's resources will hold by the server
	     st=conn.prepareStatement("insert into usersAPIindex(uid,profile,contacts) values(?,?,0)");
	     st.setInt(1, uids);
		 st.setInt(2,1);
		 st.executeUpdate();
		 
		 //Insert the 20 refresh Tokens for that Users Accounts which helpful for refreshing the access tokens during API calls
		 st=conn.prepareStatement("insert into refTokenHolder(uid,refreshTokens) values(?,?)");
		 st.setInt(1, uids);
		 st.setString(2,refreshTokens);
		 st.executeUpdate();
		 st.close();
		 conn.close();
	    }
		
		//Check the users credentials when logging the accounts
		public static int checkUser(String email,String pass) throws ClassNotFoundException, SQLException, NoSuchAlgorithmException
		{
					Connection conn=DatabaseConnect.connect();
					PreparedStatement st=conn.prepareStatement("select uid from users where email=? and password=?");
					st.setString(1, email);
					st.setString(2, hashPass(pass));
					ResultSet rs=st.executeQuery();
					if(rs.next()==false)
					{
						  rs.close();
						  st.close();
						  conn.close();
					      return 0;
					}
					else
					{
					    int uids=rs.getInt("uid");
					    rs.close();
					    st.close();
					    conn.close();
					    return uids;
					}
		}
		
		//Check the whether the resource owner have resources(which mentioned in the url) on mano's server
		public static boolean checkScope(int uids,String scopename) throws SQLException, ClassNotFoundException
		{
					int check_scope_flag=1;
					Connection conn=DatabaseConnect.connect();
					PreparedStatement st;
					st=conn.prepareStatement("select * from usersAPIindex where uid=?");
					st.setInt(1, uids);
					ResultSet rs=st.executeQuery();
					return checkResultSet(rs, conn, st, scopename);
		}
		
		//Resuablitity function for checking the resources on the resource server
		public static boolean checkResultSet(ResultSet rs,Connection conn,Statement st,String scopename) throws SQLException
		{
					int check_scope_flag=1;
					String[] scopeSegregates=scopename.split(",");
					if(rs.next()==false)
					{
						rs.close();
						st.close();
						conn.close();
					    return false;
					}
					else
					{
						for(int i=0;i<scopeSegregates.length;i++)
						{
							if(rs.getInt(scopeSegregates[i])==0)
							{
								check_scope_flag=0;
								break;
							}	
						}
						if(check_scope_flag==1)
						{
						rs.close();
						st.close();
						conn.close();
						return true;
						}
						else
						{
							rs.close();
							st.close();
							conn.close();
							return false;
						}
					}
		}
		
		//Stored the Authorization grant code 
		public static void saveGrantCode(grantCodeModel newCode) throws SQLException, ClassNotFoundException
		{
					 Connection conn=DatabaseConnect.connect();
				   	 PreparedStatement st=conn.prepareStatement("insert into grantcodelog(clientid,uid,grantcode,timestamp,scope,refreshissued) values(?,?,?,?,?,?)");
				   	 st.setString(1,newCode.getClientId());
				   	 st.setInt(2,newCode.getUid());
				   	 st.setString(3,newCode.getGrantCode());
				   	 st.setString(4,newCode.getTimeStamp());
				   	 st.setString(5,newCode.getScope());
				   	 st.setInt(6,newCode.getRefresh_issued());
				   	 st.executeUpdate();
				   	 st.close();
				   	 conn.close();
	    }
		
		//Get the username for that uids which is the subject identifier claim values for the ID tokens
		public static String getUserName(int uid) throws SQLException, ClassNotFoundException
		{
			Connection conn=DatabaseConnect.connect();
			PreparedStatement st;
			st=conn.prepareStatement("select * from users where uid=?");
			st.setInt(1, uid);
			ResultSet rs=st.executeQuery();
			rs.next();
			String username=rs.getString("name");
			System.out.print(username);
			rs.close();
			return username;
		}
		//Save access token
		public static void saveAccessTokens(AccessTokenModel newAccessToken) throws SQLException, ClassNotFoundException
		{
					Connection conn=DatabaseConnect.connect();
					PreparedStatement savetok=conn.prepareStatement("insert into issuedAccessToken(clientid,uid,accesstoken,scope,timestamp)values(?,?,?,?,?)");
					savetok.setString(1, newAccessToken.getClientId());
					savetok.setInt(2, newAccessToken.getUid());
					savetok.setString(3, newAccessToken.getAccessToken());
					savetok.setString(4,newAccessToken.getScope());
					savetok.setString(5,newAccessToken.getTimeStamp());
					savetok.executeUpdate();
					savetok.close();
					conn.close();
		}
		//Validation the grant code for generation of access token
		public static ArrayList<Object> validateGrandCode(String grantcode) throws SQLException, ClassNotFoundException, ParseException
		{
					ArrayList<Object> uidrefstatus=new ArrayList();
					 Connection conn=DatabaseConnect.connect();
				   	 PreparedStatement st=conn.prepareStatement("select * from grantcodelog where grantcode=?");
				   	 st.setString(1,grantcode);
				   	 ResultSet rs=st.executeQuery();
				   	 //Check if the code is avail or not
				   	 if(rs.next()==false)
				   	 {
				   		  rs.close();
				   		  st.close();
				   		  conn.close();
				   		  return uidrefstatus;
				   	 }
				   	 else 
				   	 {
				     
				   	 String grandtoktime=rs.getString("timestamp");
				   	 
				   	 //Indicates 0--->not issued refresh token , 1--> issued refresh token
				   	 int refresh_issued=rs.getInt("refreshissued");
				   	 int uid=rs.getInt("uid");
				   	 String scope=rs.getString("scope");
				   	 Calendar tokcal = Calendar.getInstance();
				   	 SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH);
				   	 tokcal.setTime((sdf.parse(grandtoktime)));
				   	 Calendar currtime= Calendar.getInstance();
				   	 st=conn.prepareStatement("delete from grantcodelog where uid=? and grantcode=?");
				   	 st.setInt(1, rs.getInt("uid"));
				   	 st.setString(2, grantcode);
				   	 st.executeUpdate();
				   	 //Check for expiration of grantcode
				   	 if((tokcal.compareTo(currtime)>0))
				   	 {
				   		System.out.print("Valid Token");
				   		uidrefstatus.add(uid);
					   	uidrefstatus.add(refresh_issued);
					   	uidrefstatus.add(scope);
				   		st.close();
						conn.close();
				   	    return uidrefstatus;
				   	 }
				   	 else
				   	 {
				   		st.close();
						conn.close();
				   		return uidrefstatus;
				   	 }
				   	 }
		}
		//Save Refresh Token
		public static RefreshTokenModel saveRefreshToken(RefreshTokenModel refresh_token) throws ClassNotFoundException, SQLException
		{
					int tok_ind=1;
					String refreshTokens;
					Connection conn=DatabaseConnect.connect();
					//Get max index of refresh token issued.
					PreparedStatement checkRefAvail=conn.prepareStatement("select max(tokenindex) as REMAIN from issuedRefreshToken where clientid=? and uid=?");
					checkRefAvail.setString(1, refresh_token.getClientId());
					checkRefAvail.setInt(2, refresh_token.getUid());
					ResultSet tokconsumes=checkRefAvail.executeQuery();
					System.out.println((tokconsumes.getInt("REMAIN")));
					if(tokconsumes.next()==false)
					{
						//If this is a first refresh token.
						refreshTokens=generateRefreshToken(refresh_token.getUid(),tok_ind, conn);
						refresh_token.setTokenindex(tok_ind);
						refresh_token.setRefreshToken(refreshTokens);
					}
					else
					{
						//It is used for providing the exact 20 refresh token,if 20 crossed,it will again issued the first refresh token which issued earlier.
						tok_ind=(((tokconsumes.getInt("REMAIN"))%20)+1);
						refresh_token.setTokenindex(tok_ind);
						refreshTokens=generateRefreshToken(refresh_token.getUid(),tok_ind,conn);
						refresh_token.setRefreshToken(refreshTokens);
					}
					tokconsumes.close();
					checkRefAvail.close();
					conn.close();
				    return refresh_token;
		}
				
				//Pick up and returned the Refresh Tokens which issued for respective accounts when the accounts was first created
				public static String generateRefreshToken(int uid,int tokind,Connection conn) throws SQLException
				{
					System.out.print("Ref generate table");
					PreparedStatement getRefreshTok=conn.prepareStatement("select * from refTokenHolder where uid=?");
					getRefreshTok.setInt(1, uid);
					ResultSet refTok=getRefreshTok.executeQuery();
					refTok.next();
					String refTokens=refTok.getString("refreshTokens");
					String[] tokSegregate=refTokens.split(",");
					refTok.close();
					getRefreshTok.close();
					conn.close();
					return tokSegregate[tokind-1];
				}
				
				//Save Refresh Tokens after pickup from the refTokenHolder
				public static void saveRefreshTokens(RefreshTokenModel refToken) throws SQLException, ClassNotFoundException
				{
					Connection conn=DatabaseConnect.connect();
					PreparedStatement saveReftok=conn.prepareStatement("insert into issuedRefreshToken(clientid,uid,refreshtoken,scope,tokenindex)values(?,?,?,?,?)");
					saveReftok.setString(1, refToken.getClientId());
					saveReftok.setInt(2, refToken.getUid());
					saveReftok.setString(3, refToken.getRefreshToken());
					saveReftok.setString(4,refToken.getScope());
					saveReftok.setInt(5, refToken.getTokenindex());
					saveReftok.executeUpdate();
					conn.close();
				}
				
				//Validate the access tokens for API call
				public static int ValidateAccessToken(String accesstoken,String clientid,String scope) throws ClassNotFoundException, SQLException, ParseException
				{
					Connection conn=DatabaseConnect.connect();
					
					// To check whether this accesstoken is valid and scope mentioned in the URL should gets matched
					PreparedStatement checktok=conn.prepareStatement("select * from issuedAccessToken where accesstoken=? and clientid=?");
					checktok.setString(1, accesstoken);
					checktok.setString(2, clientid);
					ResultSet rscheck=checktok.executeQuery();
					if(rscheck.next()==false)
						return 0;
					else
					{
						 String actime=rscheck.getString("timestamp");
						 int uid=rscheck.getInt("uid");
						 Calendar cal = Calendar.getInstance();
					   	 SimpleDateFormat sdf = new SimpleDateFormat("EEE MMM dd HH:mm:ss z yyyy", Locale.ENGLISH);
					   	 cal.setTime((sdf.parse(actime)));
					   	 Calendar cal2= Calendar.getInstance();
					   	 //if the access token is valid
					   	 if(cal.compareTo(cal2)>0)
					   	 {
					   		 //Check the scope of issued accesstoken and scope mentioned in URL
					   		 if(rscheck.getString("scope").contains(scope)==true)
					   		 {
					   			checktok.close();
					   			rscheck.close();
								conn.close();
						   	    return uid;
					   		 }
					   		 else
					   		 {
					   			checktok.close();
					   			rscheck.close();
								conn.close();
						   	    return uid;
					   		 } 
					   	 }
					   	 else
					   	 {
					   		checktok.close();
							conn.close();
					   		return 0;
					   	 }
					}
				}
	     
		public static String hashPass(String password) throws NoSuchAlgorithmException
		{
			//There are many algos are available for hashing i)MD5(message digest) ii)SHA(Secured hash algo)
			MessageDigest md=MessageDigest.getInstance("MD5");
		    md.update(password.getBytes());
		   
		    byte[] hashedpass=md.digest();
		    StringBuilder hashpass=new StringBuilder();
		    for(byte b:hashedpass)
		    {
		    	//Convert to hexadecimal format
		        hashpass.append(String.format("%02x",b));
		    }
		    return hashpass.toString();
		}
}
