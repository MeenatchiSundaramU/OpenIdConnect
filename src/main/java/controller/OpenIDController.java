package controller;

import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Random;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import com.google.gson.JsonObject;
import dao.ClientDao;
import dao.DeveloperDao;
import dao.OidcAuthAuthorizeDao;
import dao.ResourceDao;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import model.AccessTokenModel;
import model.CreateAccModel;
import model.DeveloperModel;
import model.LoginValidateModel;
import model.RefreshTokenModel;
import model.SigninCredentialsModel;
import model.grantCodeModel;

@WebServlet(value="/")
public class OpenIDController extends HttpServlet
{
	
	protected void service(HttpServletRequest req,HttpServletResponse resp) throws IOException
	{
	    String clientEndpt=req.getServletPath();
	    switch(clientEndpt)
	    {
	         //Developer console endpoint to registered the client
	         case "/msDevConsole/devdb":  try {
			                              devDetails(req,resp);
		                                  } catch (ClassNotFoundException | IOException | SQLException e) {
			                              e.printStackTrace();}
	                                      break;
	        
	        //Authorization endpoint
	        //Participated flows----->Authorization code flow,Implicit flow,Hybrid flow
	                                      
	        case "/msoidc/authorize":     signInWithMano(req,resp);
                                          break;
                                 
             //When user create an account on mano accounts server this case will called
                                          
           case "/msaccounts/createAcc" : try {
				                          createAcc(req,resp);} catch (ClassNotFoundException | SQLException | NoSuchAlgorithmException e) {
				                          e.printStackTrace();}
                                          break;
                                          
             //When user logs in their mano's accounts on server this case will called
                                                     
           case "/msaccounts/login" :     try {
				                          LogVerified(req,resp);} catch (ClassNotFoundException | SQLException | IOException | NoSuchAlgorithmException e) {
				                          e.printStackTrace();}
                                          break;
                                          
            //When the resource owner grants permission for the resources this case will called
                                                     
           case "/msaccounts/codeortoksent" : try {
			                                issueCodeIdTokSent(req,resp);}catch (ClassNotFoundException | SQLException | IOException e) {
			                                e.printStackTrace();}
                                            break;
                                                     
        //When the resource owner denied the permission grants for the requested resources this case will called 
    
           case "/msaccounts/grantdenied"    :      deniedAuthorizationGrant(req,resp);
                                                     break;
    
                //Participated Flow---->Authorization code flow,Hybrid Flow
                                                     
            //Endpoint for Code Exchange for accesstoken, Refresh Token,ID Token(token Endpoints)
           case "/msoidc/token":                     issueAccRefIDToken(req,resp);  
                                                     break;
                                                     
            //Token response endpoint(Issued Access Token and Refresh Token & ID token)
           case "/client/response1":                 try {RedirectUriResp(req,resp);} catch (Exception e) {
			                                         e.printStackTrace();}
                                                     break;
           
           //Userinfo endpoint to get the info about the user and returned to the client
           case "/msoidc/userinfo"                 : try {getUserProfileDetails(req,resp);
		                                             } catch (NumberFormatException | ClassNotFoundException | SQLException | ParseException | IOException e) {
			                                         e.printStackTrace();}
                                                     break;
     
	}
	}
	
	//Upload the developer details to developerdb
	void devDetails(HttpServletRequest req,HttpServletResponse resp) throws IOException, ClassNotFoundException, SQLException
    {
	   HttpSession session=req.getSession();
	   //create one developer model obj for combined the developer details
       DeveloperModel newdev=new DeveloperModel();
       //Generate random string for clientId
       newdev.setClientId(randomStringGenerator());
       
       //Generate random string for clientSecret
       newdev.setClientSecret(randomStringGenerator());
       newdev.setAppName(req.getParameter("appname"));
       newdev.setRedirectUri(req.getParameter("url1"));
       
       //Store Secret key in devloperdb table used when validate the ID token
       newdev.setSecretKey((String) session.getAttribute("Secret_Key"));
       
       //Here we have concatenate the multiple redirected uri's and each seperated by commas.
       //When validate the redirected uris we split up based on commas and stored in arrayList and validation made easier.

       if((req.getParameter("url2").contains("null"))==false)
       {
         //Concatenate with URL 1 each of us seperated by commas
         newdev.setRedirectUri(newdev.getRedirectUri().concat(','+req.getParameter("url2")));
       }
       if((req.getParameter("url3").contains("null"))==false)
       {
         //Concatenate with URL 1,2 each of us seperated by commas
         newdev.setRedirectUri(newdev.getRedirectUri().concat(','+req.getParameter("url3")));
       }
       
       //Uploaded the details to developerdb table in database.
       DeveloperDao.InsertDeveloper(newdev);
       
       //Redirect to signin client main page
       resp.sendRedirect("http://localhost:8080/OpenIdConnect/clientsigin.jsp");
    }
	
	void signInWithMano(HttpServletRequest req,HttpServletResponse resp) throws IOException
    {
		//First clear the previous session values related to login credentials
	    deleteSessionValues(req,"login_failed");
	    deleteSessionValues(req, "token_response");
        HttpSession session=req.getSession();
        
        //Create one signInWithLogin Model object to store the query parameter
        SigninCredentialsModel queryParam=new SigninCredentialsModel();
        
        //Stored the URI details for further process
          try
          {
          queryParam.setResponseType(req.getParameter("response_type"));
          queryParam.setClientId(req.getParameter("client_id"));
          queryParam.setScope(req.getParameter("scope"));
          queryParam.setRedirectUri(req.getParameter("redirect_uri"));
          queryParam.setState(req.getParameter("state"));
          
        //if authorization flow is implicit or hybrid nonce parameter is mandatory
          if(queryParam.getResponseType().equals("code")==false)
          {
       	       queryParam.setNonce(req.getParameter("nonce"));
          }
          
          session.setAttribute("signinQueryObj", queryParam);
          //Redirected to Authentication Page
          resp.sendRedirect("http://localhost:8080/OpenIdConnect/msaccounts/ManoLogin.jsp");
          }
          catch(Exception e)
          {
           //When the request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once
        	 authErrorCodes(0,queryParam.getRedirectUri(),queryParam.getState(),resp);
          }
    }
	
	//When end users clicks on create a brand new account
	void createAcc(HttpServletRequest req,HttpServletResponse resp) throws ClassNotFoundException, SQLException, IOException, NoSuchAlgorithmException
    {
 	   String refreshTokens="";
 	   //Create one object in CreateAccModel and stored the value into it
 	   
 	   CreateAccModel newuser=new CreateAccModel();
 	   newuser.setName(req.getParameter("crename"));
 	   newuser.setEmail(req.getParameter("cremail"));
 	   newuser.setPassword(req.getParameter("crepass"));
 	   newuser.setLocation(req.getParameter("creloc"));
 	   newuser.setPhone(req.getParameter("cremobile"));
 	   
 	 //Generate 20 refresh token for per accounts which helps during refreshing the access tokens.
 	   for(int i=1;i<=20;i++)
 	   {
 		   //Each tokens will seperated by commas.
 		   refreshTokens=refreshTokens.concat(randomStringGenerator());
 		   if(i<20)
 		   {
 			   refreshTokens=refreshTokens.concat(",");  
 		   }
 	   }
 	   
 	   //Stored the new users details in users table and 20 refreshTokens in refTokenHolder table
 	   OidcAuthAuthorizeDao.InsertUser(newuser, refreshTokens);
 	   resp.sendRedirect("ManoLogin.jsp");
    }
	
	 //Login verifying
    void LogVerified(HttpServletRequest req,HttpServletResponse resp) throws ClassNotFoundException, SQLException, IOException, NoSuchAlgorithmException
    {
       //First clear the previous session values related to login credentials
	   deleteSessionValues(req,"login_failed");
 	   HttpSession session=req.getSession();
 	   
 	   SigninCredentialsModel queryValue=(SigninCredentialsModel)session.getAttribute("signinQueryObj");
 	   
 	   String email=req.getParameter("logmail");
 	   String password=req.getParameter("logpass");
 	   
 	   //Extract the exact scope parameters
	   queryValue.setScope(queryValue.getScope().replace("openid ", "").replace(" ",","));
	   session.setAttribute("scopename",queryValue.getScope());
	      
	       //Create an Login object for validation using loginResuability function
 	   LoginValidateModel validLogCredentials=new LoginValidateModel(email, password,queryValue.getClientId(),queryValue.getRedirectUri(),queryValue.getScope());
 	   
 	   //Verified Login credentials
 	   //If the fn returns 1----> All credentials are matched
 	   //If fn returns 0 -----> Login Credentials are invalid
 	   //If fn returns 2 ----->  Invalid ClientId and redirect URI
 	   //If fn returns 3 ----->  Your mentioned scoped resources are not avail for that login user
 	   int loginVerifiedResults=reuseLoginValidity(req,resp,validLogCredentials);
 	   if(loginVerifiedResults==1)
 	   {
 		   resp.sendRedirect("ResourceConfirm.jsp");
 	   }
 	   else
 	   {
 		   logErrorDisplay(req,queryValue, resp, loginVerifiedResults);
 	   }
 	   
    }
    //Reuseable function for invalid log credentials(Used by authorization code flow,implicit flow,Hybrid flow)
    public static void logErrorDisplay(HttpServletRequest req,SigninCredentialsModel signinmodel,HttpServletResponse resp,int logResults) throws IOException
    {
 	   if(logResults==2)
 	   {
 		   //when clientid or redirecturi becomes invalid the following error response will gets returned
 		  authErrorCodes(1,signinmodel.getRedirectUri(),signinmodel.getState(),resp);
 	   }
 	   else if(logResults==3)
 	   {
 		   //When the requested scope becomes invalid,the following error response will gets returned
 		  authErrorCodes(4,signinmodel.getRedirectUri(),signinmodel.getState(),resp);
 	   }
 	   else if(logResults==0)
 	   {
 		   //If the login credentials are not matched,it will redirected again to the login page
 		   HttpSession session=req.getSession();
 		   session.setAttribute("login_failed","Invalid Login Credentials");
 		   resp.sendRedirect("ManoLogin.jsp");
 	   }
    }
    
    //Resuablility function for Login Validity
    public static int reuseLoginValidity(HttpServletRequest req,HttpServletResponse resp,LoginValidateModel logModel) throws ClassNotFoundException, SQLException, IOException, NoSuchAlgorithmException
    {
 	   
 	   HttpSession session=req.getSession();
 	   
 	   //Check the login credentials and extracts the user uid which helps for scope verifications
        int uids=OidcAuthAuthorizeDao.checkUser(logModel.getEmail(),logModel.getPass());
	    session.setAttribute("uids", uids);
 	    if(uids!=0)
 		   {
 		       //Check for verified Client ID and Redirect URI
 		       if(DeveloperDao.verifyDeveloper(logModel.getClientid(),logModel.getRedirecturi())==true)
 		       {
 		    	   //Then verified the scope whether the resource owner have the resources on that server
 		    	   if(OidcAuthAuthorizeDao.checkScope(uids,logModel.getScope())==true)
 		    		   //If the mentioned scope resources are availble returned 1
 		    		   return 1;
 		    	   else
 		    		   //If the mentioned scope resources are not availble returned 3
 		    		   return 3;
 		       }
 		       else
                    //If the clientId and redirectUri are mismatched,it will returns 2
 		    	   return 2;
 		   }
 	    else
 	    	//Invalid Login Credentials
 	    	return 0;
    }
    
    //Function for the Authorization endpoint
    public static void issueCodeIdTokSent(HttpServletRequest req,HttpServletResponse resp) throws ClassNotFoundException, SQLException, IOException
    {
  	  //Here response will depends on the type of flow,
  	  HttpSession session=req.getSession();
  	  SigninCredentialsModel queryValue=(SigninCredentialsModel)session.getAttribute("signinQueryObj");
  	  int uid=(int) session.getAttribute("uids");
  	  
  	  //This string variable will built the redirect uri parameters based on response_type
  	  String redirect_uri=queryValue.getRedirectUri()+"?";
  	  
  	  //if the response type is invalid we need to returned the error response
  	  int error_flag=0;
  	  
  	  //Get the username for that uid which is the subject identifier claim values for the ID tokens
  	  String username=OidcAuthAuthorizeDao.getUserName(uid);
  	  
  	  //Split the response_type based on " " 
  	  String[] response_splits=queryValue.getResponseType().split(" ");
  	  for(int i=0;i<response_splits.length;i++)
  	  {
  		  switch(response_splits[i])
  		  {
  		     case "code"     ://Create one object for the grantcode and insert the values
  				             grantCodeModel newGrantCode=new grantCodeModel(queryValue.getClientId(),randomStringGenerator(),timeGenerator(2),queryValue.getScope(),uid,1);
  				             
  				             //insert the grantCode object to the grantcodelog table
  				             OidcAuthAuthorizeDao.saveGrantCode(newGrantCode);
  				             
  				             //It will append the auth code along with redirected uri's
  						     redirect_uri+="code="+newGrantCode.getGrantCode()+"&";
  				             break;
  				          
  		     case "id_token" ://We need claims values such as uid,subject identifier(username),audience as (clientId)
  				              String jwtToken=createJWTToken(uid,username,queryValue.getClientId());
  				              
  				              //Append ID token along with redirect_uri
  				              redirect_uri+="id_token="+jwtToken+"&";
  				              break;
  				              
  		     case "token"    ://Generate access token from the authorization endpoint for implicit flow
  				              String newAccToken=reuseAccessTokenCode(req, uid,queryValue.getClientId(),queryValue.getScope());
  				              redirect_uri+="access_token="+newAccToken+"&token_type=bearer"+"&expires_in=3600&";
  				              break;
  				
  	//if the response_type contains invalid value default will work and returned unsupported response type
  		     default          :error_flag=1;
  		                       break;
  		  }
  		  if(error_flag==1)
  		  {
  			  //clear the redirected uri
  			  redirect_uri="";
  			  break;
  		  }
  	  }
  	  if(error_flag==1)
  	  {
  		//if none of the above response type will gets matched returns unsupported response type error codes
		  authErrorCodes(3,queryValue.getRedirectUri(),queryValue.getState(), resp);
  	  }
  	  else
  	  {
  		  //send the authorization response to the client
  		  resp.sendRedirect(redirect_uri+"state="+queryValue.getState());
  	  }
    }
    
    //When the authorization grants was denied by the end users(Resource owners)
    public static void deniedAuthorizationGrant(HttpServletRequest req,HttpServletResponse resp) throws IOException
    {
    	HttpSession session=req.getSession();
    	SigninCredentialsModel queryValue=(SigninCredentialsModel)session.getAttribute("signinQueryObj");
    	authErrorCodes(2,queryValue.getRedirectUri(),queryValue.getState(), resp);
    }
    
    //Returns the possible exceptions or error codes when validating the query parameters involved in the authorization and authentication request
    public static void authErrorCodes(int error_no,String redirecturi,String state,HttpServletResponse resp) throws IOException
    {
    	String[] auth_error_code= {"invalid_request","unauthorized_client","access_denied","unsupported_response_type","invalid_scope","server_error","temporary_unavailable"};
    	resp.sendRedirect(redirecturi+"?error="+auth_error_code[error_no]+"&state="+state);
    }
    
    //Token Endpoints
    public static void issueAccRefIDToken(HttpServletRequest req,HttpServletResponse resp) throws IOException
    {
      HashMap<String,Object> jsonresp=new HashMap<String,Object>();
  	  try
  	  {
  	  String clientId=req.getParameter("client_id");
      String redirecturi=req.getParameter("redirect_uri");
      String grant_type=req.getParameter("grant_type");
      String auth_code=req.getParameter("code");
      String refresh_token="";
      
      //First Check the grant type
      if(grant_type.contentEquals("authorization_code")==true)
      {
    	   //Check for verified Client ID and Redirect URI
	       if(DeveloperDao.verifyDeveloper(clientId,redirecturi)==true)
           {
	    	 //Check whether the grantcode is valid or not and whether we need to issued refresh token along access token or not
         	  
         	  //The below function returned two values one is uid of the user.Next status of refresh token issued 
         	   //0--->Not issued refresh token along with access token,1---->issued refresh token along with access token
         	  
         	  ArrayList<Object> refreshissued=OidcAuthAuthorizeDao.validateGrandCode(auth_code);
         	  
         	  //Check if the grandcode is valid or not
         	  if(refreshissued.get(0)!=null)
         	  {
         		//Get the username for that uids which is the subject identifier claim values for the ID tokens
         	  	String username=OidcAuthAuthorizeDao.getUserName((Integer)refreshissued.get(0));
         	  	
         	    //We need claims values such as uid,subject identifier(username),audience as (clientId)
         		String jwtToken=createJWTToken((Integer)refreshissued.get(0),username,clientId);
         		
         		//No refresh token issued if refresh_issued status==0
         		String access_token=reuseAccessTokenCode(req,(Integer)refreshissued.get(0), clientId,(String)refreshissued.get(2));
         		// issued refresh token along with access token if refresh_issued status==1
         		if((Integer)refreshissued.get(1)==1)
         		{
         		     refresh_token=reuseRefreshTokenCode(req,(Integer)refreshissued.get(0), clientId,(String)refreshissued.get(2));
         		}
         		    // made required key value pairs into the Hashmap which helps to built JSON response .
         		    jsonresp.put("access_token",access_token);
         		    jsonresp.put("token_type", "Bearer");
         		    if(refresh_token.isEmpty()==false)
         		    jsonresp.put("refresh_token",refresh_token);
        		    
         		    jsonresp.put("expires_in",3600);
         		    jsonresp.put("id_token",jwtToken);
         	  }
         	  else
         	  {
         		  //Invalid grant code(may it can expired or not avail)
         		  jsonresp.put("error", "unsupported_grant_type");
         	  }
           }
	       else
	       {
	    	   //invalid clientId and redirecturi
	    	   jsonresp.put("error", "unauthorized_client");
	       }
      }
      else
      {
    	  //invalid grant code in request param
    	  jsonresp.put("error", "invalid_grant");
      }
      
      //built JSON token response
      builtJSON(jsonresp, req, resp,redirecturi);
  	  }
  	  catch(Exception e)
  	  {
  		  //Error response for missing param in token request
  		String redirecturi=req.getParameter("redirect_uri");
  		jsonresp.put("error", "invalid_request");
  		builtJSON(jsonresp, req, resp,redirecturi);
  	  }
    }
    
    //Built JSON Format for token response to client
   public static void builtJSON(HashMap<String,Object> jsonresp,HttpServletRequest req,HttpServletResponse resp,String redirect_uri) throws IOException
    {
    	HttpSession session=req.getSession();
    	resp.setContentType("application/json");
 		resp.setCharacterEncoding("utf-8");
 		
 		//create Json Object to return token response
 		JsonObject json = new JsonObject();
    	for(String key:jsonresp.keySet())
    	{
    		if(key.contentEquals("expires_in")==true)
    		{
    		json.addProperty(key,(Integer)jsonresp.get(key));
    		}
    		else
    		{
    		json.addProperty(key,(String)jsonresp.get(key));
    		}
    	}
    	// finally return the json string to client     
		session.setAttribute("token_response",json.toString());
		resp.sendRedirect(redirect_uri);
    }
    //Token response
    void RedirectUriResp(HttpServletRequest req,HttpServletResponse resp) throws Exception
    {
 		   HttpSession session=req.getSession();
 		   
 		  //Response for implict flow(when idtoken or token,idtoken issued to client)
 		  if(session.getAttribute("token_response")==null)
 		  {
 			  //After validate the token get the name of authenticated user and moved to home page and welcomes him
 			  String name=ClientDao.validateToken((String)req.getParameter("id_token"));
 			  if(!name.isEmpty())
 			  {
 				  //if the ID token is valid redirect to main page
 				  session.setAttribute("enduser_name", name);
 				  resp.sendRedirect("http://localhost:8080/OpenIdConnect/accessProfileInfo.jsp");
 			  }
 			  else
 			  {
 				  //Reauthenticate Again to get Valid Token
 				 resp.sendRedirect("http://localhost:8080/OpenIdConnect/clientsigin.jsp");
 			  }
 		  }
 		  //Response for Authorization code flow,Hybrid flow
 		  else
 		  {
 			  resp.getWriter().print(session.getAttribute("token_response"));
 		  }
 	 }
    
    //UserInfo EndPoints
    public static void getUserProfileDetails(HttpServletRequest req,HttpServletResponse resp) throws NumberFormatException, SQLException, ParseException, ClassNotFoundException, IOException
    {
    	HashMap<String,Object> jsonresp=new HashMap<String,Object>();
    	  try
    	  {
    	  String clientId=req.getParameter("client_id");
          String redirecturi=req.getParameter("redirect_uri");
          String accesstoken=req.getParameter("access_token");
          String scope=req.getParameter("scope");
          
 	     //Validate the access token issued with Authorized server
    	if(DeveloperDao.verifyDeveloper(clientId,redirecturi)==true)
    	{
    		//Fetch the uids for that respective access Token
          int uids=OidcAuthAuthorizeDao.ValidateAccessToken(accesstoken,clientId,scope);
 	     if(uids!=0)
 	     {
 		   //Made an API call to fetch users info
 		   CreateAccModel usersinfo=ResourceDao.getUsers(uids);
 		   
 		   //Built the json response about userinfo to the client
 		  jsonresp.put("name",usersinfo.getName());
		  jsonresp.put("email",usersinfo.getEmail());
		  jsonresp.put("mobileno",usersinfo.getPhone());
		  jsonresp.put("location",usersinfo.getLocation());
		  
 	     }
 	     else
 	    	//When the access token was expired or invalid
     		jsonresp.put("error", "invalid_token");
    	}
    	else
    	{
    		//invalid clientid or redirecturi this error response will returned
    		jsonresp.put("error", "unauthorized_client");
    	}
    	builtJSON(jsonresp, req, resp,redirecturi);
    	}
    	catch(Exception e)
    	{
    		//when there is any missing parameters in that request returns the following error response
    		String redirecturi=req.getParameter("redirect_uri");
      		jsonresp.put("error", "invalid_request");
      		builtJSON(jsonresp, req, resp,redirecturi);
    	}
    }
    
    //Create JWT Token which tells about the authentication event and short info about the end user
    public static String createJWTToken(int uid,String username,String clientid) throws ClassNotFoundException, SQLException
    {
    	//Get key which is given during client registration
    	String secretKey=DeveloperDao.getSecretKey(clientid);
    	
    	//we need to signed the JWT token using secret key after Hash Message Authentication code process
    	Key secret_hmacKey = new SecretKeySpec(Base64.getDecoder().decode(secretKey), 
                             SignatureAlgorithm.HS256.getJcaName());
        
    	//Create the JWT Token with signature
        String IDToken   = Jwts.builder()
                         .claim("uid", uid)
                         .setSubject(username)
                         .setIssuer("http://localhost:8080/OpenIdConnect/msaccounts.com")
                         .setAudience(clientid)
                         .setIssuedAt(Date.from(Instant.now()))
                         
                         //Id token valid upto for 20 min
                         .setExpiration(Date.from(Instant.now().plus(20l, ChronoUnit.MINUTES)))
                         .signWith(SignatureAlgorithm.HS256, secret_hmacKey)
                         .compact();
        return IDToken;
    }
	//Random String Generator for tokens and client secret and id
    public static String randomStringGenerator()
    {
   	    int lLimit = 97; 
   	    int rLimit = 122; 
   	    int targetStringLength =10;
   	    Random random = new Random();
           String generatedString = random.ints(lLimit, rLimit + 1)
   	      .limit(targetStringLength)
   	      .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
   	      .toString();
           return "mano."+generatedString;
    }
    
     //Many flows use accessToken frequently,Made a reusability functionality for AcessToken Upload
    public static String reuseAccessTokenCode(HttpServletRequest req,int uid,String clientId,String allScopes) throws ClassNotFoundException, SQLException
    {
    	HttpSession session=req.getSession();
    	AccessTokenModel newAccToken=new AccessTokenModel(uid,clientId,randomStringGenerator(),allScopes,timeGenerator(60));
    	//Save the access tokens
	    OidcAuthAuthorizeDao.saveAccessTokens(newAccToken);
	    return newAccToken.getAccessToken();
    }
    //Many flows use RefreshToken frequently,Made a reusability functionality for RefreshToken Upload
    public static String reuseRefreshTokenCode(HttpServletRequest req,int uid,String clientId,String allScopes) throws ClassNotFoundException, SQLException
    {
    	RefreshTokenModel newRefToken=new RefreshTokenModel(uid,-1,clientId,"",allScopes);
    	
    	//Saved the access tokens and refresh tokens
    	RefreshTokenModel refreshToken=OidcAuthAuthorizeDao.saveRefreshToken(newRefToken);
		
		//When refresh token objects received saved the refresh tokens to issuedRefreshToken table
		OidcAuthAuthorizeDao.saveRefreshTokens(newRefToken);
		return refreshToken.getRefreshToken();
    }
    //Extract Time used for validate the Access token and Authorization code
    public static String timeGenerator(int timeincrease) 
    {
 		      Calendar cal = Calendar.getInstance();
 		      cal.add(Calendar.MINUTE, timeincrease);
 		      System.out.println("Updated Date = " + cal.getTime());
 		      return cal.getTime().toString();
    }
    
  //Functions will gets invoked when you need to delete the session values by pass the session parameters
    public static void deleteSessionValues(HttpServletRequest req,String delSessions)
    {
    	HttpSession session=req.getSession();
    	session.removeAttribute(delSessions);
    }
}
