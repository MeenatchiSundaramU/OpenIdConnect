<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Log In</title>
</head>
<body>
<center>
<h1>Welcome to Login Page</h1>
<form action="login">
<input type="email" placeholder="Enter your email" name="logmail"><br><br><br>
<input type="password" placeholder="Enter your password" name="logpass"><br><br><br>
<input type="submit" value="Log In"><br><br><br>
</form>
<a href="CreateAccount.jsp"><button>Create an Account</button></a>
<%
   if((String)session.getAttribute("login_failed")!=null)
   {
	   out.println((String)session.getAttribute("login_failed"));
   }
   
%>
</center>
</body>
</html>