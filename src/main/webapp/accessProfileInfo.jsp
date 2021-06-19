<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Insert title here</title>
</head>
<body>
<center>
<h1>Welcome 
<%
    String name=(String)session.getAttribute("enduser_name");
    out.println(name);
%>
</h1>
<a href="msoidc/userinfo"><input type="submit" value="Access More Profile Info"></a>
</center>
</body>
</html>