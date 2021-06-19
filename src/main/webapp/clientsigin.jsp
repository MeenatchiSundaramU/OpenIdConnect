<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Client Sign In</title>
</head>
<body>
<center>
<a href="msDevConsole/developerConsole.jsp"><button>Developer Console</button><br><br></a>
<a href="msoidc/authorize?client_id=mano.empojplqqo&scope=openid profile&redirect_uri=http://localhost:8080/OpenIdConnect/client/response1&response_type=id_token token&state=xyz"><input type="submit" value="Sign in with Mano"></a>
</center>
</body>
</html>
