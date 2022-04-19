<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Login</title>
</head>
<body>


	<form action="/loginDatabase" >
  <div class="container">
    <h1>Login</h1>
    <p>Please fill below information to login.</p>
    <hr>
    
   
    <label for="userName"><b>userName</b></label>
    <input type="userName" placeholder="Enter userName" name="userName" id="userName" required>

	<hr>
    <label for="passWord"><b>Password</b></label>
    <input type="passWord" placeholder="passWord" name="passWord" id="passWord" required>
    <hr>

 
    <button type="submit" class="registerbtn">Login</button>
  </div>

 
</form>
	
</body>
</html>