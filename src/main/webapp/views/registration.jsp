<%@ page language="java" contentType="text/html; charset=ISO-8859-1"
    pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="ISO-8859-1">
<title>Registration</title>


</head>
<body>


<form action="/registerDatabase">
  <div class="container">
    <h1>Register</h1>
    <p>Please fill in this form to create an account.</p>
    <hr>
    
     <label for="First name"><b>First Name</b></label>
    <input type="text" placeholder="Enter First Name" name="firstName" id="firstName" required>
    <hr>
     <label for="Last name"><b>Last Name</b></label>
    <input type="text" placeholder="Enter last Name" name="lastName" id="lastName" required>
	<hr>
    <label for="email"><b>Email</b></label>
    <input type="email" placeholder="Enter Email" name="emailId" id="email" required>
	<hr>
    <label for="userName"><b>userName</b></label>
    <input type="userName" placeholder="Enter userName" name="userName" id="userName" required>

    <label for="passWord"><b>Password</b></label>
    <input type="passWord" placeholder="passWord" name="passWord" id="passWord" required>
    <hr>

    <p>for creating an account please click on Register button</p>
    <button type="submit" class="registerbtn">Register</button>
  </div>

 
</form>


	<form action="/login">
	<p>Already have an account? <button type="submit" >Sign</button></p>
	</form>


</body>
</html>